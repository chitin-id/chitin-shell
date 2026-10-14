import type { IntentV1, SecurityTier } from '../intent/types.js';
import type { PolicyConfig, VerificationResult } from './types.js';
import { determineTier } from './tier.js';
import { RateLimiter } from './rate-limiter.js';
import type { OnChainPolicyLoader } from './on-chain-loader.js';
import { validateIntent } from '../intent/validator.js';
import { ApprovalAuthority, localApprovalAuthority } from './approval.js';

export interface PolicySecurity {
  trustedDids?: string[];
  trustedKeys?: Record<string, Uint8Array>;
  approvalAuthority?: ApprovalAuthority;
}

export class PolicyEngine {
  private policy: PolicyConfig;
  private rateLimiter: RateLimiter;
  private onChainLoader?: OnChainPolicyLoader;
  private security: PolicySecurity;
  private nonces = new Map<string, number>();

  constructor(policy: PolicyConfig, rateLimiter?: RateLimiter, onChainLoader?: OnChainPolicyLoader, security: PolicySecurity = {}) {
    this.policy = policy;
    this.rateLimiter = rateLimiter ?? new RateLimiter();
    this.onChainLoader = onChainLoader;
    this.security = security;
  }

  verify(intent: IntentV1): VerificationResult {
    return this.verifyAuthorized(intent, false);
  }

  private verifyAuthorized(intent: IntentV1, allowOnChain: boolean): VerificationResult {
    const invalid = this.validateAuthorization(intent);
    if (invalid) return { approved: false, tier: 3, reason: invalid };
    const tier = determineTier(intent.action.type, this.policy);
    const tierKey = `tier_${tier}` as keyof PolicyConfig['tiers'];
    const tierConfig = this.policy.tiers[tierKey];
    if (tierConfig.verification === 'on_chain' && !allowOnChain) {
      return { approved: false, tier, reason: 'This action requires on-chain verification' };
    }

    // Tier 3: always requires human approval
    if (tier === 3) {
      return {
        approved: false,
        tier,
        reason: `Action '${intent.action.type}' requires human approval (${tierConfig.description})`,
        requires_human: true,
      };
    }

    // Blacklist check (Tier 1 and 2)
    if (tier >= 1) {
      const blacklistResult = this.checkBlacklist(intent);
      if (blacklistResult) return { ...blacklistResult, tier };
    }

    // Tier 0: always approve
    if (tier === 0) {
      return {
        approved: true,
        tier,
        reason: 'Tier 0: auto-approved',
        approval_token: (this.security.approvalAuthority ?? localApprovalAuthority).issue(intent),
      };
    }

    // Tier 1: whitelist + rate limit checks
    if (tier === 1) {
      if (tierConfig.constraints?.recipient_whitelist) {
        const to = intent.action.params.to as string | undefined;
        const contacts = this.policy.whitelists?.contacts ?? [];
        if (to && !contacts.includes(to)) {
          return {
            approved: false,
            tier,
            reason: `Recipient '${to}' is not in the approved contacts whitelist`,
          };
        }
      }
    }

    // Rate limit check (Tier 1 and 2)
    const rateLimitResult = this.checkRateLimit(intent, tierConfig);
    if (rateLimitResult) return { ...rateLimitResult, tier };

    // Action-specific rate limits
    const actionRateResult = this.checkActionRateLimit(intent);
    if (actionRateResult) return { ...actionRateResult, tier };

    // Record successful action for rate limiting
    this.rateLimiter.record(intent.agent_did, intent.action.type);

    return {
      approved: true,
      tier,
      reason: `Tier ${tier}: approved after ${tierConfig.verification} verification`,
      approval_token: (this.security.approvalAuthority ?? localApprovalAuthority).issue(intent),
    };
  }

  /**
   * Verify an intent on-chain.
   * For tier 0-1, uses local verification (fast path).
   * For tier 2+, delegates to the on-chain AgentPolicy contract.
   * Throws if onChainLoader is not configured.
   */
  async verifyOnChain(intent: IntentV1): Promise<VerificationResult> {
    if (!this.onChainLoader) {
      throw new Error('On-chain policy loader not configured');
    }

    // For tier 0-1, still verify locally (fast path)
    const localResult = this.verifyAuthorized(intent, true);
    if (!localResult.approved) return localResult;
    if (localResult.tier <= 1) return localResult;

    // For tier 2+, verify on-chain
    const intentHash = PolicyEngine.computeIntentHash(intent);
    const onChainResult = await this.onChainLoader.verifyOnChain(
      intent.agent_did,
      intent.action.type,
      intentHash,
    );

    return {
      approved: onChainResult.approved,
      tier: onChainResult.tier as SecurityTier,
      reason: onChainResult.reason,
      requires_human: onChainResult.tier === 3,
      approval_token: onChainResult.approved && onChainResult.tier !== 3
        ? (this.security.approvalAuthority ?? localApprovalAuthority).issue(intent) : undefined,
    };
  }

  /**
   * Compute a SHA-256 hash of the canonical JSON representation of an intent.
   * Returns a 0x-prefixed hex string suitable for use as a bytes32 on-chain.
   */
  static computeIntentHash(intent: IntentV1): string {
    return ApprovalAuthority.intentHash(intent);
  }

  getPolicy(): PolicyConfig {
    return this.policy;
  }

  private validateAuthorization(intent: IntentV1): string | null {
    try {
      let key = this.security.trustedKeys?.[intent.agent_did];
      if (!key && this.security.trustedDids?.includes(intent.agent_did) && intent.agent_did.startsWith('did:key:')) {
        key = Buffer.from(intent.agent_did.slice('did:key:'.length), 'base64url');
      }
      if (!key || key.length !== 32) return 'Agent identity is not trusted';
      const result = validateIntent(intent, key);
      if (!result.valid) return result.errors.join('; ');
      const now = Date.now();
      const timestamp = Date.parse(intent.timestamp);
      if (timestamp < now - 300_000 || timestamp > now + 60_000) return 'Intent timestamp is expired or in the future';
      if (!Number.isSafeInteger(intent.nonce)) return 'Invalid intent nonce';
      const nonceKey = `${intent.agent_did}:${intent.nonce}`;
      for (const [key, expires] of this.nonces) if (expires < now) this.nonces.delete(key);
      if (this.nonces.has(nonceKey)) return 'Intent nonce has already been used';
      this.nonces.set(nonceKey, timestamp + 360_000);
      return null;
    } catch { return 'Invalid signed intent'; }
  }

  private checkBlacklist(intent: IntentV1): Omit<VerificationResult, 'tier'> | null {
    const to = intent.action.params.to as string | undefined;
    if (!to) return null;

    const blacklistedContacts = this.policy.blacklists?.contacts ?? [];
    if (blacklistedContacts.includes(to)) {
      return {
        approved: false,
        reason: `Recipient '${to}' is blacklisted`,
      };
    }

    const blacklistedDomains = this.policy.blacklists?.domains ?? [];
    for (const domain of blacklistedDomains) {
      if (to.includes(domain)) {
        return {
          approved: false,
          reason: `Recipient '${to}' matches blacklisted domain '${domain}'`,
        };
      }
    }

    return null;
  }

  private checkRateLimit(
    intent: IntentV1,
    tierConfig: PolicyConfig['tiers'][keyof PolicyConfig['tiers']],
  ): Omit<VerificationResult, 'tier'> | null {
    const rule = tierConfig.constraints?.rate_limit;
    if (!rule) return null;

    const result = this.rateLimiter.check(intent.agent_did, intent.action.type, rule);
    if (!result.allowed) {
      return {
        approved: false,
        reason: `Rate limit exceeded: ${rule.max} per ${rule.window} (resets at ${new Date(result.reset_at).toISOString()})`,
      };
    }

    return null;
  }

  private checkActionRateLimit(intent: IntentV1): Omit<VerificationResult, 'tier'> | null {
    const rule = this.policy.rate_limits?.[intent.action.type];
    if (!rule) return null;

    const result = this.rateLimiter.check(intent.agent_did, intent.action.type, rule);
    if (!result.allowed) {
      return {
        approved: false,
        reason: `Action rate limit exceeded for '${intent.action.type}': ${rule.max} per ${rule.window}`,
      };
    }

    return null;
  }
}
