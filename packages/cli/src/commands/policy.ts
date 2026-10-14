/**
 * `chitin-shell policy` — Policy management sub-commands
 *
 * - show   : Pretty-print the current policy with tier colors
 * - verify : Validate a policy file structure
 * - test   : Simulate running an action through the policy
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  loadDefaultPolicy,
  loadPolicyFromFile,
  PolicyEngine,
  generateKeyPair,
  createIntent,
  determineTier,
} from '@chitin-id/shell-core';
import type { PolicyConfig, TierConfig } from '@chitin-id/shell-core';
import {
  color,
  tierLabel,
  tierColor,
  parseFlag,
  loadConfig,
  loadPolicyForDisplay,
} from '../utils.js';

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export async function policyCommand(args: string[]): Promise<void> {
  const sub = args[0];

  switch (sub) {
    case 'show':
      return policyShow(args.slice(1));
    case 'verify':
      return policyVerify(args.slice(1));
    case 'test':
      return policyTest(args.slice(1));
    case '--help':
    case '-h':
    case undefined:
      return policyHelp();
    default:
      console.error(color.red(`Unknown policy sub-command: ${sub}`));
      policyHelp();
      process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// policy show
// ---------------------------------------------------------------------------

async function policyShow(args: string[]): Promise<void> {
  const filePath = parseFlag(args, '--file');
  const policy = await loadPolicyForDisplay(filePath);

  console.log(color.bold('Chitin Shell — Security Policy'));
  console.log(color.dim(`  Version: ${policy.version}`));
  console.log();

  const tierKeys = ['tier_0', 'tier_1', 'tier_2', 'tier_3'] as const;
  for (const tierKey of tierKeys) {
    const tier = Number(tierKey.charAt(5));
    const config: TierConfig = policy.tiers[tierKey];

    console.log(`  ${tierLabel(tier)}  ${color.dim(config.description)}`);
    console.log(`    Verification: ${color.cyan(config.verification)}`);
    console.log(`    Actions: ${config.actions.map((a) => color.white(a)).join(', ')}`);

    if (config.constraints?.rate_limit) {
      const rl = config.constraints.rate_limit;
      console.log(`    Rate limit: ${color.yellow(`${rl.max} per ${rl.window}`)}`);
    }
    if (config.constraints?.recipient_whitelist) {
      console.log(`    Recipient whitelist: ${color.green('enabled')}`);
    }
    if (config.multisig) {
      console.log(
        `    Multisig: ${color.magenta(`${config.multisig.required} required, timeout ${config.multisig.timeout}`)}`,
      );
    }
    console.log();
  }

  // Whitelists / Blacklists
  if (policy.whitelists) {
    const contacts = policy.whitelists.contacts ?? [];
    const domains = policy.whitelists.domains ?? [];
    if (contacts.length > 0 || domains.length > 0) {
      console.log(color.bold('  Whitelists'));
      if (contacts.length > 0) {
        console.log(`    Contacts: ${contacts.join(', ')}`);
      }
      if (domains.length > 0) {
        console.log(`    Domains: ${domains.join(', ')}`);
      }
      console.log();
    }
  }

  if (policy.blacklists) {
    const contacts = policy.blacklists.contacts ?? [];
    const domains = policy.blacklists.domains ?? [];
    if (contacts.length > 0 || domains.length > 0) {
      console.log(color.bold('  Blacklists'));
      if (contacts.length > 0) {
        console.log(`    Contacts: ${color.red(contacts.join(', '))}`);
      }
      if (domains.length > 0) {
        console.log(`    Domains: ${color.red(domains.join(', '))}`);
      }
      console.log();
    }
  }

  // Per-action rate limits
  if (policy.rate_limits && Object.keys(policy.rate_limits).length > 0) {
    console.log(color.bold('  Per-Action Rate Limits'));
    for (const [action, rule] of Object.entries(policy.rate_limits)) {
      console.log(`    ${color.white(action)}: ${rule.max} per ${rule.window}`);
    }
    console.log();
  }
}

// ---------------------------------------------------------------------------
// policy verify
// ---------------------------------------------------------------------------

const VALID_VERIFICATIONS = ['none', 'local', 'on_chain', 'human_approval'];
const REQUIRED_TIERS = ['tier_0', 'tier_1', 'tier_2', 'tier_3'] as const;

async function policyVerify(args: string[]): Promise<void> {
  const filePath = parseFlag(args, '--file');
  const errors: string[] = [];

  let policy: PolicyConfig;
  try {
    if (filePath) {
      policy = await loadPolicyFromFile(filePath);
    } else {
      try {
        const config = await loadConfig();
        policy = await loadPolicyFromFile(join(process.cwd(), config.policy));
      } catch {
        policy = loadDefaultPolicy();
      }
    }
  } catch (err) {
    console.log(color.red('  INVALID'));
    console.log(`  ${(err as Error).message}`);
    process.exit(1);
    return; // unreachable but satisfies TS
  }

  console.log(color.bold('Chitin Shell — Policy Verification'));
  console.log();

  // Check version
  if (!policy.version || typeof policy.version !== 'string') {
    errors.push('Missing or invalid "version" field');
  }

  // Check all tiers present
  for (const tierKey of REQUIRED_TIERS) {
    const tier = policy.tiers[tierKey];
    if (!tier) {
      errors.push(`Missing required tier: ${tierKey}`);
      continue;
    }

    // Check description
    if (!tier.description || typeof tier.description !== 'string') {
      errors.push(`${tierKey}: missing or invalid "description"`);
    }

    // Check actions array
    if (!Array.isArray(tier.actions)) {
      errors.push(`${tierKey}: "actions" must be an array`);
    } else if (tier.actions.length === 0) {
      errors.push(`${tierKey}: "actions" array is empty`);
    }

    // Check verification value
    if (!VALID_VERIFICATIONS.includes(tier.verification)) {
      errors.push(
        `${tierKey}: invalid verification "${tier.verification}" (expected: ${VALID_VERIFICATIONS.join(', ')})`,
      );
    }

    // Check rate limit structure
    if (tier.constraints?.rate_limit) {
      const rl = tier.constraints.rate_limit;
      if (typeof rl.max !== 'number' || rl.max <= 0) {
        errors.push(`${tierKey}: rate_limit.max must be a positive number`);
      }
      if (typeof rl.window !== 'string' || !rl.window.match(/^\d+[mhd]$/)) {
        errors.push(`${tierKey}: rate_limit.window must match format (e.g., "1m", "1h", "24h")`);
      }
    }

    // Check multisig structure
    if (tier.multisig) {
      if (typeof tier.multisig.required !== 'number' || tier.multisig.required < 1) {
        errors.push(`${tierKey}: multisig.required must be a positive number`);
      }
      if (typeof tier.multisig.timeout !== 'string') {
        errors.push(`${tierKey}: multisig.timeout must be a string`);
      }
    }
  }

  // Check per-action rate limits
  if (policy.rate_limits) {
    for (const [action, rule] of Object.entries(policy.rate_limits)) {
      if (typeof rule.max !== 'number' || rule.max <= 0) {
        errors.push(`rate_limits.${action}: max must be a positive number`);
      }
      if (typeof rule.window !== 'string' || !rule.window.match(/^\d+[mhd]$/)) {
        errors.push(`rate_limits.${action}: window must match format (e.g., "1m", "1h", "24h")`);
      }
    }
  }

  // Check for duplicate actions across tiers
  const allActions = new Map<string, string>();
  for (const tierKey of REQUIRED_TIERS) {
    const tier = policy.tiers[tierKey];
    if (!tier || !Array.isArray(tier.actions)) continue;
    for (const action of tier.actions) {
      if (allActions.has(action)) {
        errors.push(
          `Action "${action}" appears in both ${allActions.get(action)} and ${tierKey}`,
        );
      } else {
        allActions.set(action, tierKey);
      }
    }
  }

  // Print results
  if (errors.length === 0) {
    console.log(`  ${color.green('VALID')} — Policy passes all checks`);
    console.log();
    console.log(color.dim(`  Version: ${policy.version}`));
    console.log(
      color.dim(`  Total actions: ${allActions.size} across ${REQUIRED_TIERS.length} tiers`),
    );
  } else {
    console.log(`  ${color.red('INVALID')} — Found ${errors.length} error(s):`);
    console.log();
    for (const err of errors) {
      console.log(`  ${color.red('x')} ${err}`);
    }
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// policy test
// ---------------------------------------------------------------------------

async function policyTest(args: string[]): Promise<void> {
  const action = args[0];
  if (!action) {
    console.error(color.red('Usage: chitin-shell policy test <action> [--to recipient]'));
    process.exit(1);
  }

  const to = parseFlag(args, '--to');
  const filePath = parseFlag(args, '--file');

  let policy: PolicyConfig;
  if (filePath) {
    policy = await loadPolicyFromFile(filePath);
  } else {
    try {
      const config = await loadConfig();
      policy = await loadPolicyFromFile(join(process.cwd(), config.policy));
    } catch {
      policy = loadDefaultPolicy();
    }
  }

  const testKeys = generateKeyPair();
  const engine = new PolicyEngine(policy, undefined, undefined, { trustedDids: [testKeys.did] });
  const tier = determineTier(action, policy);

  // Build a mock intent for testing
  const params: Record<string, unknown> = {};
  if (to) params.to = to;

  const mockIntent = createIntent({ action, params }, testKeys);

  const result = engine.verify(mockIntent);

  console.log(color.bold('Chitin Shell — Policy Test'));
  console.log();
  console.log(`  Action:   ${color.white(action)}`);
  if (to) {
    console.log(`  To:       ${color.white(to)}`);
  }
  console.log(`  Tier:     ${tierLabel(tier)}`);
  console.log();

  if (result.approved) {
    console.log(`  Decision: ${color.green('APPROVED')}`);
  } else if (result.requires_human) {
    console.log(`  Decision: ${color.yellow('REQUIRES HUMAN APPROVAL')}`);
  } else {
    console.log(`  Decision: ${color.red('REJECTED')}`);
  }

  console.log(`  Reason:   ${color.dim(result.reason)}`);
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

function policyHelp(): void {
  console.log(color.bold('chitin-shell policy'));
  console.log();
  console.log('  Sub-commands:');
  console.log(`    ${color.cyan('show')}     Display the current policy`);
  console.log(`    ${color.cyan('verify')}   Validate a policy file`);
  console.log(`    ${color.cyan('test')}     Test an action against the policy`);
  console.log();
  console.log('  Options:');
  console.log('    --file <path>   Specify a custom policy file');
  console.log('    --to <recipient> Specify recipient for policy test');
}
