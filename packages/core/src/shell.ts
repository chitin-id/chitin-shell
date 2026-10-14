import type { AgentKeyPair, CreateIntentParams, IntentV1 } from './intent/types.js';
import { generateKeyPair } from './intent/signer.js';
import { createIntent } from './intent/builder.js';
import type { PolicyConfig, VerificationResult } from './policy/types.js';
import { PolicyEngine } from './policy/engine.js';
import { loadPolicyFromFile, loadDefaultPolicy } from './policy/loader.js';
import { OnChainPolicyLoader } from './policy/on-chain-loader.js';
import type { OnChainPolicyConfig } from './policy/on-chain-loader.js';
import { DidResolver } from './intent/did-resolver.js';
import type { DidResolverConfig } from './intent/did-resolver.js';
import type { IVault, ExecutionResult, ActionMapper, SanitizationPattern } from './proxy/types.js';
import { MemoryVault } from './proxy/vault.js';
import { Sanitizer } from './proxy/sanitizer.js';
import { Executor } from './proxy/executor.js';
import { LocalAuditLogger } from './audit/local-logger.js';
import type { IAuditLogger } from './audit/types.js';
import { ChitinZkProver, ChitinZkVerifier } from './zkp/verifier.js';
import type { ZkProofBundle } from './zkp/types.js';

/** ZKP configuration for ChitinShell */
export interface ZkpConfig {
  /** Enable ZKP proof generation */
  enabled: boolean;
  /** Generate provenance proofs (default: true when zkp enabled) */
  provenance?: boolean;
  /** Generate non-leakage proofs (default: true when zkp enabled) */
  nonLeakage?: boolean;
  /** Generate skill safety proofs (default: false) */
  skillSafety?: boolean;
}

/** Options for executeWithProof */
export interface ExecuteWithProofOptions {
  /** User prompt for provenance proof */
  prompt?: string;
  /** Skill source code for skill safety proof */
  skillCode?: string;
}

/** Result of executeWithProof — extends the normal execute result with an optional proof bundle */
export interface ExecuteWithProofResult {
  verification: VerificationResult;
  execution?: ExecutionResult;
  proofBundle?: ZkProofBundle;
}

export interface ChitinShellOptions {
  policy?: string | PolicyConfig;
  vault?: IVault;
  auditDir?: string;
  additionalPatterns?: SanitizationPattern[];
  /** On-chain policy configuration (optional) */
  onChain?: OnChainPolicyConfig;
  /** DID resolver configuration (optional) */
  didResolver?: DidResolverConfig;
  /** ZKP configuration (optional) */
  zkp?: ZkpConfig;
}

export class ChitinShell {
  public readonly vault: IVault;
  public readonly audit: IAuditLogger;
  public readonly policyEngine: PolicyEngine;
  public readonly didResolver?: DidResolver;
  public readonly zkProver?: ChitinZkProver;
  public readonly zkVerifier?: ChitinZkVerifier;

  private keyPair: AgentKeyPair;
  private executor: Executor;
  private sanitizer: Sanitizer;
  private zkpConfig?: ZkpConfig;

  private constructor(
    vault: IVault,
    audit: IAuditLogger,
    policyEngine: PolicyEngine,
    keyPair: AgentKeyPair,
    executor: Executor,
    sanitizer: Sanitizer,
    didResolver?: DidResolver,
    zkProver?: ChitinZkProver,
    zkVerifier?: ChitinZkVerifier,
    zkpConfig?: ZkpConfig,
  ) {
    this.vault = vault;
    this.audit = audit;
    this.policyEngine = policyEngine;
    this.keyPair = keyPair;
    this.executor = executor;
    this.sanitizer = sanitizer;
    this.didResolver = didResolver;
    this.zkProver = zkProver;
    this.zkVerifier = zkVerifier;
    this.zkpConfig = zkpConfig;
  }

  static async create(options?: ChitinShellOptions): Promise<ChitinShell> {
    let policyConfig: PolicyConfig;

    if (typeof options?.policy === 'string') {
      policyConfig = await loadPolicyFromFile(options.policy);
    } else if (options?.policy !== undefined) {
      policyConfig = options.policy;
    } else {
      policyConfig = loadDefaultPolicy();
    }

    // Create on-chain policy loader if configured
    let onChainLoader: OnChainPolicyLoader | undefined;
    if (options?.onChain) {
      onChainLoader = new OnChainPolicyLoader(options.onChain);
    }

    // Create DID resolver if configured
    let didResolver: DidResolver | undefined;
    if (options?.didResolver) {
      didResolver = new DidResolver(options.didResolver);
    }

    const vault = options?.vault ?? new MemoryVault();
    const keyPair = generateKeyPair();
    const sanitizer = new Sanitizer(options?.additionalPatterns);
    const policyEngine = new PolicyEngine(policyConfig, undefined, onChainLoader, { trustedDids: [keyPair.did] });
    const executor = new Executor(vault, sanitizer);
    const audit = new LocalAuditLogger(options?.auditDir);

    // Initialize ZKP prover and verifier if enabled
    let zkProver: ChitinZkProver | undefined;
    let zkVerifier: ChitinZkVerifier | undefined;
    if (options?.zkp?.enabled) {
      zkProver = new ChitinZkProver();
      zkVerifier = new ChitinZkVerifier();
    }

    return new ChitinShell(
      vault, audit, policyEngine, keyPair, executor, sanitizer,
      didResolver, zkProver, zkVerifier, options?.zkp,
    );
  }

  createIntent(params: CreateIntentParams): IntentV1 {
    return createIntent(params, this.keyPair);
  }

  async execute(
    intent: IntentV1,
  ): Promise<{ verification: VerificationResult; execution?: ExecutionResult }> {
    const verification = this.policyEngine.verify(intent);

    await this.audit.log({
      intent_id: intent.intent_id,
      agent_did: intent.agent_did,
      action_type: intent.action.type,
      tier: verification.tier,
      decision: verification.approved ? 'approved' : 'rejected',
      reason: verification.reason,
    });

    if (!verification.approved || verification.requires_human) {
      return { verification };
    }

    const execution = await this.executor.execute(intent, verification.approval_token!);

    await this.audit.log({
      intent_id: intent.intent_id,
      agent_did: intent.agent_did,
      action_type: intent.action.type,
      tier: verification.tier,
      decision: 'approved',
      reason: verification.reason,
      execution_result: execution.status,
      execution_error: execution.error,
      execution_time_ms: execution.execution_time_ms,
    });

    return { verification, execution };
  }

  /**
   * Execute an intent with on-chain verification for tier 2+ actions.
   * Falls back to local verification for tier 0-1 actions.
   * Requires `onChain` to be configured in ChitinShellOptions.
   */
  async executeOnChain(
    intent: IntentV1,
  ): Promise<{ verification: VerificationResult; execution?: ExecutionResult }> {
    const verification = await this.policyEngine.verifyOnChain(intent);

    await this.audit.log({
      intent_id: intent.intent_id,
      agent_did: intent.agent_did,
      action_type: intent.action.type,
      tier: verification.tier,
      decision: verification.approved ? 'approved' : 'rejected',
      reason: verification.reason,
    });

    if (!verification.approved || verification.requires_human) {
      return { verification };
    }

    const execution = await this.executor.execute(intent, verification.approval_token!);

    await this.audit.log({
      intent_id: intent.intent_id,
      agent_did: intent.agent_did,
      action_type: intent.action.type,
      tier: verification.tier,
      decision: 'approved',
      reason: verification.reason,
      execution_result: execution.status,
      execution_error: execution.error,
      execution_time_ms: execution.execution_time_ms,
    });

    return { verification, execution };
  }

  /**
   * Execute an intent with ZK proof generation.
   * Runs the normal execute() pipeline, then generates proofs based on ZKP config.
   */
  async executeWithProof(
    intent: IntentV1,
    options?: ExecuteWithProofOptions,
  ): Promise<ExecuteWithProofResult> {
    // 1. Run normal execute() pipeline
    const result = await this.execute(intent);

    // 2. If zkp not enabled, return as-is
    if (!this.zkProver) {
      return result;
    }

    // 3. Generate proofs based on config
    const enableProvenance = this.zkpConfig?.provenance !== false;
    const enableNonLeakage = this.zkpConfig?.nonLeakage !== false;
    const enableSkillSafety = this.zkpConfig?.skillSafety === true;

    const bundle = await this.zkProver.generateBundle({
      prompt: enableProvenance && options?.prompt ? options.prompt : undefined,
      intent: enableProvenance ? intent : undefined,
      output: enableNonLeakage && result.execution?.data
        ? JSON.stringify(result.execution.data) : undefined,
      vaultEntries: enableNonLeakage
        ? await this.getVaultValues() : undefined,
      code: enableSkillSafety && options?.skillCode
        ? options.skillCode : undefined,
    });

    // 4. Log proof to audit
    await this.audit.log({
      intent_id: intent.intent_id,
      agent_did: intent.agent_did,
      action_type: intent.action.type,
      tier: 0,
      decision: 'approved',
      reason: 'proof_generated',
    });

    return { ...result, proofBundle: bundle };
  }

  /** Retrieve all vault values for non-leakage proof generation */
  private async getVaultValues(): Promise<string[]> {
    if (!this.vault) return [];
    const keys = await this.vault.list();
    const values: string[] = [];
    for (const key of keys) {
      const entry = await this.vault.get(key);
      if (entry) {
        values.push(typeof entry.value === 'string' ? entry.value : JSON.stringify(entry.value));
      }
    }
    return values;
  }

  registerMapper(mapper: ActionMapper): void {
    this.executor.registerMapper(mapper);
  }

  getAgentDid(): string {
    return this.keyPair.did;
  }
}
