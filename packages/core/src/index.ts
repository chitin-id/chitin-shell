// Core
export { ChitinShell } from './shell.js';
export type { ChitinShellOptions, ZkpConfig, ExecuteWithProofOptions, ExecuteWithProofResult } from './shell.js';

// Intent
export { createIntent } from './intent/builder.js';
export { generateKeyPair, signIntent, verifySignature } from './intent/signer.js';
export { validateIntentStructure, validateIntent } from './intent/validator.js';
export { DidResolver } from './intent/did-resolver.js';
export type { IntentV1, UnsignedIntent, CreateIntentParams, IntentAction, IntentContext, ActionType, SecurityTier, AgentKeyPair } from './intent/types.js';
export type { DidResolverConfig, ResolvedDid, ParsedDid } from './intent/did-resolver.js';

// Policy
export { PolicyEngine } from './policy/engine.js';
export { ApprovalAuthority } from './policy/approval.js';
export { RateLimiter } from './policy/rate-limiter.js';
export { loadPolicyFromFile, loadDefaultPolicy } from './policy/loader.js';
export { determineTier } from './policy/tier.js';
export { OnChainPolicyLoader } from './policy/on-chain-loader.js';
export type { PolicyConfig, TierConfig, RateLimitRule, VerificationResult } from './policy/types.js';
export type { OnChainPolicyConfig, OnChainVerificationResult } from './policy/on-chain-loader.js';

// Proxy
export { MemoryVault } from './proxy/vault.js';
export { Sanitizer } from './proxy/sanitizer.js';
export { Executor } from './proxy/executor.js';
export { GenericHttpMapper } from './proxy/mappers/generic-http.js';
export type { IVault, VaultEntry, ExecutionResult, ActionMapper, SanitizationPattern } from './proxy/types.js';

// Audit
export { LocalAuditLogger } from './audit/local-logger.js';
export { AuditAnchor } from './audit/anchor.js';
export { AnchoredAuditLogger } from './audit/anchored-logger.js';
export {
  buildMerkleTree,
  generateMerkleProof,
  verifyMerkleProof,
  hashAuditEntry,
} from './audit/merkle.js';
export type { IAuditLogger, AuditEntry, AuditQueryFilter } from './audit/types.js';
export type { AnchorConfig, AnchorResult, InclusionProof } from './audit/anchor.js';

// Schema
export { validateAgainstSchema, validateIntentSchema, validatePolicySchema } from './schema/index.js';
export type { ValidationResult } from './schema/index.js';

// ZKP
export {
  commit,
  verifyCommitment,
  hashToHex,
  generateBlindingFactor,
  generateProvenanceProof,
  verifyProvenanceProof,
  verifyProvenanceWithOpening,
  generateNonLeakageProof,
  verifyNonLeakageProof,
  quickLeakageCheck,
  analyzeSkillSafety,
  generateSkillSafetyProof,
  verifySkillSafetyProof,
  ChitinZkProver,
  ChitinZkVerifier,
} from './zkp/index.js';
export type {
  ProofScheme,
  Commitment,
  Opening,
  ProvenanceProof,
  NonLeakageProof,
  SkillSafetyProof,
  SkillSafetyCheck,
  ZkProofBundle,
  ZkProver,
  ZkVerifier,
} from './zkp/index.js';

// Trust Delegation
export { DelegationManager } from './trust/delegation.js';
export type { CreateDelegationParams } from './trust/delegation.js';
export { MemoryTrustStore } from './trust/store.js';
export { intersectScopes, scopeAllowsAction, isSubScope, validateScope } from './trust/scope.js';
export type {
  DelegationScope,
  DelegationToken,
  TrustChain,
  DelegationResult,
  TrustStoreEntry,
  ITrustStore,
} from './trust/types.js';

// A2A (Agent-to-Agent)
export {
  MemoryA2ARegistry,
  canonicalizeMessage,
  createA2AMessage,
  verifyA2AMessage,
  createErrorResponse,
  isMessageExpired,
  A2AClient,
  A2AServer,
  createA2AMapper,
  createSecureA2AHandler,
} from './a2a/index.js';
export type {
  A2AEndpoint,
  A2AMessage,
  A2APayload,
  A2AConfig,
  A2ARegistry,
  A2AStats,
  A2AHandler,
} from './a2a/index.js';

// TEE (Trusted Execution Environment)
export { MockTeeProvider, TeeVault } from './tee/index.js';
export type {
  TeeProvider,
  TeeAttestation,
  TeeMeasurement,
  TeeConfig,
  TeeCapabilities,
  ITeeProvider,
} from './tee/index.js';

// Health
export { HealthMonitor } from './health.js';
export type { HealthStatus, HealthCheck, HealthReport } from './health.js';

// Metrics
export { MetricsCollector } from './metrics.js';
export type { MetricPoint, MetricType, MetricDefinition } from './metrics.js';

// Config Validator
export { validateShellConfig } from './config-validator.js';
export type { ConfigValidationResult } from './config-validator.js';
