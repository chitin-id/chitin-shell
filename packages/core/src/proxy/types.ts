/**
 * Secure Proxy — Type Definitions
 *
 * The Execute Layer holds all credentials and executes verified Intents.
 * The LLM NEVER has access to any value stored here.
 */

/** A single credential entry in the vault */
export interface VaultEntry {
  type: 'api_key' | 'oauth' | 'basic' | 'bearer' | 'custom';
  value: string;
  metadata?: Record<string, unknown>;
  created_at: string;
  expires_at?: string;
  /** HTTPS origins permitted to receive this credential. Empty/missing denies use. */
  allowed_origins?: string[];
}

/** Credential vault interface — implementations can be in-memory, keychain, or TEE-backed */
export interface IVault {
  get(key: string): Promise<VaultEntry | null>;
  set(key: string, entry: Omit<VaultEntry, 'created_at'>): Promise<void>;
  delete(key: string): Promise<boolean>;
  list(): Promise<string[]>;
  has(key: string): Promise<boolean>;
}

/** Result of executing an Intent */
export interface ExecutionResult {
  status: 'success' | 'error';
  data?: unknown;
  error?: string;
  sanitized: boolean;
  execution_time_ms: number;
}

/** Maps an action type to a concrete API call */
export interface ActionMapper {
  readonly action_type: string;
  execute(
    params: Record<string, unknown>,
    vault: IVault,
  ): Promise<unknown>;
}

/** Sanitizer pattern definition */
export interface SanitizationPattern {
  name: string;
  pattern: RegExp;
  replacement: string;
}
