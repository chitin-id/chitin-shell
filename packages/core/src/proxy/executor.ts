import type { ActionMapper, ExecutionResult, IVault } from './types.js';
import type { IntentV1 } from '../intent/types.js';
import { Sanitizer } from './sanitizer.js';
import { ApprovalAuthority, localApprovalAuthority } from '../policy/approval.js';

export class Executor {
  private mappers: Map<string, ActionMapper>;
  private vault: IVault;
  private sanitizer: Sanitizer;

  constructor(vault: IVault, sanitizer: Sanitizer, mappers?: Map<string, ActionMapper>, private approvalAuthority: ApprovalAuthority = localApprovalAuthority) {
    this.vault = vault;
    this.sanitizer = sanitizer;
    this.mappers = mappers ?? new Map();
  }

  registerMapper(mapper: ActionMapper): void {
    this.mappers.set(mapper.action_type, mapper);
  }

  async execute(intent: IntentV1, approvalToken: string): Promise<ExecutionResult> {
    const start = Date.now();
    if (!this.approvalAuthority.consume(intent, approvalToken)) {
      return { status: 'error', error: 'Invalid, expired or reused approval token', sanitized: false, execution_time_ms: Date.now() - start };
    }

    const mapper = this.mappers.get(intent.action.type);
    if (!mapper) {
      return {
        status: 'error',
        error: `No mapper registered for action: ${intent.action.type}`,
        sanitized: false,
        execution_time_ms: Date.now() - start,
      };
    }

    try {
      const raw = await mapper.execute(intent.action.params, this.vault);

      const { output, redacted_count } = typeof raw === 'string'
        ? this.sanitizer.sanitize(raw)
        : this.sanitizer.sanitizeObject(raw);

      return {
        status: 'success',
        data: output,
        sanitized: redacted_count > 0,
        execution_time_ms: Date.now() - start,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const { output: sanitizedMessage } = this.sanitizer.sanitize(message);

      return {
        status: 'error',
        error: sanitizedMessage,
        sanitized: true,
        execution_time_ms: Date.now() - start,
      };
    }
  }
}
