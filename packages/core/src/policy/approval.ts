import crypto from 'node:crypto';
import type { IntentV1 } from '../intent/types.js';
import { canonicalize } from '../intent/signer.js';

/** Host-owned authorization, bound to the complete intent and usable once. */
export class ApprovalAuthority {
  private readonly key: Buffer;
  private readonly consumed = new Map<string, number>();

  constructor(secret?: string) {
    if (secret !== undefined && Buffer.byteLength(secret) < 32) throw new Error('Approval secret must be at least 32 bytes');
    this.key = secret === undefined ? crypto.randomBytes(32) : Buffer.from(secret);
  }

  issue(intent: IntentV1): string {
    const payload = Buffer.from(JSON.stringify({ id: crypto.randomUUID(), expires: Date.now() + 30_000,
      hash: ApprovalAuthority.intentHash(intent) })).toString('base64url');
    return `${payload}.${this.mac(payload)}`;
  }

  consume(intent: IntentV1, token: string): boolean {
    try {
      const [payload, signature, extra] = token.split('.');
      if (!payload || !signature || extra || !/^[0-9a-f]{64}$/.test(signature)) return false;
      if (!crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(this.mac(payload), 'hex'))) return false;
      const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      const now = Date.now();
      if (!Number.isSafeInteger(data.expires) || data.expires <= now || data.expires > now + 30_000
        || data.hash !== ApprovalAuthority.intentHash(intent) || this.consumed.has(data.id)) return false;
      for (const [id, expires] of this.consumed) if (expires <= now) this.consumed.delete(id);
      this.consumed.set(data.id, data.expires);
      return true;
    } catch { return false; }
  }

  static intentHash(intent: IntentV1): string {
    return '0x' + crypto.createHash('sha256').update(canonicalize(intent)).digest('hex');
  }

  private mac(payload: string): string { return crypto.createHmac('sha256', this.key).update(payload).digest('hex'); }
}

export const localApprovalAuthority = new ApprovalAuthority();
