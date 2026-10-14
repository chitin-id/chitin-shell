import crypto from 'node:crypto';
import type { AgentKeyPair, CreateIntentParams, IntentV1, UnsignedIntent } from './types.js';
import { signIntent } from './signer.js';

export function createIntent(params: CreateIntentParams, keyPair: AgentKeyPair): IntentV1 {
  const unsigned: UnsignedIntent = {
    version: '1.0',
    intent_id: crypto.randomUUID(),
    agent_did: keyPair.did,
    timestamp: new Date().toISOString(),
    action: {
      type: params.action,
      params: params.params,
    },
    context: {
      triggered_by: params.context?.triggered_by ?? 'user_message',
      session_id: params.context?.session_id ?? crypto.randomUUID(),
      ...(params.context?.conversation_hash !== undefined && {
        conversation_hash: params.context.conversation_hash,
      }),
      ...(params.context?.parent_intent_id !== undefined && {
        parent_intent_id: params.context.parent_intent_id,
      }),
    },
    nonce: crypto.randomBytes(6).readUIntBE(0, 6) + 1,
  };

  const signature = signIntent(unsigned, keyPair.privateKey);

  return { ...unsigned, signature };
}
