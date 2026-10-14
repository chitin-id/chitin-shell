import { generateKeyPair } from "../src/intent/signer.js";
import { createIntent } from "../src/intent/builder.js";
const testKeys = generateKeyPair();
import { describe, it, expect, beforeEach } from 'vitest';
import { determineTier } from '../src/policy/tier.js';
import { RateLimiter } from '../src/policy/rate-limiter.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { loadDefaultPolicy } from '../src/policy/loader.js';
import type { PolicyConfig } from '../src/policy/types.js';
import type { IntentV1 } from '../src/intent/types.js';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function mockIntent(
  actionType: string,
  params: Record<string, unknown> = {},
): IntentV1 {
  return createIntent({ action: actionType, params, context: { triggered_by: "user_message", session_id: "test-session" } }, testKeys);
}

// ---------------------------------------------------------------------------
// Tier Determination
// ---------------------------------------------------------------------------

describe('Tier Determination', () => {
  let policy: PolicyConfig;

  beforeEach(() => {
    policy = loadDefaultPolicy();
  });

  it('returns tier 0 for "think"', () => {
    expect(determineTier('think', policy)).toBe(0);
  });

  it('returns tier 0 for "summarize"', () => {
    expect(determineTier('summarize', policy)).toBe(0);
  });

  it('returns tier 1 for "send_message"', () => {
    expect(determineTier('send_message', policy)).toBe(1);
  });

  it('returns tier 1 for "reply_email"', () => {
    expect(determineTier('reply_email', policy)).toBe(1);
  });

  it('returns tier 2 for "send_email_new"', () => {
    expect(determineTier('send_email_new', policy)).toBe(2);
  });

  it('returns tier 2 for "file_write"', () => {
    expect(determineTier('file_write', policy)).toBe(2);
  });

  it('returns tier 3 for "transfer_funds"', () => {
    expect(determineTier('transfer_funds', policy)).toBe(3);
  });

  it('returns tier 3 for unknown actions (fail-safe)', () => {
    expect(determineTier('unknown_action', policy)).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Rate Limiter
// ---------------------------------------------------------------------------

describe('Rate Limiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter();
  });

  it('allows requests within limit', () => {
    const rule = { max: 3, window: '1m' };
    limiter.record('did:key:agent-a', 'send_message');
    limiter.record('did:key:agent-a', 'send_message');

    const result = limiter.check('did:key:agent-a', 'send_message', rule);

    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(1);
  });

  it('blocks requests exceeding limit', () => {
    const rule = { max: 2, window: '1m' };
    limiter.record('did:key:agent-a', 'send_message');
    limiter.record('did:key:agent-a', 'send_message');

    const result = limiter.check('did:key:agent-a', 'send_message', rule);

    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it('resets correctly', () => {
    const rule = { max: 1, window: '1m' };
    limiter.record('did:key:agent-a', 'send_message');

    // Before reset — should be blocked
    expect(limiter.check('did:key:agent-a', 'send_message', rule).allowed).toBe(false);

    // Reset for this specific agent
    limiter.reset('did:key:agent-a');

    // After reset — should be allowed again
    expect(limiter.check('did:key:agent-a', 'send_message', rule).allowed).toBe(true);
  });

  it('resets all agents when called without argument', () => {
    const rule = { max: 1, window: '1m' };
    limiter.record('did:key:agent-a', 'send_message');
    limiter.record('did:key:agent-b', 'send_message');

    limiter.reset();

    expect(limiter.check('did:key:agent-a', 'send_message', rule).allowed).toBe(true);
    expect(limiter.check('did:key:agent-b', 'send_message', rule).allowed).toBe(true);
  });

  it('tracks per-agent separately', () => {
    const rule = { max: 1, window: '1m' };
    limiter.record('did:key:agent-a', 'send_message');

    // Agent A should be blocked
    expect(limiter.check('did:key:agent-a', 'send_message', rule).allowed).toBe(false);

    // Agent B has no records yet — should be allowed
    expect(limiter.check('did:key:agent-b', 'send_message', rule).allowed).toBe(true);
  });

  it('cleans up old entries outside the window', () => {
    const rule = { max: 1, window: '1m' };

    // Manually inject a timestamp that is older than 1 minute
    // We access the internal state via record + time manipulation
    const agentDid = 'did:key:agent-old';
    const actionType = 'send_message';

    // Record a request, then manually backdate the timestamp
    limiter.record(agentDid, actionType);

    // Access internal entries map via check (which filters by cutoff).
    // To test cleanup: we simulate time passing by adding an entry with a very
    // old timestamp. We use a second limiter instance to control timestamps.
    const limiter2 = new RateLimiter();
    // @ts-expect-error -- accessing private field for testing
    const key = `${agentDid}:${actionType}`;
    // @ts-expect-error -- accessing private field for testing
    limiter2['entries'].set(key, [Date.now() - 120_000]); // 2 minutes ago

    const result = limiter2.check(agentDid, actionType, rule);

    // The old entry should have been cleaned up, so the check should pass
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Policy Engine
// ---------------------------------------------------------------------------

describe('Policy Engine', () => {
  let policy: PolicyConfig;
  let engine: PolicyEngine;

  beforeEach(() => {
    policy = loadDefaultPolicy();
    // Populate whitelists and blacklists for testing
    policy.whitelists = {
      contacts: ['alice@example.com', 'bob@example.com'],
      domains: ['example.com'],
      actions: [],
    };
    policy.blacklists = {
      contacts: ['mallory@evil.com'],
      domains: ['evil.com'],
    };
    policy.tiers.tier_2.verification = "local";
    engine = new PolicyEngine(policy, undefined, undefined, { trustedDids: [testKeys.did] });
  });

  it('tier 0 actions are always approved', () => {
    const intent = mockIntent('think');
    const result = engine.verify(intent);

    expect(result.approved).toBe(true);
    expect(result.tier).toBe(0);
    expect(result.reason).toContain('auto-approved');
  });

  it('tier 1 actions approved when recipient is whitelisted', () => {
    const intent = mockIntent('send_message', { to: 'alice@example.com' });
    const result = engine.verify(intent);

    expect(result.approved).toBe(true);
    expect(result.tier).toBe(1);
  });

  it('tier 1 actions rejected when recipient is not whitelisted', () => {
    const intent = mockIntent('send_message', { to: 'stranger@unknown.com' });
    const result = engine.verify(intent);

    expect(result.approved).toBe(false);
    expect(result.tier).toBe(1);
    expect(result.reason).toContain('not in the approved contacts whitelist');
  });

  it('tier 3 actions require human approval', () => {
    const intent = mockIntent('transfer_funds', { amount: 1000 });
    const result = engine.verify(intent);

    expect(result.approved).toBe(false);
    expect(result.tier).toBe(3);
    expect(result.requires_human).toBe(true);
    expect(result.reason).toContain('human approval');
  });

  it('blacklisted contacts are rejected', () => {
    const intent = mockIntent('send_message', { to: 'mallory@evil.com' });
    const result = engine.verify(intent);

    expect(result.approved).toBe(false);
    expect(result.reason).toContain('blacklisted');
  });

  it('blacklisted domains are rejected', () => {
    const intent = mockIntent('reply_email', { to: 'anyone@evil.com' });
    const result = engine.verify(intent);

    expect(result.approved).toBe(false);
    expect(result.reason).toContain('blacklisted domain');
    expect(result.reason).toContain('evil.com');
  });

  it('approved intents get an approval_token (non-empty string)', () => {
    const intent = mockIntent('think');
    const result = engine.verify(intent);

    expect(result.approved).toBe(true);
    expect(result.approval_token).toBeDefined();
    expect(typeof result.approval_token).toBe('string');
    expect(result.approval_token!.length).toBeGreaterThan(0);
  });

  it('rate limiting blocks excessive requests', () => {
    // Default tier 1 rate limit is max: 10 per 1m
    // Send 10 requests to fill the limit, then verify the 11th is blocked
    for (let i = 0; i < 10; i++) {
      const intent = mockIntent('send_message', { to: 'alice@example.com' });
      const result = engine.verify(intent);
      expect(result.approved).toBe(true);
    }

    const overflowIntent = mockIntent('send_message', { to: 'alice@example.com' });
    const result = engine.verify(overflowIntent);

    expect(result.approved).toBe(false);
    expect(result.reason).toContain('Rate limit exceeded');
  });

  it('unknown actions default to tier 3 (human approval required)', () => {
    const intent = mockIntent('totally_new_action');
    const result = engine.verify(intent);

    expect(result.approved).toBe(false);
    expect(result.tier).toBe(3);
    expect(result.requires_human).toBe(true);
  });

  it('tier 2 actions are approved when within rate limit', () => {
    const intent = mockIntent('file_write', { path: '/tmp/test.txt' });
    const result = engine.verify(intent);

    expect(result.approved).toBe(true);
    expect(result.tier).toBe(2);
    expect(result.approval_token).toBeDefined();
  });

  it('tier 1 actions approved when no recipient (no whitelist check needed)', () => {
    // A tier 1 action without a "to" param should still pass
    const intent = mockIntent('post_channel', { channel: '#general', text: 'hello' });
    const result = engine.verify(intent);

    expect(result.approved).toBe(true);
    expect(result.tier).toBe(1);
  });

  it('each approval_token is unique', () => {
    const result1 = engine.verify(mockIntent('think'));
    const result2 = engine.verify(mockIntent('summarize'));

    expect(result1.approval_token).toBeDefined();
    expect(result2.approval_token).toBeDefined();
    expect(result1.approval_token).not.toBe(result2.approval_token);
  });

  it('blacklist check applies to tier 2 actions as well', () => {
    const intent = mockIntent('send_email_new', { to: 'mallory@evil.com' });
    const result = engine.verify(intent);

    expect(result.approved).toBe(false);
    expect(result.tier).toBe(2);
    expect(result.reason).toContain('blacklisted');
  });
});
