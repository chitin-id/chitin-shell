import { localApprovalAuthority } from "../src/policy/approval.js";
import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryVault } from '../src/proxy/vault.js';
import { Sanitizer } from '../src/proxy/sanitizer.js';
import { Executor } from '../src/proxy/executor.js';
import type { ActionMapper, IVault } from '../src/proxy/types.js';
import type { IntentV1 } from '../src/intent/types.js';

function mockIntent(actionType: string, params: Record<string, unknown> = {}): IntentV1 {
  return {
    version: '1.0',
    intent_id: 'test-intent-1',
    agent_did: 'did:key:test-agent',
    timestamp: new Date().toISOString(),
    action: { type: actionType, params },
    context: { triggered_by: 'user_message', session_id: 'test-session' },
    nonce: Date.now(),
    signature: 'aa'.repeat(32),
  };
}

// ---------------------------------------------------------------------------
// MemoryVault
// ---------------------------------------------------------------------------
describe('MemoryVault', () => {
  let vault: MemoryVault;

  beforeEach(() => {
    vault = new MemoryVault();
  });

  it('set and get a credential', async () => {
    await vault.set('openai', { type: 'api_key', value: 'sk-test-123' });
    const entry = await vault.get('openai');

    expect(entry).not.toBeNull();
    expect(entry!.type).toBe('api_key');
    expect(entry!.value).toBe('sk-test-123');
  });

  it('get returns null for missing key', async () => {
    const entry = await vault.get('nonexistent');
    expect(entry).toBeNull();
  });

  it('delete removes a credential and returns true', async () => {
    await vault.set('temp', { type: 'bearer', value: 'abc' });
    const deleted = await vault.delete('temp');

    expect(deleted).toBe(true);
    expect(await vault.get('temp')).toBeNull();
  });

  it('delete returns false for missing key', async () => {
    const deleted = await vault.delete('ghost');
    expect(deleted).toBe(false);
  });

  it('list returns all keys', async () => {
    await vault.set('a', { type: 'api_key', value: '1' });
    await vault.set('b', { type: 'api_key', value: '2' });
    await vault.set('c', { type: 'bearer', value: '3' });

    const keys = await vault.list();
    expect(keys).toHaveLength(3);
    expect(keys).toContain('a');
    expect(keys).toContain('b');
    expect(keys).toContain('c');
  });

  it('has returns true for existing key', async () => {
    await vault.set('exists', { type: 'custom', value: 'v' });
    expect(await vault.has('exists')).toBe(true);
  });

  it('has returns false for missing key', async () => {
    expect(await vault.has('nope')).toBe(false);
  });

  it('set automatically adds created_at timestamp', async () => {
    const before = new Date().toISOString();
    await vault.set('stamped', { type: 'api_key', value: 'x' });
    const after = new Date().toISOString();

    const entry = await vault.get('stamped');
    expect(entry).not.toBeNull();
    expect(entry!.created_at).toBeDefined();
    expect(typeof entry!.created_at).toBe('string');
    // The timestamp must fall within the before/after window
    expect(entry!.created_at >= before).toBe(true);
    expect(entry!.created_at <= after).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Sanitizer
// ---------------------------------------------------------------------------
describe('Sanitizer', () => {
  let sanitizer: Sanitizer;

  beforeEach(() => {
    sanitizer = new Sanitizer();
  });

  it('detects and redacts OpenAI API keys', () => {
    const input = 'My key is sk-abcdefghijklmnopqrstuvwxyz1234567890';
    const result = sanitizer.sanitize(input);

    expect(result.output).toContain('[REDACTED:openai_key]');
    expect(result.output).not.toContain('sk-abcdefghij');
    expect(result.redacted_count).toBeGreaterThanOrEqual(1);
    expect(result.redacted_types).toContain('openai_key');
  });

  it('detects and redacts Anthropic keys', () => {
    const input = 'Key: sk-ant-abcdefghijklmnopqrstuvwxyz1234567890';
    const result = sanitizer.sanitize(input);

    expect(result.output).toContain('[REDACTED:anthropic_key]');
    expect(result.output).not.toContain('sk-ant-abcdefghij');
    expect(result.redacted_types).toContain('anthropic_key');
  });

  it('detects and redacts AWS keys', () => {
    const input = 'AWS access key: AKIAIOSFODNN7EXAMPLE';
    const result = sanitizer.sanitize(input);

    expect(result.output).toContain('[REDACTED:aws_key]');
    expect(result.output).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(result.redacted_types).toContain('aws_key');
  });

  it('detects and redacts GitHub tokens', () => {
    const input = 'Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn';
    const result = sanitizer.sanitize(input);

    expect(result.output).toContain('[REDACTED:github_token]');
    expect(result.output).not.toContain('ghp_ABCDEFGHIJ');
    expect(result.redacted_types).toContain('github_token');
  });

  it('detects and redacts JWTs', () => {
    const header = Buffer.from('{"alg":"HS256"}').toString('base64url');
    const payload = Buffer.from('{"sub":"1234567890"}').toString('base64url');
    const sig = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const jwt = `${header}.${payload}.${sig}`;
    const input = `Authorization: ${jwt}`;
    const result = sanitizer.sanitize(input);

    expect(result.output).toContain('[REDACTED:jwt]');
    expect(result.output).not.toContain(payload);
    expect(result.redacted_types).toContain('jwt');
  });

  it('detects and redacts Bearer tokens', () => {
    const input = 'Authorization: Bearer my-secret-token-value';
    const result = sanitizer.sanitize(input);

    expect(result.output).toContain('[REDACTED:bearer_token]');
    expect(result.output).not.toContain('my-secret-token-value');
    expect(result.redacted_types).toContain('bearer_token');
  });

  it('detects and redacts connection strings (postgres://)', () => {
    const input = 'DATABASE_URL=postgres://user:password@host:5432/db';
    const result = sanitizer.sanitize(input);

    expect(result.output).toContain('[REDACTED:connection_string]');
    expect(result.output).not.toContain('postgres://user:password');
    expect(result.redacted_types).toContain('connection_string');
  });

  it('detects and redacts generic secrets (password=xxx)', () => {
    const input = 'config: password=super_secret_123';
    const result = sanitizer.sanitize(input);

    expect(result.output).toContain('[REDACTED:generic_secret]');
    expect(result.output).not.toContain('super_secret_123');
    expect(result.redacted_types).toContain('generic_secret');
  });

  it('returns redacted_count and redacted_types metadata', () => {
    const input =
      'Keys: sk-abcdefghijklmnopqrstuvwxyz1234567890 and AKIAIOSFODNN7EXAMPLE';
    const result = sanitizer.sanitize(input);

    expect(result.redacted_count).toBe(2);
    expect(result.redacted_types).toContain('openai_key');
    expect(result.redacted_types).toContain('aws_key');
  });

  it('sanitizeObject deep-traverses nested objects', () => {
    const obj = {
      level1: {
        level2: {
          key: 'sk-abcdefghijklmnopqrstuvwxyz1234567890',
        },
      },
      safe: 'hello world',
    };
    const result = sanitizer.sanitizeObject(obj);

    const output = result.output as Record<string, unknown>;
    const level2 = (output.level1 as Record<string, unknown>).level2 as Record<
      string,
      unknown
    >;
    expect(level2.key).toContain('[REDACTED:openai_key]');
    expect(output.safe).toBe('hello world');
    expect(result.redacted_count).toBe(1);
    expect(result.redacted_types).toContain('openai_key');
  });

  it('sanitizeObject handles arrays', () => {
    const obj = {
      items: [
        'safe-string',
        'sk-abcdefghijklmnopqrstuvwxyz1234567890',
        'AKIAIOSFODNN7EXAMPLE',
      ],
    };
    const result = sanitizer.sanitizeObject(obj);

    const output = result.output as Record<string, unknown>;
    const items = output.items as string[];
    expect(items[0]).toBe('safe-string');
    expect(items[1]).toContain('[REDACTED:openai_key]');
    expect(items[2]).toContain('[REDACTED:aws_key]');
    expect(result.redacted_count).toBe(2);
  });

  it('does not modify non-secret strings', () => {
    const input = 'This is a perfectly normal string with no secrets.';
    const result = sanitizer.sanitize(input);

    expect(result.output).toBe(input);
    expect(result.redacted_count).toBe(0);
    expect(result.redacted_types).toHaveLength(0);
  });

  it('handles empty string input', () => {
    const result = sanitizer.sanitize('');

    expect(result.output).toBe('');
    expect(result.redacted_count).toBe(0);
    expect(result.redacted_types).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------
describe('Executor', () => {
  let vault: MemoryVault;
  let sanitizer: Sanitizer;
  let executor: Executor;

  beforeEach(() => {
    vault = new MemoryVault();
    sanitizer = new Sanitizer();
    executor = new Executor(vault, sanitizer);
  });

  it('returns error when no mapper is registered for action type', async () => {
    const intent = mockIntent('unknown_action');
    const result = await executor.execute(intent, localApprovalAuthority.issue(intent));

    expect(result.status).toBe('error');
    expect(result.error).toContain('No mapper registered for action');
    expect(result.error).toContain('unknown_action');
    expect(result.execution_time_ms).toBeGreaterThanOrEqual(0);
  });

  it('successfully executes with a registered mapper', async () => {
    const mapper: ActionMapper = {
      action_type: 'greet',
      async execute(params: Record<string, unknown>) {
        return { message: `Hello, ${params.name}!` };
      },
    };
    executor.registerMapper(mapper);

    const intent = mockIntent('greet', { name: 'Eiji' });
    const result = await executor.execute(intent, localApprovalAuthority.issue(intent));

    expect(result.status).toBe('success');
    const data = result.data as Record<string, unknown>;
    expect(data.message).toBe('Hello, Eiji!');
    expect(result.sanitized).toBe(false);
  });

  it('sanitizes the execution result', async () => {
    const mapper: ActionMapper = {
      action_type: 'leak_key',
      async execute() {
        return {
          response: 'Your key is sk-abcdefghijklmnopqrstuvwxyz1234567890',
        };
      },
    };
    executor.registerMapper(mapper);

    const intent = mockIntent('leak_key');
    const result = await executor.execute(intent, localApprovalAuthority.issue(intent));

    expect(result.status).toBe('success');
    expect(result.sanitized).toBe(true);
    const data = result.data as Record<string, unknown>;
    expect(data.response).toContain('[REDACTED:openai_key]');
    expect(data.response).not.toContain('sk-abcdefghij');
  });

  it('sanitizes error messages on failure', async () => {
    const mapper: ActionMapper = {
      action_type: 'fail_with_secret',
      async execute() {
        throw new Error(
          'Connection failed: postgres://admin:s3cret@db.example.com:5432/prod',
        );
      },
    };
    executor.registerMapper(mapper);

    const intent = mockIntent('fail_with_secret');
    const result = await executor.execute(intent, localApprovalAuthority.issue(intent));

    expect(result.status).toBe('error');
    expect(result.sanitized).toBe(true);
    expect(result.error).toContain('[REDACTED:connection_string]');
    expect(result.error).not.toContain('postgres://admin:s3cret');
  });

  it('measures execution_time_ms', async () => {
    const mapper: ActionMapper = {
      action_type: 'slow_op',
      async execute() {
        await new Promise((resolve) => setTimeout(resolve, 50));
        return { done: true };
      },
    };
    executor.registerMapper(mapper);

    const intent = mockIntent('slow_op');
    const result = await executor.execute(intent, localApprovalAuthority.issue(intent));

    expect(result.status).toBe('success');
    expect(result.execution_time_ms).toBeGreaterThanOrEqual(40);
  });

  it('registerMapper adds a custom mapper', async () => {
    // Before registration, should fail
    const intentBefore = mockIntent('custom_action');
    const beforeResult = await executor.execute(intentBefore, localApprovalAuthority.issue(intentBefore));
    expect(beforeResult.status).toBe('error');

    // Register and try again
    const mapper: ActionMapper = {
      action_type: 'custom_action',
      async execute(params: Record<string, unknown>, v: IVault) {
        // Verify vault is accessible
        const cred = await v.get('my-cred');
        return { vault_has_cred: cred !== null, params };
      },
    };
    executor.registerMapper(mapper);

    await vault.set('my-cred', { type: 'api_key', value: 'v' });
    const intentAfter = mockIntent('custom_action', { foo: 'bar' });
    const afterResult = await executor.execute(intentAfter, localApprovalAuthority.issue(intentAfter));

    expect(afterResult.status).toBe('success');
    const data = afterResult.data as Record<string, unknown>;
    expect(data.vault_has_cred).toBe(true);
    expect(data.params).toEqual({ foo: 'bar' });
  });
});
