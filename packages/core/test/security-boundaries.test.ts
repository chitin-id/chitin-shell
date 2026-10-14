import { describe, expect, it, vi } from 'vitest';
import { generateKeyPair } from '../src/intent/signer.js';
import { createIntent } from '../src/intent/builder.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { loadDefaultPolicy } from '../src/policy/loader.js';
import { ApprovalAuthority } from '../src/policy/approval.js';
import { GenericHttpMapper } from '../src/proxy/mappers/generic-http.js';
import { MemoryVault } from '../src/proxy/vault.js';
import { ChitinShell } from '../src/shell.js';

describe('Shell authorization boundaries', () => {
  it('rejects forged, untrusted, expired and replayed intents', () => {
    const keys = generateKeyPair();
    const other = generateKeyPair();
    const engine = new PolicyEngine(loadDefaultPolicy(), undefined, undefined, { trustedDids: [keys.did] });
    const intent = createIntent({ action: 'think', params: { query: 'approved' } }, keys);
    expect(engine.verify({ ...intent, signature: '00' }).approved).toBe(false);
    expect(engine.verify(createIntent({ action: 'think', params: {} }, other)).approved).toBe(false);
    expect(engine.verify({ ...intent, action: { type: 'think', params: { query: 'altered' } } }).approved).toBe(false);
    expect(engine.verify(intent).approved).toBe(true);
    expect(engine.verify(intent).approved).toBe(false);
    const expired = createIntent({ action: 'think', params: {} }, keys);
    expired.timestamp = new Date(1).toISOString();
    expect(engine.verify(expired).approved).toBe(false);
  });

  it('binds approval tokens to nested parameters and rejects arbitrary tokens/replay', () => {
    const authority = new ApprovalAuthority();
    const intent = createIntent({ action: 'api_call', params: { url: 'https://allowed.example/api', nested: { value: 1 } } }, generateKeyPair());
    const token = authority.issue(intent);
    const changed = { ...intent, action: { ...intent.action, params: { ...intent.action.params, nested: { value: 2 } } } };
    expect(ApprovalAuthority.intentHash(changed)).not.toBe(ApprovalAuthority.intentHash(intent));
    expect(authority.consume(changed, token)).toBe(false);
    expect(authority.consume(intent, 'arbitrary-token')).toBe(false);
    expect(authority.consume(intent, token)).toBe(true);
    expect(authority.consume(intent, token)).toBe(false);
  });

  it('refuses to send vault credentials to an unapproved destination', async () => {
    const vault = new MemoryVault();
    await vault.set('service', { type: 'bearer', value: 'fixture-placeholder', allowed_origins: ['https://api.allowed.example'] });
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    try {
      await expect(new GenericHttpMapper().execute({ url: 'https://attacker.example/collect', credential_key: 'service' }, vault)).rejects.toThrow('not authorized');
      expect(fetch).not.toHaveBeenCalled();
    } finally { vi.unstubAllGlobals(); }
  });

  it('does not execute a forged intent through the public Shell pipeline', async () => {
    const shell = await ChitinShell.create();
    const execute = vi.fn(async () => 'fixture');
    shell.registerMapper({ action_type: 'think', execute });
    const intent = shell.createIntent({ action: 'think', params: {} });
    const rejected = await shell.execute({ ...intent, signature: '00' });
    expect(rejected.verification.approved).toBe(false);
    expect(execute).not.toHaveBeenCalled();
    expect((await shell.execute(intent)).verification.approved).toBe(true);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it('fails closed on an on-chain tier without chain verification', () => {
    const keys = generateKeyPair();
    const engine = new PolicyEngine(loadDefaultPolicy(), undefined, undefined, { trustedDids: [keys.did] });
    expect(engine.verify(createIntent({ action: 'api_call', params: {} }, keys)).approved).toBe(false);
  });
});
