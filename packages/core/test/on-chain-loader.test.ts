import { generateKeyPair } from "../src/intent/signer.js";
import { createIntent } from "../src/intent/builder.js";
const testKeys = generateKeyPair();
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  OnChainPolicyLoader,
  encodeUint8,
  encodeString,
  encodeBytes32,
  decodeUint256,
  decodeUint8,
  decodeBool,
  decodeString,
  decodeStringArray,
} from '../src/policy/on-chain-loader.js';
import type { OnChainPolicyConfig } from '../src/policy/on-chain-loader.js';

// ---------------------------------------------------------------------------
// Mock RPC helpers
// ---------------------------------------------------------------------------

const MOCK_CONFIG: OnChainPolicyConfig = {
  rpcUrl: 'https://mock-rpc.example.com',
  contractAddress: '0x1234567890abcdef1234567890abcdef12345678',
  chainId: 8453,
  cacheTtlMs: 5000,
};

/**
 * Build a mock JSON-RPC response for eth_call.
 * Returns a Response-like object that fetch would return.
 */
function mockRpcResponse(result: string) {
  return {
    ok: true,
    json: async () => ({ result }),
  } as unknown as Response;
}

function mockRpcError(message: string, code: number) {
  return {
    ok: true,
    json: async () => ({ error: { message, code } }),
  } as unknown as Response;
}

function mockHttpError(status: number, statusText: string) {
  return {
    ok: false,
    status,
    statusText,
    json: async () => ({}),
  } as unknown as Response;
}

/**
 * Encode a uint256 as a 0x-prefixed 64-char hex response.
 */
function encodeUint256Response(value: number): string {
  return '0x' + value.toString(16).padStart(64, '0');
}

/**
 * Encode a string array as an ABI-encoded response.
 * Layout: offset_to_array (0x20) + array_length + offsets... + string_data...
 */
function encodeStringArrayResponse(strings: string[]): string {
  // Outer tuple: one element, offset = 0x20
  let result = (32).toString(16).padStart(64, '0'); // offset to array

  // Array: length + offsets + strings
  const arrayLength = strings.length.toString(16).padStart(64, '0');

  // Calculate offsets: each offset is relative to start of array data (after offsets block)
  // offsets block size = strings.length * 32 bytes
  const offsetsBlockSize = strings.length * 32;
  const stringDatas: string[] = [];
  const offsets: string[] = [];
  let currentDataOffset = offsetsBlockSize;

  for (const s of strings) {
    offsets.push(currentDataOffset.toString(16).padStart(64, '0'));
    const hexBytes = Buffer.from(s, 'utf-8').toString('hex');
    const byteLength = hexBytes.length / 2;
    const lengthWord = byteLength.toString(16).padStart(64, '0');
    const paddedData = hexBytes.padEnd(Math.ceil(hexBytes.length / 64) * 64, '0');
    const stringData = lengthWord + paddedData;
    stringDatas.push(stringData);
    currentDataOffset += stringData.length / 2; // advance by total bytes of this string entry
  }

  result += arrayLength + offsets.join('') + stringDatas.join('');
  return '0x' + result;
}

/**
 * Encode a verifyAction response: (bool approved, uint8 tier, string reason)
 */
function encodeVerifyActionResponse(approved: boolean, tier: number, reason: string): string {
  const boolWord = (approved ? 1 : 0).toString(16).padStart(64, '0');
  const tierWord = tier.toString(16).padStart(64, '0');
  // String offset: 3 * 32 = 96 bytes from start of data
  const stringOffset = (96).toString(16).padStart(64, '0');
  // String data
  const hexBytes = Buffer.from(reason, 'utf-8').toString('hex');
  const byteLength = hexBytes.length / 2;
  const lengthWord = byteLength.toString(16).padStart(64, '0');
  const paddedData = hexBytes.padEnd(Math.ceil(hexBytes.length / 64) * 64, '0');

  return '0x' + boolWord + tierWord + stringOffset + lengthWord + paddedData;
}

// ---------------------------------------------------------------------------
// Tests: ABI Encoding Helpers
// ---------------------------------------------------------------------------

describe('ABI Encoding Helpers', () => {
  it('encodeUint8 produces correct 64-char hex', () => {
    expect(encodeUint8(0)).toBe('0'.repeat(64));
    expect(encodeUint8(1)).toBe('0'.repeat(63) + '1');
    expect(encodeUint8(255)).toBe('0'.repeat(62) + 'ff');
  });

  it('encodeUint8 throws for out-of-range values', () => {
    expect(() => encodeUint8(256)).toThrow('uint8 out of range');
    expect(() => encodeUint8(-1)).toThrow('uint8 out of range');
  });

  it('encodeString produces length + padded data', () => {
    const result = encodeString('hello');
    // length = 5 bytes
    expect(result.slice(0, 64)).toBe((5).toString(16).padStart(64, '0'));
    // data: "hello" = 68656c6c6f, padded to 32 bytes
    expect(result.slice(64)).toContain('68656c6c6f');
    // Total length should be 128 chars (64 length + 64 padded data)
    expect(result.length).toBe(128);
  });

  it('encodeBytes32 handles 0x-prefixed and raw hex', () => {
    const hex32 = 'a'.repeat(64);
    expect(encodeBytes32('0x' + hex32)).toBe(hex32);
    expect(encodeBytes32(hex32)).toBe(hex32);
  });

  it('encodeBytes32 throws for invalid length', () => {
    expect(() => encodeBytes32('0xaabb')).toThrow('bytes32 must be 32 bytes');
  });
});

// ---------------------------------------------------------------------------
// Tests: ABI Decoding Helpers
// ---------------------------------------------------------------------------

describe('ABI Decoding Helpers', () => {
  it('decodeUint256 parses hex to bigint', () => {
    expect(decodeUint256('0x' + '0'.repeat(63) + '1')).toBe(1n);
    expect(decodeUint256('0x' + '0'.repeat(62) + 'ff')).toBe(255n);
    expect(decodeUint256('0x' + '0'.repeat(56) + 'ffffffff')).toBe(4294967295n);
  });

  it('decodeUint8 parses hex to number', () => {
    expect(decodeUint8('0'.repeat(63) + '0')).toBe(0);
    expect(decodeUint8('0'.repeat(63) + '2')).toBe(2);
    expect(decodeUint8('0'.repeat(62) + 'ff')).toBe(255);
  });

  it('decodeBool parses hex to boolean', () => {
    expect(decodeBool('0'.repeat(64))).toBe(false);
    expect(decodeBool('0'.repeat(63) + '1')).toBe(true);
  });

  it('decodeString parses ABI-encoded string', () => {
    // Encode "hello" and decode it
    const encoded = encodeString('hello');
    // decodeString expects the full hex and a byte offset
    const result = decodeString(encoded, 0);
    expect(result).toBe('hello');
  });

  it('decodeStringArray parses ABI-encoded string[]', () => {
    // Build a string array: ["think", "recall"]
    const response = encodeStringArrayResponse(['think', 'recall']);
    // The array starts at offset 0x20 (32 bytes)
    const cleaned = response.startsWith('0x') ? response.slice(2) : response;
    const offset = parseInt(cleaned.slice(0, 64), 16);
    const result = decodeStringArray(response, offset);
    expect(result).toEqual(['think', 'recall']);
  });

  it('decodeStringArray handles empty array', () => {
    const response = encodeStringArrayResponse([]);
    const cleaned = response.startsWith('0x') ? response.slice(2) : response;
    const offset = parseInt(cleaned.slice(0, 64), 16);
    const result = decodeStringArray(response, offset);
    expect(result).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Tests: OnChainPolicyLoader
// ---------------------------------------------------------------------------

describe('OnChainPolicyLoader', () => {
  let loader: OnChainPolicyLoader;
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    loader = new OnChainPolicyLoader(MOCK_CONFIG);
    fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('getPolicyVersion returns correct version number', async () => {
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeUint256Response(42)));

    const version = await loader.getPolicyVersion();
    expect(version).toBe(42);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('loadPolicy reconstructs PolicyConfig from getTierActions calls', async () => {
    // First call: policyVersion -> 1
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeUint256Response(1)));
    // Calls 2-5: getTierActions(0), getTierActions(1), getTierActions(2), getTierActions(3)
    fetchSpy.mockResolvedValueOnce(
      mockRpcResponse(encodeStringArrayResponse(['think', 'recall', 'summarize'])),
    );
    fetchSpy.mockResolvedValueOnce(
      mockRpcResponse(encodeStringArrayResponse(['send_message', 'reply_email'])),
    );
    fetchSpy.mockResolvedValueOnce(
      mockRpcResponse(encodeStringArrayResponse(['send_email_new', 'file_write'])),
    );
    fetchSpy.mockResolvedValueOnce(
      mockRpcResponse(encodeStringArrayResponse(['transfer_funds', 'change_permissions'])),
    );

    const policy = await loader.loadPolicy();

    expect(policy.version).toBe('1');
    expect(policy.tiers.tier_0.actions).toEqual(['think', 'recall', 'summarize']);
    expect(policy.tiers.tier_1.actions).toEqual(['send_message', 'reply_email']);
    expect(policy.tiers.tier_2.actions).toEqual(['send_email_new', 'file_write']);
    expect(policy.tiers.tier_3.actions).toEqual(['transfer_funds', 'change_permissions']);
    expect(policy.tiers.tier_3.verification).toBe('human_approval');
    expect(fetchSpy).toHaveBeenCalledTimes(5);
  });

  it('cache prevents duplicate RPC calls on second loadPolicy', async () => {
    // First load
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeUint256Response(1)));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse([])));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse([])));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse([])));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse([])));

    const policy1 = await loader.loadPolicy();
    const callCountAfterFirst = fetchSpy.mock.calls.length;

    // Second load (cached)
    const policy2 = await loader.loadPolicy();

    expect(policy1).toEqual(policy2);
    expect(fetchSpy).toHaveBeenCalledTimes(callCountAfterFirst); // No new calls
  });

  it('clearCache forces fresh fetch on next loadPolicy', async () => {
    // First load
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeUint256Response(1)));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse(['think'])));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse([])));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse([])));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse([])));

    await loader.loadPolicy();
    expect(fetchSpy).toHaveBeenCalledTimes(5);

    // Clear cache
    loader.clearCache();

    // Second load — should make fresh requests
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeUint256Response(2)));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse(['think', 'recall'])));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse([])));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse([])));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringArrayResponse([])));

    const policy2 = await loader.loadPolicy();

    expect(policy2.version).toBe('2');
    expect(policy2.tiers.tier_0.actions).toEqual(['think', 'recall']);
    expect(fetchSpy).toHaveBeenCalledTimes(10);
  });

  it('verifyOnChain returns approved for authorized actions', async () => {
    fetchSpy.mockResolvedValueOnce(
      mockRpcResponse(encodeVerifyActionResponse(true, 1, 'Action approved')),
    );

    const result = await loader.verifyOnChain(
      'did:chitin:8453:0x1234:42',
      'send_message',
      '0x' + 'a'.repeat(64),
    );

    expect(result.approved).toBe(true);
    expect(result.tier).toBe(1);
    expect(result.reason).toBe('Action approved');
  });

  it('verifyOnChain returns rejected for tier 3 actions', async () => {
    fetchSpy.mockResolvedValueOnce(
      mockRpcResponse(
        encodeVerifyActionResponse(false, 3, 'Requires human approval'),
      ),
    );

    const result = await loader.verifyOnChain(
      'did:chitin:8453:0x1234:42',
      'transfer_funds',
      '0x' + 'b'.repeat(64),
    );

    expect(result.approved).toBe(false);
    expect(result.tier).toBe(3);
    expect(result.reason).toBe('Requires human approval');
  });

  it('handles RPC error responses', async () => {
    fetchSpy.mockResolvedValueOnce(mockRpcError('execution reverted', -32000));

    await expect(loader.getPolicyVersion()).rejects.toThrow('RPC error: execution reverted');
  });

  it('handles HTTP errors', async () => {
    fetchSpy.mockResolvedValueOnce(mockHttpError(500, 'Internal Server Error'));

    await expect(loader.getPolicyVersion()).rejects.toThrow(
      'RPC request failed: 500 Internal Server Error',
    );
  });

  it('handles missing result in RPC response', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    } as unknown as Response);

    await expect(loader.getPolicyVersion()).rejects.toThrow('RPC response missing result');
  });

  it('sends correct calldata format in eth_call', async () => {
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeUint256Response(1)));

    await loader.getPolicyVersion();

    const callBody = JSON.parse(fetchSpy.mock.calls[0][1].body as string);
    expect(callBody.method).toBe('eth_call');
    expect(callBody.params[0].to).toBe(MOCK_CONFIG.contractAddress);
    // policyVersion() selector = 0x58355ead
    expect(callBody.params[0].data).toBe('0x58355ead');
    expect(callBody.params[1]).toBe('latest');
  });
});

// ---------------------------------------------------------------------------
// Tests: PolicyEngine.verifyOnChain integration
// ---------------------------------------------------------------------------

describe('PolicyEngine.verifyOnChain', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('throws when onChainLoader is not configured', async () => {
    const { PolicyEngine } = await import('../src/policy/engine.js');
    const { loadDefaultPolicy } = await import('../src/policy/loader.js');
    const engine = new PolicyEngine(loadDefaultPolicy());

    const intent = {
      version: '1.0' as const,
      intent_id: 'test-1',
      agent_did: 'did:key:test',
      timestamp: new Date().toISOString(),
      action: { type: 'file_write', params: {} },
      context: { triggered_by: 'user_message' as const, session_id: 'test' },
      nonce: Date.now(),
      signature: 'aa'.repeat(32),
    };

    await expect(engine.verifyOnChain(intent)).rejects.toThrow(
      'On-chain policy loader not configured',
    );
  });

  it('uses local verification for tier 0-1 actions even with onChainLoader', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    const { PolicyEngine } = await import('../src/policy/engine.js');
    const { loadDefaultPolicy } = await import('../src/policy/loader.js');
    const { OnChainPolicyLoader } = await import('../src/policy/on-chain-loader.js');

    const onChainLoader = new OnChainPolicyLoader(MOCK_CONFIG);
    const engine = new PolicyEngine(loadDefaultPolicy(), undefined, onChainLoader, { trustedDids: [testKeys.did] });

    const intent = createIntent({ action: "think", params: {} }, testKeys);

    const result = await engine.verifyOnChain(intent);

    expect(result.approved).toBe(true);
    expect(result.tier).toBe(0);
    // No fetch calls should have been made (local verification for tier 0)
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
