import crypto from 'node:crypto';
import type { AgentKeyPair, IntentV1, UnsignedIntent } from './types.js';

export function generateKeyPair(): AgentKeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  const rawPublic = extractRawPublicKey(publicKey);
  const rawPrivate = extractRawPrivateKey(privateKey);

  const did = 'did:key:' + base64url(rawPublic);

  return { publicKey: rawPublic, privateKey: rawPrivate, did };
}

export function signIntent(unsignedIntent: UnsignedIntent, privateKey: Uint8Array): string {
  const payload = canonicalize(unsignedIntent);
  const key = crypto.createPrivateKey({
    key: wrapRawPrivateKey(privateKey),
    format: 'der',
    type: 'pkcs8',
  });
  const sig = crypto.sign(null, Buffer.from(payload), key);
  return sig.toString('hex');
}

export function verifySignature(intent: IntentV1, publicKey: Uint8Array): boolean {
  const { signature, ...unsigned } = intent;
  const payload = canonicalize(unsigned);
  const sigBuffer = Buffer.from(signature, 'hex');
  const key = crypto.createPublicKey({
    key: wrapRawPublicKey(publicKey),
    format: 'der',
    type: 'spki',
  });
  return crypto.verify(null, Buffer.from(payload), key, sigBuffer);
}

export function canonicalize(obj: unknown): string {
  return JSON.stringify(sortKeys(obj));
}

function sortKeys(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    sorted[key] = sortKeys((value as Record<string, unknown>)[key]);
  }
  return sorted;
}

function base64url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString('base64url');
}

// Ed25519 SPKI DER prefix (12 bytes) before the 32-byte raw public key
const SPKI_ED25519_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

// Ed25519 PKCS8 DER prefix (16 bytes) before the 32-byte raw private key
const PKCS8_ED25519_PREFIX = Buffer.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

function extractRawPublicKey(spkiDer: Buffer): Uint8Array {
  return new Uint8Array(spkiDer.subarray(SPKI_ED25519_PREFIX.length));
}

function extractRawPrivateKey(pkcs8Der: Buffer): Uint8Array {
  return new Uint8Array(pkcs8Der.subarray(PKCS8_ED25519_PREFIX.length));
}

function wrapRawPublicKey(raw: Uint8Array): Buffer {
  return Buffer.concat([SPKI_ED25519_PREFIX, raw]);
}

function wrapRawPrivateKey(raw: Uint8Array): Buffer {
  return Buffer.concat([PKCS8_ED25519_PREFIX, raw]);
}
