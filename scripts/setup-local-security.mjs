import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const directory = resolve('.local');
mkdirSync(directory, { recursive: true });
const keyFile = resolve(directory, 'agent-key.json');
const envFile = resolve(directory, 'security.env');
if (existsSync(keyFile) || existsSync(envFile)) throw new Error('Local security configuration exists; refusing to overwrite it');
const keys = generateKeyPairSync('ed25519');
const publicKey = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const privateKey = keys.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32);
const did = `did:key:${publicKey.toString('base64url')}`;
writeFileSync(keyFile, JSON.stringify({ did, publicKey: publicKey.toString('hex'), privateKey: privateKey.toString('hex') }), { flag: 'wx', mode: 0o600 });
writeFileSync(envFile, `TRUSTED_AGENT_DIDS=${did}\nSHELL_APPROVAL_SECRET=${randomBytes(48).toString('base64url')}\n`, { flag: 'wx', mode: 0o600 });
console.log(`Created local configuration for ${did}. Secret values are not displayed.`);
