import { safeFetch } from "../safe-fetch.js";
import type { ActionMapper, IVault } from '../types.js';

/**
 * Blocked hostname patterns to prevent SSRF attacks against internal services.
 * Covers: localhost, private RFC 1918, link-local (cloud metadata), loopback.
 */
const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\.\d+\.\d+\.\d+$/,              // IPv4 loopback
  /^\[::1\]$/,                           // IPv6 loopback
  /^10\.\d+\.\d+\.\d+$/,               // RFC 1918: 10.0.0.0/8
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/, // RFC 1918: 172.16.0.0/12
  /^192\.168\.\d+\.\d+$/,              // RFC 1918: 192.168.0.0/16
  /^169\.254\.\d+\.\d+$/,              // Link-local (AWS/GCP metadata)
  /^0\.0\.0\.0$/,                       // Unspecified
  /^\[fd[0-9a-f]{2}:/i,                // IPv6 ULA
  /^\[fe80:/i,                          // IPv6 link-local
];

function isBlockedUrl(urlString: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return true; // Malformed URLs are blocked
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return true; // Only HTTP(S) allowed
  }

  const hostname = parsed.hostname;
  return BLOCKED_HOST_PATTERNS.some((p) => p.test(hostname));
}

export class GenericHttpMapper implements ActionMapper {
  readonly action_type = 'api_call';

  async execute(params: Record<string, unknown>, vault: IVault): Promise<unknown> {
    const url = params.url as string;

    if (!url || isBlockedUrl(url)) {
      throw new Error('Request blocked: URL targets a restricted address');
    }

    const method = (params.method as string) ?? 'GET';
    const headers: Record<string, string> = { ...(params.headers as Record<string, string> ?? {}) };
    const body = params.body;
    const credential_key = params.credential_key as string | undefined;

    if (credential_key) {
      const entry = await vault.get(credential_key);
      const destination = new URL(url);
      if (!entry || destination.protocol !== 'https:' || !entry.allowed_origins?.includes(destination.origin)) {
        throw new Error('Credential is not authorized for this destination');
      }
      if (entry.expires_at && Date.parse(entry.expires_at) <= Date.now()) throw new Error('Credential has expired');
      if (entry) {
        switch (entry.type) {
          case 'bearer':
            headers['Authorization'] = `Bearer ${entry.value}`;
            break;
          case 'basic':
            headers['Authorization'] = `Basic ${entry.value}`;
            break;
          case 'api_key':
            headers['X-API-Key'] = entry.value;
            break;
        }
      }
    }

    const response = await safeFetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    });

    const contentType = response.headers.get('content-type') ?? '';
    const responseBody = contentType.includes('application/json')
      ? await response.json()
      : await response.text();

    return {
      status: response.status,
      headers: Object.fromEntries(response.headers as unknown as Iterable<[string, string]>),
      body: responseBody,
    };
  }
}
