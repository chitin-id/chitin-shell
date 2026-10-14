/**
 * Chitin Shell — Policy Engine Container Server
 *
 * The verification layer. This container:
 * - Receives Intents from the agent container
 * - Validates structure and signature
 * - Verifies against policy rules (tier, rate limits, blacklists)
 * - Forwards approved Intents to the proxy for execution
 *
 * It sits on BOTH networks:
 * - chitin-isolated (can talk to agent)
 * - chitin-proxy (can talk to proxy)
 */

import {
  createJsonServer,
  fetchJson,
  healthHandler,
  type JsonRoute,
  type RouteResponse,
} from './shared/http-utils.js';
import {
  PolicyEngine,
  ApprovalAuthority,
  loadPolicyFromFile,
  loadDefaultPolicy,
  validateIntentStructure,
  type IntentV1,
  type PolicyConfig,
  type VerificationResult,
} from '@chitin-id/shell-core';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const POLICY_PORT = parseInt(process.env.POLICY_PORT ?? '3100', 10);
const PROXY_URL = process.env.PROXY_URL ?? 'http://chitin-proxy:3200';
const POLICY_CONFIG_PATH = process.env.POLICY_CONFIG_PATH;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const approvalSecret = process.env.SHELL_APPROVAL_SECRET;
if (!approvalSecret) throw new Error("SHELL_APPROVAL_SECRET is required");
const approvalAuthority = new ApprovalAuthority(approvalSecret);
let policyEngine: PolicyEngine;
const startedAt = new Date().toISOString();

// Approval tokens: short-lived map of token -> intent_id (prevents replay)
const approvalTokens = new Map<string, { intent_id: string; intent_hash: string; expires: number }>();
const APPROVAL_TTL_MS = 30_000; // 30 seconds

// Cleanup expired tokens every minute
setInterval(() => {
  const now = Date.now();
  for (const [token, entry] of approvalTokens) {
    if (entry.expires < now) {
      approvalTokens.delete(token);
    }
  }
}, 60_000);

// ---------------------------------------------------------------------------
// Initialize policy engine
// ---------------------------------------------------------------------------

async function initPolicy(): Promise<void> {
  let config: PolicyConfig;

  if (POLICY_CONFIG_PATH) {
    console.log(`[policy] Loading policy from: ${POLICY_CONFIG_PATH}`);
    config = await loadPolicyFromFile(POLICY_CONFIG_PATH);
  } else {
    console.log('[policy] No POLICY_CONFIG_PATH set, using default policy');
    config = loadDefaultPolicy();
  }

  const trustedDids = (process.env.TRUSTED_AGENT_DIDS || "").split(",").filter(Boolean);
  if (!trustedDids.length) throw new Error("TRUSTED_AGENT_DIDS is required");
  policyEngine = new PolicyEngine(config, undefined, undefined, { trustedDids, approvalAuthority });
  console.log(`[policy] Policy engine initialized (version: ${config.version})`);
}

// ---------------------------------------------------------------------------
// Route: POST /verify
// ---------------------------------------------------------------------------

async function handleVerify(body: unknown): Promise<RouteResponse> {
  if (!body || typeof body !== 'object') {
    return { status: 400, body: { error: 'Request body must be a JSON object' } };
  }

  const { intent } = body as { intent?: unknown };

  if (!intent) {
    return { status: 400, body: { error: 'Missing required field: intent' } };
  }

  // Structural validation
  const structCheck = validateIntentStructure(intent);
  if (!structCheck.valid) {
    return {
      status: 400,
      body: {
        error: 'Invalid Intent structure',
        details: structCheck.errors,
        verification: { approved: false, tier: -1, reason: 'Structural validation failed' },
      },
    };
  }

  const intentV1 = intent as IntentV1;

  // Policy verification
  const verification = policyEngine.verify(intentV1);

  // If not approved or requires human approval, return immediately
  if (!verification.approved || verification.requires_human) {
    return {
      status: 200,
      body: { verification },
    };
  }

  // Generate a short-lived approval token for the proxy
  const proxyToken = verification.approval_token!;
  approvalTokens.set(proxyToken, {
    intent_id: intentV1.intent_id,
    intent_hash: PolicyEngine.computeIntentHash(intentV1),
    expires: Date.now() + APPROVAL_TTL_MS,
  });

  // Forward to proxy for execution
  try {
    const proxyResult = await fetchJson<{
      status: string;
      data?: unknown;
      error?: string;
      sanitized?: boolean;
      execution_time_ms?: number;
    }>(`${PROXY_URL}/execute`, {
      intent: intentV1,
      approval_token: proxyToken,
      verification: {
        approved: verification.approved,
        tier: verification.tier,
        reason: verification.reason,
      },
    });

    // Consume the token (one-time use)
    approvalTokens.delete(proxyToken);

    return {
      status: 200,
      body: {
        verification,
        execution: proxyResult.data,
      },
    };
  } catch (err) {
    // Clean up the token on failure
    approvalTokens.delete(proxyToken);

    const message = err instanceof Error ? err.message : String(err);
    return {
      status: 502,
      body: {
        verification,
        execution: {
          status: 'error',
          error: `Failed to reach proxy: ${message}`,
          sanitized: false,
          execution_time_ms: 0,
        },
      },
    };
  }
}

// ---------------------------------------------------------------------------
// Route: POST /execute (direct execution request with pre-verified token)
// ---------------------------------------------------------------------------

async function handleExecute(body: unknown): Promise<RouteResponse> {
  if (!body || typeof body !== 'object') {
    return { status: 400, body: { error: 'Request body must be a JSON object' } };
  }

  const { intent, approval_token } = body as {
    intent?: unknown;
    approval_token?: string;
  };

  if (!intent || !approval_token) {
    return {
      status: 400,
      body: { error: 'Missing required fields: intent, approval_token' },
    };
  }

  // Validate the approval token
  const tokenEntry = approvalTokens.get(approval_token);
  if (!tokenEntry) {
    return {
      status: 403,
      body: { error: 'Invalid or expired approval token' },
    };
  }

  const intentV1 = intent as IntentV1;
  if (tokenEntry.intent_id !== intentV1.intent_id || tokenEntry.intent_hash !== PolicyEngine.computeIntentHash(intentV1)) {
    return {
      status: 403,
      body: { error: 'Approval token does not match intent_id' },
    };
  }

  if (tokenEntry.expires < Date.now()) {
    approvalTokens.delete(approval_token);
    return {
      status: 403,
      body: { error: 'Approval token has expired' },
    };
  }

  // Consume the token
  approvalTokens.delete(approval_token);

  // Forward to proxy
  try {
    const proxyResult = await fetchJson(`${PROXY_URL}/execute`, {
      intent: intentV1,
      approval_token,
      verification: { approved: true, tier: 0, reason: 'Pre-verified' },
    });

    return { status: 200, body: proxyResult.data };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      status: 502,
      body: { error: `Failed to reach proxy: ${message}` },
    };
  }
}

// ---------------------------------------------------------------------------
// Route: GET /policy
// ---------------------------------------------------------------------------

async function handleGetPolicy(): Promise<RouteResponse> {
  return {
    status: 200,
    body: {
      policy: policyEngine.getPolicy(),
    },
  };
}

// ---------------------------------------------------------------------------
// Start Server
// ---------------------------------------------------------------------------

const routes: JsonRoute[] = [
  healthHandler('chitin-policy', startedAt),
  {
    method: 'POST',
    path: '/verify',
    handler: async (body) => handleVerify(body),
  },
  {
    method: 'POST',
    path: '/execute',
    handler: async (body) => handleExecute(body),
  },
  {
    method: 'GET',
    path: '/policy',
    handler: async () => handleGetPolicy(),
  },
];

initPolicy()
  .then(() => {
    createJsonServer(POLICY_PORT, routes, 'chitin-policy');
  })
  .catch((err) => {
    console.error('[policy] Failed to initialize:', err);
    process.exit(1);
  });
