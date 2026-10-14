import { readFileSync } from "node:fs";
/**
 * Chitin Shell — Agent Container Server
 *
 * This is the LLM sandbox. It has:
 * - NO API keys
 * - NO internet access (except to policy engine)
 * - NO access to vault or proxy
 *
 * The agent can only create Intents and forward them to the policy engine.
 * The policy engine decides whether to approve and execute them.
 */

import {
  createJsonServer,
  fetchJson,
  healthHandler,
  type JsonRoute,
  type RouteResponse,
} from './shared/http-utils.js';
import {
  createIntent,
  verifySignature,
  type AgentKeyPair,
  validateIntentStructure,
  type CreateIntentParams,
  type IntentV1,
} from '@chitin-id/shell-core';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const AGENT_PORT = parseInt(process.env.AGENT_PORT ?? '3000', 10);
const POLICY_URL = process.env.POLICY_URL ?? 'http://chitin-policy:3100';

// ---------------------------------------------------------------------------
// Agent State
// ---------------------------------------------------------------------------

const keyFile = process.env.AGENT_KEY_FILE;
if (!keyFile) throw new Error("AGENT_KEY_FILE is required");
const keyData = JSON.parse(readFileSync(keyFile, "utf8"));
const keyPair: AgentKeyPair = { publicKey: Buffer.from(keyData.publicKey, "hex"), privateKey: Buffer.from(keyData.privateKey, "hex"), did: keyData.did };
if (keyPair.publicKey.length !== 32 || keyPair.privateKey.length !== 32 || keyPair.did !== `did:key:${Buffer.from(keyPair.publicKey).toString("base64url")}`
  || !verifySignature(createIntent({ action: "think", params: {} }, keyPair), keyPair.publicKey)) throw new Error("Invalid agent signing key");
const startedAt = new Date().toISOString();

console.log(`[agent] Agent DID: ${keyPair.did}`);
console.log(`[agent] Policy engine URL: ${POLICY_URL}`);

// Verify no secrets leaked into this container
const FORBIDDEN_ENV_PREFIXES = ['PROXY_', 'OPENAI', 'ANTHROPIC', 'SLACK_TOKEN', 'VAULT_'];
for (const [key] of Object.entries(process.env)) {
  for (const prefix of FORBIDDEN_ENV_PREFIXES) {
    if (key.startsWith(prefix)) {
      console.error(`[agent] SECURITY VIOLATION: Found forbidden env var '${key}' in agent container. Exiting.`);
      process.exit(1);
    }
  }
}

// ---------------------------------------------------------------------------
// Route: POST /intent
// ---------------------------------------------------------------------------

async function handleIntent(body: unknown): Promise<RouteResponse> {
  if (!body || typeof body !== 'object') {
    return { status: 400, body: { error: 'Request body must be a JSON object' } };
  }

  const { action, params, context } = body as Record<string, unknown>;

  if (typeof action !== 'string' || !action) {
    return { status: 400, body: { error: 'Missing required field: action (string)' } };
  }

  if (params !== undefined && (typeof params !== 'object' || params === null || Array.isArray(params))) {
    return { status: 400, body: { error: 'Field params must be an object' } };
  }

  // Build the Intent
  const intentParams: CreateIntentParams = {
    action,
    params: (params as Record<string, unknown>) ?? {},
    context: context as CreateIntentParams['context'],
  };

  const intent: IntentV1 = createIntent(intentParams, keyPair);

  // Validate our own output (defense in depth)
  const validation = validateIntentStructure(intent);
  if (!validation.valid) {
    return {
      status: 500,
      body: { error: 'Internal: generated invalid Intent', details: validation.errors },
    };
  }

  // Forward to policy engine for verification + execution
  try {
    const policyResult = await fetchJson<{
      verification: { approved: boolean; tier: number; reason: string; requires_human?: boolean };
      execution?: { status: string; data?: unknown; error?: string };
    }>(`${POLICY_URL}/verify`, { intent });

    return {
      status: policyResult.status,
      body: {
        intent_id: intent.intent_id,
        agent_did: intent.agent_did,
        action: intent.action.type,
        ...policyResult.data,
      },
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      status: 502,
      body: {
        error: 'Failed to reach policy engine',
        message,
        intent_id: intent.intent_id,
      },
    };
  }
}

// ---------------------------------------------------------------------------
// Route: GET /agent-info
// ---------------------------------------------------------------------------

async function handleAgentInfo(): Promise<RouteResponse> {
  return {
    status: 200,
    body: {
      agent_did: keyPair.did,
      policy_url: POLICY_URL,
      capabilities: ['create_intent', 'forward_to_policy'],
      restrictions: [
        'no_api_keys',
        'no_internet_access',
        'no_vault_access',
        'no_proxy_access',
      ],
    },
  };
}

// ---------------------------------------------------------------------------
// Start Server
// ---------------------------------------------------------------------------

const routes: JsonRoute[] = [
  healthHandler('chitin-agent', startedAt),
  {
    method: 'POST',
    path: '/intent',
    handler: async (body) => handleIntent(body),
  },
  {
    method: 'GET',
    path: '/agent-info',
    handler: async () => handleAgentInfo(),
  },
];

createJsonServer(AGENT_PORT, routes, 'chitin-agent');
