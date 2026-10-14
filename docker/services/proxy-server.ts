/**
 * Chitin Shell — Secure Proxy Container Server
 *
 * The execute layer. This container:
 * - Holds ALL API keys and credentials (vault)
 * - Executes verified Intents against real APIs
 * - Sanitizes all output before returning to the policy engine
 * - Has external network access
 *
 * ONLY the policy engine can reach this container.
 * The agent container CANNOT reach this container directly.
 */

import {
  createJsonServer,
  healthHandler,
  type JsonRoute,
  type RouteResponse,
} from './shared/http-utils.js';
import {
  MemoryVault,
  ApprovalAuthority,
  Sanitizer,
  Executor,
  GenericHttpMapper,
  validateIntentStructure,
  type IntentV1,
  type VerificationResult,
} from '@chitin-id/shell-core';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const PROXY_PORT = parseInt(process.env.PROXY_PORT ?? '3200', 10);

// ---------------------------------------------------------------------------
// Initialize Vault with credentials from environment
// ---------------------------------------------------------------------------

const vault = new MemoryVault();
const sanitizer = new Sanitizer();
const approvalSecret = process.env.SHELL_APPROVAL_SECRET;
if (!approvalSecret) throw new Error("SHELL_APPROVAL_SECRET is required");
const executor = new Executor(vault, sanitizer, undefined, new ApprovalAuthority(approvalSecret));
const startedAt = new Date().toISOString();

// Register built-in mappers
executor.registerMapper(new GenericHttpMapper());

/**
 * Load credentials from environment variables.
 * Convention: PROXY_<SERVICE>_KEY or PROXY_<SERVICE>_TOKEN
 * becomes vault key "<service>" with type "api_key" or "bearer".
 */
async function loadVaultFromEnv(): Promise<void> {
  const PROXY_PREFIX = 'PROXY_';
  let count = 0;

  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith(PROXY_PREFIX) || !value || !/(?:_KEY|_TOKEN)$/.test(key)) continue;

    // PROXY_OPENAI_KEY -> openai
    // PROXY_ANTHROPIC_KEY -> anthropic
    // PROXY_SLACK_TOKEN -> slack
    const rest = key.slice(PROXY_PREFIX.length).toLowerCase();
    const parts = rest.split('_');
    const suffix = parts[parts.length - 1];
    const serviceName = parts.slice(0, -1).join('_');

    const entryType = suffix === 'token' ? 'bearer' as const : 'api_key' as const;

    await vault.set(serviceName, {
      type: entryType,
      value,
      allowed_origins: (process.env[`PROXY_${serviceName.toUpperCase()}_ORIGINS`] || "").split(",").filter(Boolean),
      metadata: { source: 'environment', env_var: key },
    });

    count++;
    console.log(`[proxy] Loaded credential: ${serviceName} (${entryType}) from ${key}`);
  }

  console.log(`[proxy] Vault initialized with ${count} credential(s)`);
}

// ---------------------------------------------------------------------------
// Route: POST /execute
// ---------------------------------------------------------------------------

async function handleExecute(body: unknown): Promise<RouteResponse> {
  if (!body || typeof body !== 'object') {
    return { status: 400, body: { error: 'Request body must be a JSON object' } };
  }

  const { intent, approval_token, verification } = body as {
    intent?: unknown;
    approval_token?: string;
    verification?: VerificationResult;
  };

  // Validate required fields
  if (!intent) {
    return { status: 400, body: { error: 'Missing required field: intent' } };
  }

  if (!approval_token) {
    return { status: 400, body: { error: 'Missing required field: approval_token' } };
  }

  if (!verification?.approved) {
    return {
      status: 403,
      body: { error: 'Intent was not approved by policy engine' },
    };
  }

  // Validate intent structure
  const structCheck = validateIntentStructure(intent);
  if (!structCheck.valid) {
    return {
      status: 400,
      body: { error: 'Invalid Intent structure', details: structCheck.errors },
    };
  }

  const intentV1 = intent as IntentV1;

  // Execute the action
  console.log(
    `[proxy] Executing: ${intentV1.action.type} (intent: ${intentV1.intent_id}, tier: ${verification.tier})`,
  );

  const result = await executor.execute(intentV1, approval_token);

  console.log(
    `[proxy] Result: ${result.status} (${result.execution_time_ms}ms, sanitized: ${result.sanitized})`,
  );

  return {
    status: result.status === 'success' ? 200 : 500,
    body: result,
  };
}

// ---------------------------------------------------------------------------
// Route: GET /vault-keys (for debugging — list key names only, never values)
// ---------------------------------------------------------------------------

async function handleVaultKeys(): Promise<RouteResponse> {
  const keys = await vault.list();
  return {
    status: 200,
    body: {
      count: keys.length,
      keys,
      note: 'Values are never exposed through this endpoint',
    },
  };
}

// ---------------------------------------------------------------------------
// Start Server
// ---------------------------------------------------------------------------

const routes: JsonRoute[] = [
  healthHandler('chitin-proxy', startedAt),
  {
    method: 'POST',
    path: '/execute',
    handler: async (body) => handleExecute(body),
  },
  {
    method: 'GET',
    path: '/vault-keys',
    handler: async () => handleVaultKeys(),
  },
];

loadVaultFromEnv()
  .then(() => {
    createJsonServer(PROXY_PORT, routes, 'chitin-proxy');
  })
  .catch((err) => {
    console.error('[proxy] Failed to initialize:', err);
    process.exit(1);
  });
