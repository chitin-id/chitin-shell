# Intent and credential authorization

The policy engine accepts only signed intents from host-configured identities. Local Shell instances trust the key they create; direct `PolicyEngine` callers must provide `trustedDids` or `trustedKeys` in the fourth constructor argument. An agent cannot add its own identity to this configuration. Ed25519 signatures bind nested action parameters. Intents expire after five minutes and cannot reuse a nonce.

Approval tokens authenticate the entire intent, expire after 30 seconds and are consumed once by the executor. Docker policy and proxy must share a random `SHELL_APPROVAL_SECRET` of at least 32 bytes. The agent must not receive this secret. The `verification.approved` request field is not sufficient to authorize execution.

Credentials require an explicit `allowed_origins` list. HTTP destinations, missing destination permissions and expired credentials are rejected. Redirects are disabled for credential requests. DNS results are checked and the socket connects to the validated address without resolving again.

Docker deployments require a persistent agent signing key file and a matching `TRUSTED_AGENT_DIDS` entry. Run `node scripts/setup-local-security.mjs` from the Shell root to create local development configuration, then start Compose with `docker compose --env-file .local/security.env -f docker/docker-compose.yml up --build`. The setup script never replaces existing keys. It creates no external resources and submits no transactions.

Local verification fails closed for actions whose policy requires on-chain verification. Use `executeOnChain` with an appropriate configured policy loader, or explicitly configure a local policy for actions that do not require a chain decision.
