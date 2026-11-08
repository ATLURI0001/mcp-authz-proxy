# Deployment and operations

## Local Compose

Requires Docker Engine/Desktop with Compose v2 and Python 3.10+. No host Go
installation is required. Docker Desktop should use Linux containers on Windows.

```bash
python3 scripts/setup-demo.py
docker compose up --build -d
python3 scripts/smoke.py
```

The setup script creates random infrastructure/downstream secrets in `.env` and
never overwrites it. Demo user passwords in the Keycloak realm are intentionally
public fixture credentials. Ports bind to 127.0.0.1. PostgreSQL, Redis and the demo
backend have no host-published ports. Images are version-tagged; audit and pin
approved digests before an external deployment.

- Gateway: http://localhost:8080/mcp
- Keycloak: http://localhost:8082 (admin password in `.env`)
- Grafana: http://localhost:3000 (admin password in `.env`)
- Prometheus: http://localhost:9091

`/healthz` is process liveness. `/readyz` checks PostgreSQL and Redis, not the issuer
or upstream. An unhealthy issuer/upstream will therefore still produce request-time
errors. View gateway audit events with `docker compose logs gateway` and durable
records with:

```bash
docker compose exec postgres psql -U mcp -d mcp -c "SELECT created_at,event FROM audit_events ORDER BY sequence DESC LIMIT 20"
```

Stop with `docker compose down`. Data survives in `postgres-data`. Only use
`docker compose down -v` when you deliberately want to erase the demo database.
Schema initialization runs on the first empty volume; apply later schema changes
explicitly. Keycloak development storage is ephemeral, so imported demo identities
are reset when its container is recreated.

## Operator CLI

Run the CLI inside the gateway container so it receives DATABASE_URL. For example:

```bash
docker compose exec gateway admin grant -subject 22222222-2222-4222-8222-222222222222 -tool echo
docker compose exec gateway admin list -subject 22222222-2222-4222-8222-222222222222
docker compose exec gateway admin revoke -subject 22222222-2222-4222-8222-222222222222 -tool echo
docker compose exec gateway admin approve -subject 11111111-1111-4111-8111-111111111111 -tool restart_demo -params /app/configs/restart-params.json
```

The last command prints a one-use approval token. Add it to the matching tool call
as `X-Approval-Token`. It expires in five minutes and is not a substitute for the
user's bearer token, scopes or grant. For other requests, provide a reviewed params
file through a trusted read-only mount. Never expose this CLI as a public endpoint.
In production, run it separately with an operator-specific database role.

## Kubernetes template

`deploy/kubernetes/gateway.yaml` is a starting template, **not** an all-in-one cluster
or an already-published image. Supply external PostgreSQL/Redis, a real issuer and
an HTTPS stateless backend. Build/push the image to your own registry first, then
set the Deployment image to that immutable digest.

1. Create namespace `mcp-authz`.
2. Create `gateway-config` ConfigMap with key `gateway.json`, adapted from the demo:
   set `allow_http` false; replace resource/issuer/JWKS/upstream/origins; use real
   immutable user subjects and credential environment-variable names.
3. Create `gateway-secrets` with DATABASE_URL, REDIS_URL and each credential variable
   through your secret manager. Require database TLS (`sslmode=verify-full`), Redis
   TLS (`rediss://`) and trust the appropriate CA. Do not commit secrets.
4. Apply the schema with a migration owner and create least-privilege runtime and
   operator database roles. Remove the fixture grants before deployment.
5. Apply the deployment template and configure an HTTPS ingress for port 8080.
   Adapt NetworkPolicy namespace selectors to your ingress/monitoring installation.
6. Add destination-specific egress policies, ingress limits and network isolation
   for database, Redis and the backend. Keep port 9090 private.
7. Disable Keycloak direct access/password grants and development mode. Use proper
   client registration, exact redirect URIs, Code + PKCE and short-lived tokens.
8. Configure backup, audit retention, secret rotation and alerting. Test credential
   isolation with the actual upstream service before granting real tool authority.

The sample contains no public Ingress, DNS, TLS certificates or external databases.
It must be adapted and tested in your cluster; this package does not claim a tested
Kubernetes deployment.

## Failure behavior

- 401: check issuer, audience (must equal resource URL), expiry and JWKS key ID.
- 403: check mcp:connect/tool scopes, exact subject grants, credential mapping and
  approval token. Tokens may contain broad scopes while database grants remain narrow.
- 429: wait for the next minute; Retry-After is conservatively 60 seconds.
- 502: verify the backend implements the documented JSON/stateless contract and
  returns matching JSON-RPC IDs. SSE/stateful responses are unsupported.
- 503: verify PostgreSQL and Redis connectivity and audit-write permissions.
- New signing key rejected: allow the 60-second refresh interval and verify overlap.
- Docker cannot bind a port: stop the conflicting local service or update mappings
  together with issuer/resource/audience and login/smoke URLs.
