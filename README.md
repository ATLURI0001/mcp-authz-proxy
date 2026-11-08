# mcp-authz-proxy

**Scoped tool access. Separate credentials. Auditable execution.**

A Go authorization gateway for MCP tools. It validates access tokens, intersects
token scopes with per-user database grants, and forwards approved tool requests
using a separate downstream credential for each user.

The demo makes the boundary visible: Alice can echo a message; Bob cannot. Both can
ask `whoami`, and the backend sees their distinct identities. A simulated restart
requires an operator-issued approval tied to the exact request and usable once.

**Status:** pre-1.0 reference implementation. Targets MCP **2025-11-25**, JSON-only
stateless tools backends. It is not a universal MCP proxy or a certified security
product. Read [the supported protocol contract](docs/PROTOCOL.md) before connecting
an existing MCP server. [Validation status](docs/VALIDATION.md) distinguishes executed
checks from checks provided for your environment.

## Run the full demo

Install Docker Desktop/Engine with Compose v2 and Python 3.10+. From this folder:

```bash
python3 scripts/setup-demo.py
docker compose up --build -d
python3 scripts/smoke.py
```

On Windows, `python` may be the installed command instead of `python3`.
The smoke script waits for startup, then checks authentication, allow/deny decisions,
per-user credentials, filtered tool discovery and the approval gate. No paid API or
LLM key is needed. The restart tool is a simulation and changes no infrastructure.

| Service | Local URL |
|---|---|
| MCP endpoint | http://localhost:8080/mcp |
| Keycloak | http://localhost:8082 |
| Grafana dashboard | http://localhost:3000/d/mcp-authz |
| Prometheus | http://localhost:9091 |

Grafana and Keycloak admin credentials are generated in `.env`. The two **local-only**
fixture users are `alice` / `demo-alice-local-only` and `bob` / `demo-bob-local-only`.
Never expose this demo stack or reuse fixture credentials externally.

## What is implemented

| Deliverable | Implementation |
|---|---|
| Gateway | Go HTTP server; tools forwarding; bounded bodies/timeouts; graceful shutdown |
| OAuth resource server | Fixed issuer/JWKS, RS256, audience/expiry checks, protected-resource metadata |
| Interactive login demo | Authorization Code + PKCE S256 helper with state validation |
| Policy | Configured tool allowlist + token scopes + PostgreSQL per-user grants |
| Credential boundary | Separate operator-provisioned downstream token per subject; no passthrough |
| Approvals | Exact params digest, subject binding, five-minute expiry, atomic one-use consumption |
| Audit | Durable pre-execution intent plus completion/error events; structured JSON logs |
| Limits | Redis rate counters shared across replicas; request/header/response/time limits |
| Observability | Private Prometheus metrics endpoint and provisioned Grafana dashboard |
| Demo | Keycloak, PostgreSQL, Redis, gateway, demo server, Prometheus, Grafana |
| Delivery | Dockerfile, Compose, Kubernetes template, tests, CI and cross-platform build workflow |

## Try an authenticated call

For interactive browser login:

```bash
# Bash / zsh
TOKEN=$(python3 scripts/login.py)
curl http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}'
```

The gateway is stateless, so this diagnostic call can run without a stored session.
A regular MCP client should perform initialize/initialized negotiation first.
PowerShell equivalent:

```powershell
$token = python scripts/login.py
$headers = @{
  Authorization = "Bearer $token"
  Accept = "application/json, text/event-stream"
  "MCP-Protocol-Version" = "2025-11-25"
}
$body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}'
Invoke-RestMethod -Uri http://localhost:8080/mcp -Method Post -Headers $headers -ContentType application/json -Body $body
```

Do not commit or share access tokens. See [deployment instructions](docs/DEPLOYMENT.md)
for granting/revoking access and issuing one-use restart approvals.

## Develop and test

Go 1.27.3+ is required for local builds. Docker builds supply their own Go toolchain.

```bash
go mod download
go vet ./...
go test -race -count=1 -coverprofile=coverage.out ./...
go build ./...
```

`make build` builds three executables: `gateway`, `demo-server`, and `admin`.
The native gateway defaults to loopback listeners. Its runtime needs DATABASE_URL,
REDIS_URL, subject credential variables, and CONFIG_FILE (defaults to
`configs/local.json`). Use Compose for the easiest integrated setup.

Security tests cover wrong issuer/audience, expired tokens, algorithm confusion,
unauthorized tools, cross-user credentials, filtered discovery, audit failure,
rate limiting, approval replay/argument changes, redirected requests, cancellation,
body limits, version handling and duplicate JSON keys. Backend integration tests
are gated by TEST_DATABASE_URL and TEST_REDIS_URL; CI supplies real services.

## Repository map

- `cmd/` — gateway, demo server and operator CLI
- `internal/auth/` — access-token validation and bounded JWKS caching
- `internal/gateway/` — protocol handling, authorization and forwarding
- `internal/store/` — PostgreSQL and Redis adapters
- `configs/` — local/Compose configuration and approval example
- `deploy/` — schema, identity realm, monitoring and Kubernetes template
- `scripts/` — setup, login, smoke and test helpers
- `docs/` — architecture, protocol limits, threat model, operations and GitHub setup

## Boundaries

No SSE, sessions, stdio, resources, prompts, sampling, task API or automatic upstream
OAuth account linking. No prompt-injection detection or exactly-once execution.
Credentials are provisioned externally. The Kubernetes manifest requires your own
image, secrets, identity provider, TLS ingress and databases. These limits are
intentional and documented; unsupported requests fail closed.

[Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT-MODEL.md) ·
[Deployment](docs/DEPLOYMENT.md) · [Push to GitHub](docs/GITHUB-PUSH.md) ·
[Security policy](SECURITY.md)

MIT licensed. Maintained by Ramprasad Atluri.
