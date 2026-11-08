# Validation report

Validated on 8 November 2026 with Go 1.27.3 on Linux amd64.

| Check | Result |
|---|---|
| gofmt check | PASS |
| go vet ./... | PASS |
| go test -race -count=1 -coverprofile=coverage.out ./... | PASS, including real backend integration |
| go build ./... and all three executable builds | PASS |
| govulncheck v1.9.0 ./... | No vulnerabilities found after dependency upgrades |
| PostgreSQL adapter | PASS against PostgreSQL 17.11 |
| Redis adapter | PASS against Redis 8.0.2 |
| Native gateway + demo-server + admin end-to-end | PASS |
| JSON and YAML parsing, Python syntax, shell syntax | PASS |
| Compose stack including Keycloak/Grafana | NOT RUN: Docker unavailable in build environment |
| Interactive Keycloak Code + PKCE login | NOT RUN: included for local verification |
| Kubernetes template | NOT DEPLOYED: environment-specific image/secrets/networking required |
| GitHub Actions | Workflow definitions supplied; not executed on GitHub |
| Container vulnerability scan | NOT RUN |

The native end-to-end test uses a locally generated RSA key and a test JWKS server.
It validates the resource-server path, not Keycloak configuration or login. It
exercised successful Alice calls, denied Bob calls, distinct downstream identities,
wrong-audience rejection, approval gating, argument binding, successful approved
execution and replay rejection using the built binaries and real databases.

Unit/integration coverage: auth 82.1%, gateway 81.2%, store 78.1%; overall Go statement
coverage 62.9%. Command entry points were exercised by a separate native run and
are not included in instrumented coverage. These are coverage measurements, not
security guarantees or benchmark results.

The initial vulnerability scan found vulnerable dependency versions; pgx and
transitive text dependencies were upgraded before the final successful scan.
The final module versions are locked in go.mod and go.sum. Vulnerability databases
change: run the scan again before deployment. CI includes it.

The Redis integration run used 8.0.2 while Compose/CI pin the compatible 7.4 series.
The adapter uses INCR, EXPIRE and EVAL, which are supported by both; the complete
Compose configuration still requires its own smoke run.

Reproduce the main checks with `bash scripts/test.sh`. For real backends, initialize
an isolated database from deploy/schema.sql and set TEST_DATABASE_URL and
TEST_REDIS_URL. Without those variables, the backend integration test is explicitly
skipped. For the native binary test, follow CONTRIBUTING.md. For the complete stack,
run `python3 scripts/smoke.py` after `docker compose up --build -d`.

The packaging workspace was outside a Git checkout, so local build commands used
GOFLAGS=-buildvcs=false to disable unavailable VCS stamping. Normal Git clones and
GitHub Actions do not require that override.
