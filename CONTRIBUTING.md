# Contributing

Use Go 1.27.3 or newer. Run `go mod download`, then `bash scripts/test.sh` (or the
individual commands on Windows). Tests must verify a security boundary or externally
visible behavior. Keep policy checks before upstream calls; never forward inbound
Authorization, session IDs, cookies or arbitrary client headers.

For backend integration tests, use an isolated PostgreSQL database initialized with
`deploy/schema.sql` and Redis, then set TEST_DATABASE_URL and TEST_REDIS_URL. Tests
create/delete prefixed fixture records. Never point these tests at production.

Before submitting a change, run the Compose smoke test and update the compatibility
matrix if supported methods, transport behavior or authorization rules change.
Document any security tradeoff. Use focused commits and a PR that explains the
problem, behavior change and validation performed.

For the optional native full-binary check (Linux/macOS), build with `make build`,
install `python3 -m pip install -r scripts/requirements-test.txt`, set the same two
TEST_* URLs, and run `python3 scripts/native-e2e.py`. Initialize the test database
with deploy/schema.sql first. It starts a test JWKS issuer plus the gateway/backend
on loopback ports 18082, 18080, 19090 and 8081. Keep those ports free. This check
uses real signed tokens and databases but does not validate Keycloak login.
