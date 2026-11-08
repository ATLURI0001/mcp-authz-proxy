# Threat model

## Assets and trust assumptions

Protected assets are downstream credentials, tool execution authority, user data,
policy records and audit history. Attackers may control a client, tool arguments,
headers, JSON-RPC method names or a lower-privileged account. The issuer, operator,
configuration, downstream server and infrastructure secret stores are trusted.

| Threat | Implemented control | Remaining limit |
|---|---|---|
| Wrong-audience or forged tokens | RS256 allowlist; issuer/audience/expiry/signature checks | Bearer token theft remains possible; use HTTPS and short expiry |
| Cross-user access | Exact subject grants; independent downstream credentials | Upstream must enforce the identity of those credentials |
| Token passthrough | Fresh upstream Authorization header from provisioned secret | No automatic upstream OAuth provisioning |
| Tool-name bypass | Fixed method/tool allowlists; duplicate-key rejection | Arguments are validated by the backend, not a general policy language |
| Approval replay or argument substitution | Atomic single-use approval bound to subject and full params digest | Operator must review the entire params file |
| Credential exfiltration via redirects | Redirects disabled; fixed configured upstream | Trusted config and DNS can still redirect traffic at infrastructure level |
| Browser-origin abuse | Exact Origin allowlist, no wildcard CORS | Not an authentication substitute; non-browser clients may omit Origin |
| Dependency outage | Policy, initial audit and rate checks fail closed | Availability depends on PostgreSQL/Redis/issuer |
| Request flooding | Body/header/time limits and distributed per-user rate limit | Unauthenticated traffic needs ingress-level rate/connection limits |
| Sensitive logging | No raw tokens, tool arguments or response bodies in audit | Subject IDs are personal data; define retention/access policies |
| Duplicate execution | No automatic retries; one-use sensitive approvals | Network failure can leave execution outcome unknown |

## Explicit non-goals

This gateway does not detect prompt injection, sanitize model output, isolate
untrusted server processes, implement malware scanning, or make destructive tools
safe by itself. Authorization cannot determine whether a user's instruction is
wise. No security audit, penetration-test certification or benchmark is claimed.

The demo database role is a development superuser. Production must separate schema
owner, operator and runtime roles. Runtime needs SELECT on grants, INSERT on audit
and DELETE on approvals; use a narrowly permissioned view or database function for
approval consumption if your database access policy requires it. Protect Redis,
issuer management, metrics and configuration from public access. Do not expose the
demo server directly. Egress policy must restrict the gateway to the expected issuer,
database, Redis and upstream endpoints. The sample Kubernetes policy restricts
**ingress only**, because egress destinations depend on your environment.

## Key and secret rotation

JWKS cache is refreshed at most every 60 seconds. Keep old signing keys published
during token overlap. Unknown keys fail closed during the cooldown. Credential
mappings are read at startup; rotate downstream secrets and restart instances with
an overlap window managed by the upstream. JWT revocation/introspection is not
implemented; token expiry bounds exposure. Immediate grant revocation prevents
new tool calls even while a valid token exists.
