# MCP compatibility contract

This release deliberately targets the **2025-11-25** MCP revision, not the latest
revision. It implements a bounded tools-only, JSON-response Streamable HTTP server.
It is not advertised as a general-purpose transparent proxy or full conformance
implementation. Check the client's ability to negotiate this revision.

| Capability | Behavior |
|---|---|
| `initialize` | Local result; negotiates 2025-11-25, advertises tools only |
| `notifications/initialized` | Authenticated 202, no response body |
| `ping` | Local empty result |
| `tools/list` | Forwarded, filtered by grants and scopes; preserves cursor |
| `tools/call` | Authorized, optionally approved, forwarded |
| HTTP GET / DELETE | 405; no SSE stream or session lifecycle |
| JSON-RPC batches | Rejected |
| Resources, prompts, tasks, sampling, elicitation | Not implemented; rejected |
| Cancellation | HTTP disconnect/context cancellation propagates; JSON-RPC cancellation notifications are not implemented |
| Streaming responses | Not implemented; upstream SSE rejected with 502 |
| Stateful upstreams | Not supported; no session passthrough |
| Newer protocol revisions | Not implemented; explicitly rejected after negotiation |

Every POST needs `Authorization: Bearer ...`, `Content-Type: application/json`,
and `Accept: application/json, text/event-stream`. After initialization also send
`MCP-Protocol-Version: 2025-11-25`. No query parameters are accepted.
Tool permissions require both a token scope and a database grant.

HTTP errors use JSON-RPC error envelopes with the request ID when known: 401 for
invalid/missing tokens, 403 for denial, 429 for rate limits, 503 for unavailable
policy/audit/rate dependencies, and 502 for upstream failures. Successful upstream
tool errors remain MCP `isError` responses. Never retry mutating calls blindly.

OAuth protected-resource metadata is exposed at
`/.well-known/oauth-protected-resource` and
`/.well-known/oauth-protected-resource/mcp`. The 401 challenge points clients to
metadata. The gateway is a resource server, not an authorization server. Keycloak
handles login and token issuance; `scripts/login.py` demonstrates Code + PKCE.
The smoke script's password grant is a demo/CI exception, not OAuth 2.1 guidance.

References consulted:
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://www.rfc-editor.org/rfc/rfc9728
