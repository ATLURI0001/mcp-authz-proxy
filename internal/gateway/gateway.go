// Package gateway implements a deliberately bounded MCP 2025-11-25 tools gateway.
package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ATLURI0001/mcp-authz-proxy/internal/auth"
	"github.com/ATLURI0001/mcp-authz-proxy/internal/store"
)

const Version = "2025-11-25"
const maxBody = 1024 * 1024

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type Gateway struct {
	Config                  Config
	Auth                    auth.Verifier
	Store                   store.Backend
	Client                  *http.Client
	Log                     *slog.Logger
	allowed, denied, failed atomic.Uint64
}

func New(c Config, a auth.Verifier, s store.Backend) *Gateway {
	return &Gateway{Config: c, Auth: a, Store: s, Log: slog.Default(), Client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (g *Gateway) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/mcp", g.serve)
	m.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("ok\n")) })
	m.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, c := context.WithTimeout(r.Context(), 2*time.Second)
		defer c()
		if g.Store.Ready(ctx) != nil {
			http.Error(w, "dependencies unavailable", 503)
			return
		}
		w.WriteHeader(200)
	})
	m.HandleFunc("/.well-known/oauth-protected-resource", g.metadata)
	m.HandleFunc("/.well-known/oauth-protected-resource/mcp", g.metadata)
	return m
}
func (g *Gateway) Metrics() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# TYPE mcp_requests_total counter\nmcp_requests_total{result=\"allowed\"} %d\nmcp_requests_total{result=\"denied\"} %d\nmcp_requests_total{result=\"error\"} %d\n", g.allowed.Load(), g.denied.Load(), g.failed.Load())
	})
}
func (g *Gateway) metadata(w http.ResponseWriter, r *http.Request) {
	scopes := []string{"mcp:connect"}
	seen := map[string]bool{"mcp:connect": true}
	for _, rule := range g.Config.Tools {
		if !seen[rule.Scope] {
			scopes = append(scopes, rule.Scope)
			seen[rule.Scope] = true
		}
	}
	sort.Strings(scopes)
	writeJSON(w, 200, map[string]any{"resource": g.Config.Resource, "authorization_servers": []string{g.Config.Issuer}, "scopes_supported": scopes, "bearer_methods_supported": []string{"header"}})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func rpcError(w http.ResponseWriter, status, code int, id json.RawMessage, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	writeJSON(w, status, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
}
func result(w http.ResponseWriter, id json.RawMessage, v any) {
	writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "result": v})
}
func (g *Gateway) audit(e store.Event) error {
	ctx, c := context.WithTimeout(context.Background(), 2*time.Second)
	defer c()
	if err := g.Store.Audit(ctx, e); err != nil {
		g.Log.Error("audit unavailable", "request_id", e.ID)
		return err
	}
	g.Log.Info("decision", "request_id", e.ID, "subject", e.Subject, "method", e.Method, "tool", e.Tool, "decision", e.Decision, "reason", e.Reason)
	return nil
}
func (g *Gateway) serve(w http.ResponseWriter, r *http.Request) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "entropy unavailable", 503)
		return
	}
	e := store.Event{ID: hex.EncodeToString(nonce)}
	w.Header().Set("X-Request-ID", e.ID)
	var req Request
	deny := func(status, code int, reason string) {
		e.Decision = "deny"
		e.Reason = reason
		g.denied.Add(1)
		if g.audit(e) != nil {
			g.failed.Add(1)
			rpcError(w, 503, -32603, req.ID, "audit unavailable")
			return
		}
		rpcError(w, status, code, req.ID, reason)
	}
	if r.URL.RawQuery != "" {
		deny(400, -32600, "query parameters are not accepted")
		return
	}
	if origins := r.Header.Values("Origin"); len(origins) > 0 {
		for _, origin := range origins {
			ok := false
			for _, s := range g.Config.Origins {
				if origin == s {
					ok = true
					break
				}
			}
			if !ok {
				deny(403, -32003, "origin denied")
				return
			}
		}
	}
	if len(r.Header.Values("Authorization")) != 1 {
		g.challenge(w, "")
		deny(401, -32001, "bearer token required")
		return
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		g.challenge(w, "")
		deny(401, -32001, "bearer token required")
		return
	}
	ident, err := g.Auth.Verify(r.Context(), parts[1])
	if err != nil {
		g.challenge(w, "")
		deny(401, -32001, "invalid access token")
		return
	}
	e.Subject = ident.Subject
	ok, err := g.Store.Limit(r.Context(), ident.Subject, g.Config.Rate)
	if err != nil {
		deny(503, -32603, "rate limiter unavailable")
		return
	}
	if !ok {
		w.Header().Set("Retry-After", "60")
		deny(429, -32029, "rate limit exceeded")
		return
	}
	if !ident.Scopes["mcp:connect"] {
		g.challenge(w, "mcp:connect")
		deny(403, -32003, "insufficient scope")
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		deny(405, -32600, "only POST is supported; no SSE or sessions")
		return
	}
	if r.Header.Get("Mcp-Session-Id") != "" {
		deny(400, -32600, "sessions are not supported")
		return
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" {
		deny(415, -32600, "application/json required")
		return
	}
	accept := strings.ToLower(strings.Join(r.Header.Values("Accept"), ", "))
	if !strings.Contains(accept, "application/json") || !strings.Contains(accept, "text/event-stream") {
		deny(406, -32600, "Accept must include application/json and text/event-stream")
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		deny(413, -32600, "request too large")
		return
	}
	if unambiguousJSON(b) != nil || json.Unmarshal(b, &req) != nil || req.JSONRPC != "2.0" || req.Method == "" {
		deny(400, -32600, "invalid JSON-RPC request; batches unsupported")
		return
	}
	if len(req.ID) > 0 {
		var id any
		dec := json.NewDecoder(bytes.NewReader(req.ID))
		dec.UseNumber()
		if dec.Decode(&id) != nil {
			deny(400, -32600, "invalid id")
			return
		}
		switch id.(type) {
		case string, json.Number:
		default:
			deny(400, -32600, "id must be string or number")
			return
		}
	}
	// Whitelist methods before using them as log fields.
	switch req.Method {
	case "initialize", "notifications/initialized", "ping", "tools/list", "tools/call":
		e.Method = req.Method
	default:
		deny(400, -32601, "method not supported")
		return
	}
	if req.Method != "initialize" && r.Header.Get("MCP-Protocol-Version") != Version {
		deny(400, -32600, "unsupported or missing MCP-Protocol-Version")
		return
	}
	if req.Method != "notifications/initialized" && len(req.ID) == 0 {
		deny(400, -32600, "request id required")
		return
	}
	if req.Method == "notifications/initialized" && len(req.ID) != 0 {
		deny(400, -32600, "notification must not contain id")
		return
	}
	credential := g.Config.Credentials[ident.Subject]
	if credential == "" {
		deny(403, -32003, "no downstream credential provisioned")
		return
	}
	// Never forward arbitrary methods, headers, URLs, cookies, session ids or inbound tokens.
	if req.Method == "tools/call" {
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if json.Unmarshal(req.Params, &p) != nil || p.Name == "" {
			deny(400, -32602, "invalid tool parameters")
			return
		}
		if len(p.Arguments) > 0 && !bytes.Equal(bytes.TrimSpace(p.Arguments), []byte("null")) {
			trimmed := bytes.TrimSpace(p.Arguments)
			if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
				deny(400, -32602, "tool arguments must be a JSON object")
				return
			}
		}
		rule, exists := g.Config.Tools[p.Name]
		if !exists {
			deny(403, -32003, "tool denied")
			return
		}
		e.Tool = p.Name
		if !ident.Scopes[rule.Scope] {
			g.challenge(w, rule.Scope)
			deny(403, -32003, "insufficient scope")
			return
		}
		ok, err = g.Store.Allow(r.Context(), ident.Subject, p.Name)
		if err != nil {
			deny(503, -32603, "policy unavailable")
			return
		}
		if !ok {
			deny(403, -32003, "tool denied")
			return
		}
		if rule.Approval {
			digest, err := Digest(req.Params)
			if err != nil {
				deny(400, -32602, "invalid parameters")
				return
			}
			token := r.Header.Get("X-Approval-Token")
			if len(token) != 64 {
				deny(403, -32003, "approval required")
				return
			}
			ok, err = g.Store.Consume(r.Context(), token, ident.Subject, digest)
			if err != nil {
				deny(503, -32603, "approval store unavailable")
				return
			}
			if !ok {
				deny(403, -32003, "approval invalid, expired, or already used")
				return
			}
		}
	}
	e.Decision = "allow"
	e.Reason = "authorized"
	if err = g.audit(e); err != nil {
		g.failed.Add(1)
		rpcError(w, 503, -32603, req.ID, "audit unavailable")
		return
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(req.Params, &p) != nil || p.ProtocolVersion == "" {
			rpcError(w, 400, -32602, req.ID, "protocolVersion required")
			return
		}
		g.allowed.Add(1)
		result(w, req.ID, map[string]any{"protocolVersion": Version, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "serverInfo": map[string]string{"name": "mcp-authz-proxy", "version": "0.1.0"}})
		return
	case "notifications/initialized":
		g.allowed.Add(1)
		w.WriteHeader(202)
		return
	case "ping":
		g.allowed.Add(1)
		result(w, req.ID, map[string]any{})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	up, err := http.NewRequestWithContext(ctx, "POST", g.Config.Upstream, bytes.NewReader(b))
	if err != nil {
		g.upstreamError(w, req.ID, e)
		return
	}
	up.Header.Set("Authorization", "Bearer "+credential)
	up.Header.Set("Content-Type", "application/json")
	up.Header.Set("Accept", "application/json, text/event-stream")
	up.Header.Set("MCP-Protocol-Version", Version)
	res, err := g.Client.Do(up)
	if err != nil {
		g.upstreamError(w, req.ID, e)
		return
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	media, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || len(data) > maxBody || res.StatusCode != 200 || media != "application/json" || res.Header.Get("Mcp-Session-Id") != "" {
		g.upstreamError(w, req.ID, e)
		return
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(data, &envelope) != nil || string(envelope["jsonrpc"]) != `"2.0"` || !bytes.Equal(bytes.TrimSpace(envelope["id"]), bytes.TrimSpace(req.ID)) {
		g.upstreamError(w, req.ID, e)
		return
	}
	_, hasResult := envelope["result"]
	_, hasError := envelope["error"]
	if hasResult == hasError {
		g.upstreamError(w, req.ID, e)
		return
	}
	if req.Method == "tools/list" && hasResult {
		var listing struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor,omitempty"`
		}
		if json.Unmarshal(envelope["result"], &listing) != nil {
			g.upstreamError(w, req.ID, e)
			return
		}
		visible := []json.RawMessage{}
		for _, tool := range listing.Tools {
			var t struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(tool, &t) != nil {
				g.upstreamError(w, req.ID, e)
				return
			}
			rule, exists := g.Config.Tools[t.Name]
			if !exists || !ident.Scopes[rule.Scope] {
				continue
			}
			allowed, err := g.Store.Allow(ctx, ident.Subject, t.Name)
			if err != nil {
				g.upstreamError(w, req.ID, e)
				return
			}
			if allowed {
				visible = append(visible, tool)
			}
		}
		listing.Tools = visible
		envelope["result"], _ = json.Marshal(listing)
		data, _ = json.Marshal(envelope)
	}
	g.allowed.Add(1)
	e.Decision = "complete"
	e.Reason = "upstream_response"
	// The intent was durably logged before execution; completion failure cannot undo an action.
	if err = g.audit(e); err != nil {
		g.failed.Add(1)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	_, _ = w.Write(data)
}
func (g *Gateway) challenge(w http.ResponseWriter, scope string) {
	suffix := ""
	if scope != "" {
		suffix = `, error="insufficient_scope", scope="` + scope + `"`
	}
	w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+strings.TrimSuffix(g.Config.Resource, "/mcp")+`/.well-known/oauth-protected-resource"`+suffix)
}
func (g *Gateway) upstreamError(w http.ResponseWriter, id json.RawMessage, e store.Event) {
	g.failed.Add(1)
	e.Decision = "error"
	e.Reason = "upstream_failure"
	_ = g.audit(e)
	rpcError(w, 502, -32603, id, "upstream unavailable or unsupported response")
}

// Digest binds approvals to the entire params object using Go's stable JSON encoding.
// json.Number prevents float rounding; object key order is normalized, arrays are not.
func Digest(raw []byte) (string, error) {
	if err := unambiguousJSON(raw); err != nil {
		return "", err
	}
	var v map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return "", err
	}
	if v == nil {
		return "", fmt.Errorf("object required")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
