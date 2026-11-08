package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/ATLURI0001/mcp-authz-proxy/internal/auth"
	"github.com/ATLURI0001/mcp-authz-proxy/internal/store"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeAuth struct{}

func (fakeAuth) Verify(ctx context.Context, t string) (auth.Identity, error) {
	if t == "bad" {
		return auth.Identity{}, errors.New("invalid")
	}
	scopes := map[string]bool{"mcp:connect": true, "tools:read": true, "tools:write": true}
	if t == "limited" {
		delete(scopes, "tools:write")
	}
	return auth.Identity{Subject: t, Scopes: scopes}, nil
}

type memoryStore struct {
	mu              sync.Mutex
	events          []store.Event
	down, throttled bool
	approval        string
	used            bool
}

func (s *memoryStore) Allow(_ context.Context, sub, tool string) (bool, error) {
	if s.down {
		return false, errors.New("down")
	}
	return sub != "bob" || tool == "whoami", nil
}
func (s *memoryStore) Audit(_ context.Context, e store.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return errors.New("down")
	}
	s.events = append(s.events, e)
	return nil
}
func (s *memoryStore) Limit(context.Context, string, int) (bool, error) { return !s.throttled, nil }
func (s *memoryStore) Consume(_ context.Context, token, sub, digest string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || sub != "alice" || digest != s.approval || token != strings.Repeat("a", 64) {
		return false, nil
	}
	s.used = true
	return true, nil
}
func (s *memoryStore) Ready(context.Context) error { return nil }
func fixture(t *testing.T) (*Gateway, *memoryStore, *int) {
	t.Helper()
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Cookie") != "" || r.Header.Get("X-Approval-Token") != "" || r.Header.Get("X-Evil") != "" {
			t.Error("unsafe header forwarded")
		}
		token := r.Header.Get("Authorization")
		if token != "Bearer downstream-alice" && token != "Bearer downstream-bob" {
			t.Error("wrong credential", token)
		}
		var q Request
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.Method == "tools/list" {
			result(w, q.ID, map[string]any{"tools": []any{map[string]string{"name": "echo"}, map[string]string{"name": "whoami"}, map[string]string{"name": "secret"}}})
			return
		}
		result(w, q.ID, map[string]any{"content": []any{map[string]string{"type": "text", "text": token}}})
	}))
	t.Cleanup(upstream.Close)
	s := &memoryStore{}
	g := New(Config{Resource: "https://gateway.example/mcp", Issuer: "https://id.example", Upstream: upstream.URL, Rate: 100, Tools: map[string]Rule{"echo": {Scope: "tools:read"}, "whoami": {Scope: "tools:read"}, "restart_demo": {Scope: "tools:write", Approval: true}}, Credentials: map[string]string{"alice": "downstream-alice", "bob": "downstream-bob", "limited": "downstream-alice"}}, fakeAuth{}, s)
	g.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	return g, s, &calls
}
func call(g *Gateway, token, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", Version)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, r)
	return w
}

const echo = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}`

func TestSecurityBoundaries(t *testing.T) {
	tests := []struct {
		name, token, body string
		headers           map[string]string
		status            int
	}{
		{"missing token", "", echo, nil, 401}, {"invalid token", "bad", echo, nil, 401}, {"denied principal", "bob", echo, nil, 403},
		{"unknown principal", "unmapped", echo, nil, 403}, {"bad origin", "alice", echo, map[string]string{"Origin": "https://evil.example"}, 403},
		{"unsupported method", "alice", `{"jsonrpc":"2.0","id":1,"method":"resources/read"}`, nil, 400},
		{"unknown tool", "alice", strings.Replace(echo, `"echo"`, `"secret"`, 1), nil, 403},
		{"batch", "alice", "[" + echo + "]", nil, 400}, {"invalid JSON", "alice", "{", nil, 400},
		{"version", "alice", echo, map[string]string{"MCP-Protocol-Version": "1900-01-01"}, 400},
		{"session spoof", "alice", echo, map[string]string{"Mcp-Session-Id": "stolen"}, 400},
		{"accept", "alice", echo, map[string]string{"Accept": "text/html"}, 406},
		{"content type", "alice", echo, map[string]string{"Content-Type": "text/plain"}, 415},
		{"missing id", "alice", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"}}`, nil, 400},
		{"object id", "alice", strings.Replace(echo, `"id":1`, `"id":{}`, 1), nil, 400},
		{"missing approval", "alice", strings.Replace(echo, `"echo"`, `"restart_demo"`, 1), nil, 403},
		{"missing scope", "limited", strings.Replace(echo, `"echo"`, `"restart_demo"`, 1), nil, 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, _, n := fixture(t)
			w := call(g, tt.token, tt.body, tt.headers)
			if w.Code != tt.status {
				t.Fatalf("got %d: %s", w.Code, w.Body)
			}
			if *n != 0 {
				t.Fatal("denied request reached upstream")
			}
		})
	}
}
func TestForwardingAndCredentialIsolation(t *testing.T) {
	g, _, n := fixture(t)
	for _, user := range []string{"alice", "bob"} {
		w := call(g, user, strings.Replace(echo, `"echo"`, `"whoami"`, 1), map[string]string{"Cookie": "secret", "X-Evil": "url", "X-Approval-Token": "hidden"})
		if w.Code != 200 || !strings.Contains(w.Body.String(), "downstream-"+user) {
			t.Fatal(w.Code, w.Body)
		}
	}
	if *n != 2 {
		t.Fatal(*n)
	}
}
func TestFilteredDiscovery(t *testing.T) {
	g, _, _ := fixture(t)
	w := call(g, "bob", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "echo") || strings.Contains(w.Body.String(), "secret") || !strings.Contains(w.Body.String(), "whoami") {
		t.Fatal(w.Code, w.Body)
	}
}
func TestDependencyFailureAndRateLimit(t *testing.T) {
	for _, kind := range []string{"audit", "rate"} {
		g, s, n := fixture(t)
		want := 503
		if kind == "audit" {
			s.down = true
		} else {
			s.throttled = true
			want = 429
		}
		w := call(g, "alice", echo, nil)
		if w.Code != want || *n != 0 {
			t.Fatal(w.Code, *n)
		}
	}
}
func TestApprovalBindingAndReplay(t *testing.T) {
	g, s, n := fixture(t)
	params := `{"name":"restart_demo","arguments":{}}`
	s.approval, _ = Digest([]byte(params))
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":` + params + `}`
	headers := map[string]string{"X-Approval-Token": strings.Repeat("a", 64)}
	changed := strings.Replace(body, `"arguments":{}`, `"arguments":{"extra":true}`, 1)
	if w := call(g, "alice", changed, headers); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := call(g, "alice", body, headers); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := call(g, "alice", body, headers); w.Code != 403 {
		t.Fatal("approval replay", w.Code)
	}
	if *n != 1 {
		t.Fatal(*n)
	}
}
func TestProtocolLifecycle(t *testing.T) {
	g, _, n := fixture(t)
	w := call(g, "alice", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), Version) {
		t.Fatal(w.Code, w.Body)
	}
	w = call(g, "alice", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)
	if w.Code != 202 {
		t.Fatal(w.Code)
	}
	w = call(g, "alice", `{"jsonrpc":"2.0","id":2,"method":"ping"}`, nil)
	if w.Code != 200 || *n != 0 {
		t.Fatal(w.Code, *n)
	}
}
func TestNoRedirectCredentialLeak(t *testing.T) {
	g, _, _ := fixture(t)
	hit := false
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer sink.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, sink.URL, 307) }))
	defer redirect.Close()
	g.Config.Upstream = redirect.URL
	w := call(g, "alice", echo, nil)
	if w.Code != 502 || hit {
		t.Fatal(w.Code, hit)
	}
}
func TestUpstreamCancellation(t *testing.T) {
	g, _, _ := fixture(t)
	seen := make(chan struct{})
	cancelled := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(seen)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer up.Close()
	g.Config.Upstream = up.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(echo)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer alice")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", Version)
	done := make(chan struct{})
	go func() { g.Handler().ServeHTTP(httptest.NewRecorder(), r); close(done) }()
	select {
	case <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream not reached")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream not cancelled")
	}
	<-done
}
func TestAuditDoesNotContainArgumentsOrTokens(t *testing.T) {
	g, s, _ := fixture(t)
	w := call(g, "alice", echo, nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	b, _ := json.Marshal(s.events)
	for _, secret := range []string{"hello", "downstream-alice", "Bearer"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("audit leaked", secret)
		}
	}
}
func TestBodyLimit(t *testing.T) {
	g, _, n := fixture(t)
	w := call(g, "alice", strings.Repeat("x", maxBody+1), nil)
	if w.Code != 413 || *n != 0 {
		t.Fatal(w.Code)
	}
}
func TestDigestCanonicalization(t *testing.T) {
	a, _ := Digest([]byte(`{"name":"x","arguments":{"a":1,"b":2}}`))
	b, _ := Digest([]byte(`{"arguments":{"b":2,"a":1},"name":"x"}`))
	if a != b {
		t.Fatal("order changed digest")
	}
	c, _ := Digest([]byte(`{"name":"x","arguments":{"a":9007199254740993}}`))
	d, _ := Digest([]byte(`{"name":"x","arguments":{"a":9007199254740992}}`))
	if c == d {
		t.Fatal("numeric precision loss")
	}
}

func TestAmbiguousJSONRejected(t *testing.T) {
	g, _, n := fixture(t)
	bad := strings.Replace(echo, `"name":"echo"`, `"name":"restart_demo","name":"echo"`, 1)
	if w := call(g, "alice", bad, nil); w.Code != 400 || *n != 0 {
		t.Fatal(w.Code, *n)
	}
	if _, err := Digest([]byte(`{"name":"x","name":"y"}`)); err == nil {
		t.Fatal("duplicate approval key accepted")
	}
}

func TestMetadataAndMethods(t *testing.T) {
	g, _, n := fixture(t)
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "https://id.example") {
		t.Fatal(w.Code, w.Body)
	}
	for _, method := range []string{"GET", "DELETE"} {
		r := httptest.NewRequest(method, "/mcp", nil)
		r.Header.Set("Authorization", "Bearer alice")
		w = httptest.NewRecorder()
		g.Handler().ServeHTTP(w, r)
		if w.Code != 405 || *n != 0 {
			t.Fatal(w.Code)
		}
	}
}
