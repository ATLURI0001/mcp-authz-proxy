package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayRejectsMultiOriginSmuggling(t *testing.T) {
	cfg := Config{
		Resource: "https://mcp.example",
		Issuer:   "https://auth.example",
		Origins:  []string{"https://allowed.example"},
		Rate:     10,
		Credentials: map[string]string{
			"alice": "secret",
		},
		Tools: map[string]Rule{
			"echo": {Scope: "tools:read"},
		},
	}
	gw := New(cfg, fakeAuth{}, &memoryStore{})

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)))
	req.Header.Add("Origin", "https://allowed.example")
	req.Header.Add("Origin", "https://evil.example")
	req.Header.Set("Authorization", "Bearer alice")

	rr := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for multi-Origin smuggling, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestGatewayAcceptsSplitCaseInsensitiveAcceptHeaders(t *testing.T) {
	cfg := Config{
		Resource: "https://mcp.example",
		Issuer:   "https://auth.example",
		Rate:     10,
		Credentials: map[string]string{
			"alice": "secret",
		},
		Tools: map[string]Rule{
			"echo": {Scope: "tools:read"},
		},
	}
	gw := New(cfg, fakeAuth{}, &memoryStore{})

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)))
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Accept", "Application/JSON")
	req.Header.Add("Accept", "text/event-stream")

	rr := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rr, req)
	if rr.Code == http.StatusNotAcceptable {
		t.Fatalf("expected split case-insensitive Accept headers to be accepted, got 406")
	}
}
