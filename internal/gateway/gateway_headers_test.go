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

func TestGatewayRejectsNonObjectToolArguments(t *testing.T) {
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

	// Send an array for arguments instead of a JSON object
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":[1,2,3]}}`)))
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", Version)

	rr := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for array arguments, got %d (%s)", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("tool arguments must be a JSON object")) {
		t.Fatalf("expected error message to mention tool arguments object requirement, got %s", rr.Body.String())
	}
}

func TestGatewayRejectsTrailingDataInID(t *testing.T) {
	cfg := Config{
		Resource: "https://mcp.example",
		Issuer:   "https://auth.example",
		Rate:     10,
		Credentials: map[string]string{
			"alice": "secret",
		},
	}
	gw := New(cfg, fakeAuth{}, &memoryStore{})

	// ID containing multiple tokens
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":"id1" "id2","method":"ping"}`)))
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", Version)

	rr := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for trailing tokens in id, got %d", rr.Code)
	}
}

func TestUnambiguousJSONEmptyPayload(t *testing.T) {
	err := unambiguousJSON([]byte("   "))
	if err == nil || err.Error() != "empty JSON payload" {
		t.Fatalf("expected 'empty JSON payload' error, got %v", err)
	}
}
