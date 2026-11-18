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

func TestGatewayOriginCaseInsensitiveAndTrailingSlash(t *testing.T) {
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

	// Uppercase and trailing slash should match canonical https://allowed.example
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)))
	req.Header.Set("Origin", "HTTPS://ALLOWED.EXAMPLE/")
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", Version)

	rr := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for case-insensitive origin with trailing slash, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestGatewayRejectsDuplicateContentTypeAndProtocolVersionHeaders(t *testing.T) {
	cfg := Config{
		Resource: "https://mcp.example",
		Issuer:   "https://auth.example",
		Rate:     10,
		Credentials: map[string]string{
			"alice": "secret",
		},
	}
	gw := New(cfg, fakeAuth{}, &memoryStore{})

	// Duplicate Content-Type headers
	req1 := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)))
	req1.Header.Set("Authorization", "Bearer alice")
	req1.Header.Add("Content-Type", "application/json")
	req1.Header.Add("Content-Type", "text/plain")
	req1.Header.Set("Accept", "application/json, text/event-stream")
	req1.Header.Set("MCP-Protocol-Version", Version)

	rr1 := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 for duplicate Content-Type headers, got %d", rr1.Code)
	}

	// Duplicate MCP-Protocol-Version headers
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)))
	req2.Header.Set("Authorization", "Bearer alice")
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json, text/event-stream")
	req2.Header.Add("MCP-Protocol-Version", Version)
	req2.Header.Add("MCP-Protocol-Version", "2024-11-05")

	rr2 := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for duplicate MCP-Protocol-Version headers, got %d", rr2.Code)
	}
}

func TestGatewayRejectsWhitespaceOnlyToolName(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"   ","arguments":{}}}`)))
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", Version)

	rr := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for whitespace tool name, got %d (%s)", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("invalid tool parameters")) {
		t.Fatalf("expected 'invalid tool parameters' error, got %s", rr.Body.String())
	}
}

func TestGatewayRejectsMultiOrInvalidApprovalTokenHeaders(t *testing.T) {
	cfg := Config{
		Resource: "https://mcp.example",
		Issuer:   "https://auth.example",
		Rate:     10,
		Credentials: map[string]string{
			"alice": "secret",
		},
		Tools: map[string]Rule{
			"deploy": {Scope: "tools:read", Approval: true},
		},
	}
	memStore := &memoryStore{}
	gw := New(cfg, fakeAuth{}, memStore)

	// Multiple X-Approval-Token headers
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy","arguments":{}}}`)))
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", Version)
	req.Header.Add("X-Approval-Token", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	req.Header.Add("X-Approval-Token", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")

	rr := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for multiple approval tokens, got %d (%s)", rr.Code, rr.Body.String())
	}

	// Non-hex characters in approval token
	reqNonHex := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy","arguments":{}}}`)))
	reqNonHex.Header.Set("Authorization", "Bearer alice")
	reqNonHex.Header.Set("Content-Type", "application/json")
	reqNonHex.Header.Set("Accept", "application/json, text/event-stream")
	reqNonHex.Header.Set("MCP-Protocol-Version", Version)
	reqNonHex.Header.Set("X-Approval-Token", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg") // 'g' is non-hex

	rrNonHex := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rrNonHex, reqNonHex)
	if rrNonHex.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-hex approval token, got %d (%s)", rrNonHex.Code, rrNonHex.Body.String())
	}
}
