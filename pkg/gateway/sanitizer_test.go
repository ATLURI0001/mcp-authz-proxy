package gateway

import (
	"net/http"
	"testing"
)

func TestRequestSanitizer_SanitizeHeader(t *testing.T) {
	s := NewRequestSanitizer()

	// Valid header
	k, v, err := s.SanitizeHeader("X-Tenant-ID", "tenant-12345")
	if err != nil || k != "X-Tenant-ID" || v != "tenant-12345" {
		t.Fatalf("unexpected result: k=%s, v=%s, err=%v", k, v, err)
	}

	// CRLF injection attempt
	_, _, err = s.SanitizeHeader("X-Forwarded", "val\r\nSet-Cookie: evil=true")
	if err != ErrCRLFInjection {
		t.Fatalf("expected ErrCRLFInjection, got %v", err)
	}

	// Null byte injection attempt
	_, _, err = s.SanitizeHeader("X-User", "admin\x00secret")
	if err != ErrNullByteInjection {
		t.Fatalf("expected ErrNullByteInjection, got %v", err)
	}

	// Invalid header key
	_, _, err = s.SanitizeHeader("X-Invalid Key:", "test")
	if err != ErrInvalidHeaderName {
		t.Fatalf("expected ErrInvalidHeaderName, got %v", err)
	}
}

func TestRequestSanitizer_FilterHopByHopHeaders(t *testing.T) {
	s := NewRequestSanitizer()

	headers := make(http.Header)
	headers.Add("Connection", "keep-alive")
	headers.Add("Keep-Alive", "timeout=5")
	headers.Add("Upgrade", "websocket")
	headers.Add("Transfer-Encoding", "chunked")
	headers.Add("X-Real-IP", "10.0.0.1")
	headers.Add("Authorization", "Bearer token-123")

	filtered := s.FilterHopByHopHeaders(headers)

	if filtered.Get("Connection") != "" {
		t.Errorf("expected Connection header to be filtered")
	}
	if filtered.Get("Upgrade") != "" {
		t.Errorf("expected Upgrade header to be filtered")
	}
	if filtered.Get("Transfer-Encoding") != "" {
		t.Errorf("expected Transfer-Encoding header to be filtered")
	}
	if filtered.Get("X-Real-IP") != "10.0.0.1" {
		t.Errorf("expected X-Real-IP to be retained, got %s", filtered.Get("X-Real-IP"))
	}
	if filtered.Get("Authorization") != "Bearer token-123" {
		t.Errorf("expected Authorization to be retained, got %s", filtered.Get("Authorization"))
	}
}

func TestRequestSanitizer_ExtractBearerToken(t *testing.T) {
	s := NewRequestSanitizer()

	// Valid Bearer
	tok, err := s.ExtractBearerToken("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz.123")
	if err != nil || tok != "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz.123" {
		t.Fatalf("unexpected token extract: tok=%s, err=%v", tok, err)
	}

	// Malformed prefix
	_, err = s.ExtractBearerToken("Basic dXNlcjpwYXNz")
	if err != ErrInvalidBearerFormat {
		t.Fatalf("expected ErrInvalidBearerFormat, got %v", err)
	}

	// CRLF in token
	_, err = s.ExtractBearerToken("Bearer abc\r\nxyz")
	if err != ErrCRLFInjection {
		t.Fatalf("expected ErrCRLFInjection, got %v", err)
	}

	// Invalid characters
	_, err = s.ExtractBearerToken("Bearer bad token with spaces")
	if err != ErrInvalidBearerFormat {
		t.Fatalf("expected ErrInvalidBearerFormat, got %v", err)
	}
}

func TestRequestSanitizer_SanitizeForwardedPath(t *testing.T) {
	s := NewRequestSanitizer()

	// Normal path
	p, err := s.SanitizeForwardedPath("/mcp/tools/list")
	if err != nil || p != "/mcp/tools/list" {
		t.Fatalf("unexpected path: %s, err: %v", p, err)
	}

	// Traversal attempt
	_, err = s.SanitizeForwardedPath("/mcp/../../../etc/passwd")
	if err != ErrPathTraversal {
		t.Fatalf("expected ErrPathTraversal, got %v", err)
	}

	// Redundant slashes cleaned
	p, err = s.SanitizeForwardedPath("//mcp//tools/call")
	if err != nil || p != "/mcp/tools/call" {
		t.Fatalf("unexpected cleaned path: %s", p)
	}

	// Null byte rejection
	_, err = s.SanitizeForwardedPath("/mcp/tools\x00/evil")
	if err != ErrNullByteInjection {
		t.Fatalf("expected ErrNullByteInjection, got %v", err)
	}
}
