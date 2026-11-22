package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAuthorizationHeader_ValidBearer(t *testing.T) {
	validTokens := []string{
		"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc_123-XYZ~+/",
		"bearer mcp_token_alpha_numeric_442==",
		"BEARER simpleToken123",
	}

	for _, vt := range validTokens {
		cred, err := ParseAuthorizationHeader(vt)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", vt, err)
		}
		if cred.Type != CredentialTypeBearer {
			t.Fatalf("expected CredentialTypeBearer, got %s", cred.Type)
		}
		if cred.RawToken == "" {
			t.Fatal("expected non-empty RawToken")
		}
		if !strings.Contains(cred.MaskedToken, "...") {
			t.Fatalf("expected masked token with ellipsis, got %s", cred.MaskedToken)
		}
	}
}

func TestParseAuthorizationHeader_Rejections(t *testing.T) {
	// Empty or whitespace
	_, err := ParseAuthorizationHeader("")
	if !errors.Is(err, ErrMissingAuthHeader) {
		t.Fatalf("expected ErrMissingAuthHeader, got %v", err)
	}

	_, err = ParseAuthorizationHeader("   ")
	if !errors.Is(err, ErrMissingAuthHeader) {
		t.Fatalf("expected ErrMissingAuthHeader, got %v", err)
	}

	// Invalid schemes
	_, err = ParseAuthorizationHeader("Basic dXNlcjpwYXNz")
	if !errors.Is(err, ErrInvalidAuthScheme) {
		t.Fatalf("expected ErrInvalidAuthScheme, got %v", err)
	}

	_, err = ParseAuthorizationHeader("Token 123456")
	if !errors.Is(err, ErrInvalidAuthScheme) {
		t.Fatalf("expected ErrInvalidAuthScheme, got %v", err)
	}

	// CRLF injection
	_, err = ParseAuthorizationHeader("Bearer token\r\nX-Injected: evil")
	if !errors.Is(err, ErrInvalidTokenChars) {
		t.Fatalf("expected ErrInvalidTokenChars for CRLF, got %v", err)
	}

	// Null byte
	_, err = ParseAuthorizationHeader("Bearer token\x00evil")
	if !errors.Is(err, ErrInvalidTokenChars) {
		t.Fatalf("expected ErrInvalidTokenChars for null byte, got %v", err)
	}

	// Spaces inside token
	_, err = ParseAuthorizationHeader("Bearer token with spaces")
	if !errors.Is(err, ErrInvalidTokenChars) {
		t.Fatalf("expected ErrInvalidTokenChars for token with spaces, got %v", err)
	}

	// Token too long
	longToken := "Bearer " + strings.Repeat("A", 4097)
	_, err = ParseAuthorizationHeader(longToken)
	if !errors.Is(err, ErrTokenTooLong) {
		t.Fatalf("expected ErrTokenTooLong, got %v", err)
	}
}

func TestParseApiKeyHeader(t *testing.T) {
	// Valid API key
	cred, err := ParseApiKeyHeader("mcp_live_9a8b7c6d5e4f3a2b1c0d")
	if err != nil {
		t.Fatalf("unexpected error for valid API key: %v", err)
	}
	if cred.Type != CredentialTypeApiKey {
		t.Fatalf("expected CredentialTypeApiKey, got %s", cred.Type)
	}
	if cred.MaskedToken == "" {
		t.Fatal("expected masked token")
	}

	// Empty
	_, err = ParseApiKeyHeader("")
	if !errors.Is(err, ErrMissingAuthHeader) {
		t.Fatalf("expected ErrMissingAuthHeader, got %v", err)
	}

	// Too short (< 8 chars)
	_, err = ParseApiKeyHeader("short")
	if !errors.Is(err, ErrMalformedApiKey) {
		t.Fatalf("expected ErrMalformedApiKey, got %v", err)
	}

	// Invalid characters (e.g. semicolon)
	_, err = ParseApiKeyHeader("mcp_key;drop_table")
	if !errors.Is(err, ErrMalformedApiKey) {
		t.Fatalf("expected ErrMalformedApiKey, got %v", err)
	}
}

func TestMaskToken(t *testing.T) {
	assertMask := func(input, expected string) {
		t.Helper()
		actual := MaskToken(input)
		if actual != expected {
			t.Fatalf("MaskToken(%q) = %q; expected %q", input, actual, expected)
		}
	}

	assertMask("", "<empty>")
	assertMask("   ", "<empty>")
	assertMask("short", "***")
	assertMask("12345678", "***")
	assertMask("mcp_live_sec_1234567890abcdef", "mcp_li...cdef")
}
