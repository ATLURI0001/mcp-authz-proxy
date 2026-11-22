package auth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	ErrMissingAuthHeader = errors.New("authorization header is missing or empty")
	ErrInvalidAuthScheme = errors.New("unsupported authorization scheme, expected Bearer")
	ErrTokenTooLong      = errors.New("authorization token exceeds maximum allowable length of 4096 bytes")
	ErrInvalidTokenChars = errors.New("token contains invalid characters, line breaks, or control codes")
	ErrMalformedApiKey   = errors.New("malformed API key format")
)

// RFC 6750 b64token syntax: 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
var bearerTokenRegex = regexp.MustCompile(`^[A-Za-z0-9\-._~+/]+=*$`)

// API Key format: prefix (e.g. mcp_live_) followed by 32+ hex/alphanumeric characters
var apiKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-]{8,128}$`)

// AuthCredentialType designates the protocol classification of the inbound token.
type AuthCredentialType string

const (
	CredentialTypeBearer AuthCredentialType = "BEARER"
	CredentialTypeApiKey AuthCredentialType = "API_KEY"
)

// ParsedAuthCredential encapsulates validated authorization credentials.
type ParsedAuthCredential struct {
	Type        AuthCredentialType `json:"type"`
	RawToken    string             `json:"-"`
	MaskedToken string             `json:"masked_token"`
}

// SanitizeHeaderString verifies that an HTTP header contains no CRLF sequences or ASCII control characters.
func SanitizeHeaderString(val string) (string, error) {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return "", nil
	}

	for i := 0; i < len(trimmed); i++ {
		b := trimmed[i]
		if b < 32 || b == 127 {
			return "", ErrInvalidTokenChars
		}
	}
	return trimmed, nil
}

// MaskToken redacts sensitive portions of a token for secure audit logging.
func MaskToken(token string) string {
	clean := strings.TrimSpace(token)
	if len(clean) == 0 {
		return "<empty>"
	}
	if len(clean) <= 8 {
		return "***"
	}
	// Preserve up to first 6 chars and last 4 chars
	prefixLen := 6
	if len(clean) < 12 {
		prefixLen = len(clean) / 3
	}
	return fmt.Sprintf("%s...%s", clean[:prefixLen], clean[len(clean)-4:])
}

// ParseAuthorizationHeader validates and extracts a Bearer token from the standard Authorization header.
func ParseAuthorizationHeader(rawHeader string) (*ParsedAuthCredential, error) {
	sanitized, err := SanitizeHeaderString(rawHeader)
	if err != nil {
		return nil, err
	}
	if sanitized == "" {
		return nil, ErrMissingAuthHeader
	}

	parts := strings.SplitN(sanitized, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, ErrInvalidAuthScheme
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return nil, ErrMissingAuthHeader
	}
	if len(token) > 4096 {
		return nil, ErrTokenTooLong
	}

	if !bearerTokenRegex.MatchString(token) {
		return nil, ErrInvalidTokenChars
	}

	return &ParsedAuthCredential{
		Type:        CredentialTypeBearer,
		RawToken:    token,
		MaskedToken: MaskToken(token),
	}, nil
}

// ParseApiKeyHeader validates and extracts a standalone API key (e.g. from X-API-Key or X-MCP-Key).
func ParseApiKeyHeader(rawKey string) (*ParsedAuthCredential, error) {
	sanitized, err := SanitizeHeaderString(rawKey)
	if err != nil {
		return nil, err
	}
	if sanitized == "" {
		return nil, ErrMissingAuthHeader
	}
	if len(sanitized) > 512 {
		return nil, ErrTokenTooLong
	}

	if !apiKeyRegex.MatchString(sanitized) {
		return nil, ErrMalformedApiKey
	}

	return &ParsedAuthCredential{
		Type:        CredentialTypeApiKey,
		RawToken:    sanitized,
		MaskedToken: MaskToken(sanitized),
	}, nil
}
