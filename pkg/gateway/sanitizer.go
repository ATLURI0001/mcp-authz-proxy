package gateway

import (
	"errors"
	"net/http"
	"path"
	"regexp"
	"strings"
)

var (
	ErrInvalidHeaderName   = errors.New("invalid HTTP header name: contains illegal characters")
	ErrCRLFInjection       = errors.New("CRLF injection detected in header value")
	ErrNullByteInjection   = errors.New("null byte injection detected")
	ErrInvalidBearerFormat = errors.New("invalid authorization bearer token format")
	ErrPathTraversal       = errors.New("path traversal detected in target URI")
)

var (
	validHeaderNameRegex = regexp.MustCompile(`^[A-Za-z0-9\-_]+$`)
	validBearerTokenRegex = regexp.MustCompile(`^[A-Za-z0-9\-_.~+/]+=*$`)

	// Hop-by-hop headers per RFC 7230 §6.1
	hopByHopHeaders = map[string]bool{
		"connection":          true,
		"keep-alive":          true,
		"proxy-authenticate":  true,
		"proxy-authorization": true,
		"te":                  true,
		"trailer":             true,
		"trailers":            true,
		"transfer-encoding":   true,
		"upgrade":             true,
	}
)

// RequestSanitizer provides defensive contracts and sanitization for ingress gateway requests.
type RequestSanitizer struct {
	MaxHeaderLength int
}

// NewRequestSanitizer creates a new sanitizer with default limits.
func NewRequestSanitizer() *RequestSanitizer {
	return &RequestSanitizer{
		MaxHeaderLength: 8192,
	}
}

// SanitizeHeader verifies header key validity, strips trailing whitespace,
// and ensures absence of CRLF and null-byte injection payloads.
func (s *RequestSanitizer) SanitizeHeader(key, val string) (string, string, error) {
	trimmedKey := strings.TrimSpace(key)
	if trimmedKey == "" || !validHeaderNameRegex.MatchString(trimmedKey) {
		return "", "", ErrInvalidHeaderName
	}

	if strings.ContainsAny(val, "\r\n") {
		return "", "", ErrCRLFInjection
	}

	if strings.Contains(val, "\x00") {
		return "", "", ErrNullByteInjection
	}

	if len(val) > s.MaxHeaderLength {
		val = val[:s.MaxHeaderLength]
	}

	return trimmedKey, strings.TrimSpace(val), nil
}

// FilterHopByHopHeaders strips RFC 7230 hop-by-hop headers from request headers.
func (s *RequestSanitizer) FilterHopByHopHeaders(headers http.Header) http.Header {
	sanitized := make(http.Header)
	for k, vals := range headers {
		lowerKey := strings.ToLower(k)
		if hopByHopHeaders[lowerKey] {
			continue
		}
		// Also strip headers named in Connection header
		for _, v := range vals {
			cleanKey, cleanVal, err := s.SanitizeHeader(k, v)
			if err == nil {
				sanitized.Add(cleanKey, cleanVal)
			}
		}
	}
	return sanitized
}

// ExtractBearerToken validates the Authorization header contract and returns the clean token.
func (s *RequestSanitizer) ExtractBearerToken(authHeader string) (string, error) {
	if strings.ContainsAny(authHeader, "\r\n") {
		return "", ErrCRLFInjection
	}
	if strings.Contains(authHeader, "\x00") {
		return "", ErrNullByteInjection
	}

	trimmed := strings.TrimSpace(authHeader)
	if trimmed == "" {
		return "", ErrInvalidBearerFormat
	}

	parts := strings.SplitN(trimmed, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrInvalidBearerFormat
	}

	token := strings.TrimSpace(parts[1])
	if token == "" || !validBearerTokenRegex.MatchString(token) {
		return "", ErrInvalidBearerFormat
	}

	return token, nil
}

// SanitizeForwardedPath cleans and guards a forwarded URL path against traversal.
func (s *RequestSanitizer) SanitizeForwardedPath(rawPath string) (string, error) {
	if strings.Contains(rawPath, "\x00") {
		return "", ErrNullByteInjection
	}
	if strings.ContainsAny(rawPath, "\r\n") {
		return "", ErrCRLFInjection
	}

	// Normalize slashes
	cleaned := path.Clean(rawPath)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	// Check if path attempts to escape root
	if strings.Contains(rawPath, "..") {
		parts := strings.Split(rawPath, "/")
		depth := 0
		for _, p := range parts {
			if p == ".." {
				depth--
				if depth < 0 {
					return "", ErrPathTraversal
				}
			} else if p != "" && p != "." {
				depth++
			}
		}
	}

	return cleaned, nil
}
