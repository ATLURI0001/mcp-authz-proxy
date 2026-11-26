package auth

import (
	"net/http"
	"strings"
)

// HeaderSmugglingSentinel detects duplicate Authorization headers, CRLF injection,
// and hop-by-hop header smuggling attempts (INC-2026-AUTHZ-1190).
type HeaderSmugglingSentinel struct{}

// InspectHeaders validates inbound HTTP headers for smuggling indicators.
func (s *HeaderSmugglingSentinel) InspectHeaders(h http.Header) (bool, string) {
	if authVals := h.Values("Authorization"); len(authVals) > 1 {
		return false, "ERR_DUPLICATE_AUTHORIZATION_HEADER"
	}

	for name, vals := range h {
		for _, v := range vals {
			if strings.ContainsAny(v, "\r\n\x00") || strings.ContainsAny(name, "\r\n\x00") {
				return false, "ERR_CRLF_HEADER_INJECTION"
			}
		}
	}

	return true, "OK"
}
