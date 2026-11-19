package auth

import "strings"

// ScopeSet manages parsed OAuth/OIDC permission scopes.
type ScopeSet map[string]struct{}

// ParseScopes splits whitespace-delimited scope strings into a lookup set.
func ParseScopes(scopeStr string) ScopeSet {
	set := make(ScopeSet)
	for _, s := range strings.Fields(scopeStr) {
		if s != "" {
			set[s] = struct{}{}
		}
	}
	return set
}

// Has checks if a required scope is present in the set.
func (s ScopeSet) Has(scope string) bool {
	_, ok := s[scope]
	return ok
}

// HasAll checks if all required scopes are satisfied.
func (s ScopeSet) HasAll(required ...string) bool {
	for _, req := range required {
		if !s.Has(req) {
			return false
		}
	}
	return true
}
