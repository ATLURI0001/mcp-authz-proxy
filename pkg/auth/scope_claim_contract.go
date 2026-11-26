package auth

import "fmt"

// ValidateScopeClaims ensures all required scopes are present in granted scopes.
func ValidateScopeClaims(granted, required []string) error {
	set := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		set[s] = struct{}{}
	}
	for _, req := range required {
		if _, ok := set[req]; !ok {
			return fmt.Errorf("contract violation: missing required scope %q", req)
		}
	}
	return nil
}
