package auth

import (
	"fmt"
	"strings"
)

// AssertSafeAuthzPath rejects directory traversal sequences in request paths.
func AssertSafeAuthzPath(path string) error {
	if strings.Contains(path, "..") || strings.Contains(path, "\\") {
		return fmt.Errorf("sentinel violation: unsafe traversal sequence in path %q", path)
	}
	return nil
}
