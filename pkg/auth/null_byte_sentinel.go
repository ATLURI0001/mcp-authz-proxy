package auth

import (
	"fmt"
	"strings"
)

// AssertNoNullByte rejects strings containing NUL bytes.
func AssertNoNullByte(s string) error {
	if strings.ContainsRune(s, '\x00') {
		return fmt.Errorf("sentinel violation: null byte detected in authz input")
	}
	return nil
}
