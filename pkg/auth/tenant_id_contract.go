package auth

import (
	"errors"
	"strings"
)

var ErrInvalidTenantIDContract = errors.New("invalid tenant id")

// ValidateTenantID ensures a non-empty tenant identifier without whitespace.
func ValidateTenantID(id string) error {
	if id == "" || strings.ContainsAny(id, " \t\n") {
		return ErrInvalidTenantIDContract
	}
	return nil
}
