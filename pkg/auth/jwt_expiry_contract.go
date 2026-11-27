package auth

import (
	"fmt"
	"time"
)

// ValidateJwtExpiry enforces non-expired exp claim with optional clock skew.
func ValidateJwtExpiry(expUnix int64, now time.Time, skew time.Duration) error {
	if expUnix <= 0 {
		return fmt.Errorf("contract violation: exp must be positive")
	}
	if now.Add(-skew).Unix() >= expUnix {
		return fmt.Errorf("contract violation: token expired at %d", expUnix)
	}
	return nil
}
