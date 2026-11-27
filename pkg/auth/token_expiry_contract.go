package auth

import (
	"errors"
	"time"
)

var ErrTokenExpiredContract = errors.New("token expired")

// ValidateTokenExpiry returns error if the token is past its expiry.
func ValidateTokenExpiry(expiry time.Time) error {
	if time.Now().After(expiry) {
		return ErrTokenExpiredContract
	}
	return nil
}
