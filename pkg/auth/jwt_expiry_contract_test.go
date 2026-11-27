package auth

import (
	"testing"
	"time"
)

func TestValidateJwtExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	if err := ValidateJwtExpiry(1060, now, 10*time.Second); err != nil {
		t.Fatalf("expected valid exp, got %v", err)
	}
	if err := ValidateJwtExpiry(900, now, 10*time.Second); err == nil {
		t.Fatal("expected expired token error")
	}
}
