package auth

import (
	"testing"
	"time"
)

func TestValidateTokenExpiry(t *testing.T) {
	if err := ValidateTokenExpiry(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ValidateTokenExpiry(time.Now().Add(-time.Hour)); err == nil {
		t.Fatal("expected error for expired token")
	}
}
