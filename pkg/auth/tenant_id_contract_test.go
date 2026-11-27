package auth

import "testing"

func TestValidateTenantID(t *testing.T) {
	if err := ValidateTenantID("tenant-01"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ValidateTenantID(""); err == nil {
		t.Fatal("expected error for empty tenant id")
	}
}
