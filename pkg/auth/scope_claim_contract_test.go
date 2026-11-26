package auth

import "testing"

func TestValidateScopeClaims(t *testing.T) {
	if err := ValidateScopeClaims([]string{"read", "write"}, []string{"read"}); err != nil {
		t.Fatalf("expected valid scopes, got %v", err)
	}
	if err := ValidateScopeClaims([]string{"read"}, []string{"admin"}); err == nil {
		t.Fatal("expected missing scope error")
	}
}
