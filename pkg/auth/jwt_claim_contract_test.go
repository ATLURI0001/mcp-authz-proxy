package auth

import "testing"

func TestJwtClaimContract(t *testing.T) {
	c := NewJwtClaimContract([]string{"sub", "iss"})
	if err := c.Validate(map[string]string{"sub": "u1", "iss": "auth"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(map[string]string{"sub": "u1"}); err == nil {
		t.Fatal("expected error for missing iss claim")
	}
}
