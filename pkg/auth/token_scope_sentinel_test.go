package auth

import "testing"

func TestTokenScopeSentinel(t *testing.T) {
	s := NewTokenScopeSentinel()
	if !s.Check([]string{"read", "write"}, "read") {
		t.Fatal("expected read to be allowed")
	}
	if s.Check([]string{"read"}, "admin") {
		t.Fatal("expected admin to be denied")
	}
	if s.Violations() != 1 {
		t.Fatalf("expected 1 violation, got %d", s.Violations())
	}
}
