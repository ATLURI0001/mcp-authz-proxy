package auth

import "testing"

func TestAuthDecisionRotary(t *testing.T) {
	r := NewAuthDecisionRotary(2)
	r.Push(true)
	r.Push(false)
	r.Push(true)
	if r.Count() != 2 {
		t.Fatalf("expected 2, got %d", r.Count())
	}
}
