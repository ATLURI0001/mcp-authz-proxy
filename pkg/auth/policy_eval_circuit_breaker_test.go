package auth

import (
	"errors"
	"testing"
	"time"
)

func TestPolicyEvalCircuitBreaker(t *testing.T) {
	cb := NewPolicyEvalCircuitBreaker(2, 5*time.Second)
	fail := func() error { return errors.New("opa 500") }
	_ = cb.Call(fail)
	_ = cb.Call(fail)
	if err := cb.Call(func() error { return nil }); err != ErrPolicyEvalOpen {
		t.Fatalf("expected ErrPolicyEvalOpen, got %v", err)
	}
}
