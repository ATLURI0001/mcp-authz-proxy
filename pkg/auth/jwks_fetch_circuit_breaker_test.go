package auth

import (
	"errors"
	"testing"
	"time"
)

func TestJwksFetchCircuitBreaker(t *testing.T) {
	cb := NewJwksFetchCircuitBreaker(2, 5*time.Second)
	fail := func() error { return errors.New("jwks 503") }
	_ = cb.Call(fail)
	_ = cb.Call(fail)
	if err := cb.Call(func() error { return nil }); err != ErrJwksFetchOpen {
		t.Fatalf("expected ErrJwksFetchOpen, got %v", err)
	}
}
