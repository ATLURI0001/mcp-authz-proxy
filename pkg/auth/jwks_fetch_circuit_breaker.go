package auth

import (
	"errors"
	"time"
)

var ErrJwksFetchOpen = errors.New("JWKS fetch circuit breaker open")

// JwksFetchCircuitBreaker protects JWKS keyset fetches against upstream outages.
type JwksFetchCircuitBreaker struct {
	threshold int
	cooldown  time.Duration
	failures  int
	openUntil time.Time
}

func NewJwksFetchCircuitBreaker(threshold int, cooldown time.Duration) *JwksFetchCircuitBreaker {
	return &JwksFetchCircuitBreaker{threshold: threshold, cooldown: cooldown}
}

func (cb *JwksFetchCircuitBreaker) Call(fn func() error) error {
	if time.Now().Before(cb.openUntil) {
		return ErrJwksFetchOpen
	}
	if err := fn(); err != nil {
		cb.failures++
		if cb.failures >= cb.threshold {
			cb.openUntil = time.Now().Add(cb.cooldown)
			cb.failures = 0
		}
		return err
	}
	cb.failures = 0
	return nil
}
