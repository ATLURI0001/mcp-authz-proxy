package auth

import (
	"errors"
	"time"
)

var ErrPolicyEvalOpen = errors.New("policy eval circuit breaker open")

// PolicyEvalCircuitBreaker guards remote policy evaluation calls.
type PolicyEvalCircuitBreaker struct {
	threshold int
	cooldown  time.Duration
	failures  int
	openUntil time.Time
}

func NewPolicyEvalCircuitBreaker(threshold int, cooldown time.Duration) *PolicyEvalCircuitBreaker {
	return &PolicyEvalCircuitBreaker{threshold: threshold, cooldown: cooldown}
}

func (cb *PolicyEvalCircuitBreaker) Call(fn func() error) error {
	if time.Now().Before(cb.openUntil) {
		return ErrPolicyEvalOpen
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
