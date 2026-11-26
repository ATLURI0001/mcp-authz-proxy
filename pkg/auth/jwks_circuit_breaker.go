package auth

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrJwksCircuitOpen = errors.New("jwks: identity provider refresh circuit open, serving cached keys")
)

// JwksCircuitBreaker protects JWKS key fetch endpoints from upstream IdP outages.
type JwksCircuitBreaker struct {
	mu                   sync.RWMutex
	failureThreshold     int
	recoveryThreshold    int
	cooldown             time.Duration
	state                string
	consecutiveFailures  int
	consecutiveSuccesses int
	tripTime             time.Time
	cachedKeys           map[string]string
}

// NewJwksCircuitBreaker creates a resilient JWKS key fetcher circuit breaker.
func NewJwksCircuitBreaker(failureThreshold int, recoveryThreshold int, cooldown time.Duration) *JwksCircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = 3
	}
	if recoveryThreshold <= 0 {
		recoveryThreshold = 2
	}
	if cooldown <= 0 {
		cooldown = 1 * time.Second
	}
	return &JwksCircuitBreaker{
		failureThreshold:  failureThreshold,
		recoveryThreshold: recoveryThreshold,
		cooldown:          cooldown,
		state:             "CLOSED",
		cachedKeys:        make(map[string]string),
	}
}

// FetchKeys executes remote JWKS fetch with cached fallback on failure or OPEN state.
func (cb *JwksCircuitBreaker) FetchKeys(fetcher func() (map[string]string, error)) (map[string]string, bool, error) {
	cb.mu.Lock()
	if cb.state == "OPEN" {
		if time.Since(cb.tripTime) >= cb.cooldown {
			cb.state = "HALF_OPEN"
			cb.consecutiveSuccesses = 0
		} else {
			keysCopy := copyKeys(cb.cachedKeys)
			cb.mu.Unlock()
			return keysCopy, true, ErrJwksCircuitOpen
		}
	}
	cb.mu.Unlock()

	keys, err := fetcher()
	if err != nil {
		cb.recordFailure()
		cb.mu.RLock()
		keysCopy := copyKeys(cb.cachedKeys)
		cb.mu.RUnlock()
		return keysCopy, true, err
	}

	cb.recordSuccess(keys)
	return keys, false, nil
}

func (cb *JwksCircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.consecutiveFailures++
	cb.consecutiveSuccesses = 0
	if cb.state == "HALF_OPEN" || cb.consecutiveFailures >= cb.failureThreshold {
		cb.state = "OPEN"
		cb.tripTime = time.Now()
	}
}

func (cb *JwksCircuitBreaker) recordSuccess(keys map[string]string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if len(keys) > 0 {
		cb.cachedKeys = copyKeys(keys)
	}
	if cb.state == "HALF_OPEN" {
		cb.consecutiveSuccesses++
		if cb.consecutiveSuccesses >= cb.recoveryThreshold {
			cb.state = "CLOSED"
			cb.consecutiveFailures = 0
		}
	} else {
		cb.consecutiveFailures = 0
	}
}

func copyKeys(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
