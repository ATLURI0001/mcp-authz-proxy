package auth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrCircuitOpen = errors.New("jwks circuit breaker is OPEN: upstream IdP unreachable")
)

type BreakerState string

const (
	BreakerClosed   BreakerState = "CLOSED"
	BreakerOpen     BreakerState = "OPEN"
	BreakerHalfOpen BreakerState = "HALF_OPEN"
)

type JWKSCircuitBreakerConfig struct {
	FailureThreshold      int
	RecoveryTimeout       time.Duration
	HalfOpenSuccessTrials int
	ServeStaleOnOpen      bool
}

func DefaultJWKSCircuitBreakerConfig() JWKSCircuitBreakerConfig {
	return JWKSCircuitBreakerConfig{
		FailureThreshold:      3,
		RecoveryTimeout:       10 * time.Second,
		HalfOpenSuccessTrials: 2,
		ServeStaleOnOpen:      true,
	}
}

type JWKSCircuitBreakerMetrics struct {
	State                BreakerState `json:"state"`
	ConsecutiveFailures  int          `json:"consecutive_failures"`
	TotalFetches         uint64       `json:"total_fetches"`
	FallbackInvocations  uint64       `json:"fallback_invocations"`
	StateTransitions     uint64       `json:"state_transitions"`
	LastFailureReason    string       `json:"last_failure_reason"`
	StaleKeyCount        int          `json:"stale_key_count"`
}

type JWKSCircuitBreaker struct {
	mu                  sync.RWMutex
	config              JWKSCircuitBreakerConfig
	fetcher             KeyFetcher
	state               BreakerState
	consecutiveFailures int
	halfOpenSuccesses   int
	openedAt            time.Time
	lastFailureReason   string

	staleKeys           map[string]crypto.PublicKey

	// Metrics
	totalFetches        uint64
	fallbackInvocations uint64
	stateTransitions    uint64
}

func NewJWKSCircuitBreaker(fetcher KeyFetcher, cfg JWKSCircuitBreakerConfig) *JWKSCircuitBreaker {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}
	if cfg.RecoveryTimeout <= 0 {
		cfg.RecoveryTimeout = 10 * time.Second
	}
	if cfg.HalfOpenSuccessTrials <= 0 {
		cfg.HalfOpenSuccessTrials = 2
	}

	return &JWKSCircuitBreaker{
		config:    cfg,
		fetcher:   fetcher,
		state:     BreakerClosed,
		staleKeys: make(map[string]crypto.PublicKey),
	}
}

func (cb *JWKSCircuitBreaker) State() BreakerState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.evalStateLocked()
	return cb.state
}

func (cb *JWKSCircuitBreaker) evalStateLocked() {
	if cb.state == BreakerOpen && time.Since(cb.openedAt) >= cb.config.RecoveryTimeout {
		cb.state = BreakerHalfOpen
		cb.halfOpenSuccesses = 0
		cb.stateTransitions++
	}
}

func (cb *JWKSCircuitBreaker) tripLocked(reason string) {
	if cb.state != BreakerOpen {
		cb.state = BreakerOpen
		cb.openedAt = time.Now()
		cb.lastFailureReason = reason
		cb.stateTransitions++
	}
}

func (cb *JWKSCircuitBreaker) resetLocked() {
	if cb.state != BreakerClosed {
		cb.state = BreakerClosed
		cb.consecutiveFailures = 0
		cb.halfOpenSuccesses = 0
		cb.stateTransitions++
	}
}

// FetchKeys executes upstream key fetching guarded by the circuit breaker.
// Returns: (keys, usedFallback, error)
func (cb *JWKSCircuitBreaker) FetchKeys(ctx context.Context) (map[string]crypto.PublicKey, bool, error) {
	cb.mu.Lock()
	cb.totalFetches++
	cb.evalStateLocked()

	if cb.state == BreakerOpen {
		if cb.config.ServeStaleOnOpen && len(cb.staleKeys) > 0 {
			cb.fallbackInvocations++
			keysCopy := make(map[string]crypto.PublicKey, len(cb.staleKeys))
			for k, v := range cb.staleKeys {
				keysCopy[k] = v
			}
			cb.mu.Unlock()
			return keysCopy, true, nil
		}
		reason := cb.lastFailureReason
		cb.mu.Unlock()
		return nil, false, fmt.Errorf("%w: %s", ErrCircuitOpen, reason)
	}
	cb.mu.Unlock()

	// Attempt fetch
	keys, err := cb.fetcher(ctx)
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.consecutiveFailures++
		cb.lastFailureReason = err.Error()

		if cb.state == BreakerHalfOpen || cb.consecutiveFailures >= cb.config.FailureThreshold {
			cb.tripLocked(err.Error())
		}

		if cb.config.ServeStaleOnOpen && len(cb.staleKeys) > 0 {
			cb.fallbackInvocations++
			keysCopy := make(map[string]crypto.PublicKey, len(cb.staleKeys))
			for k, v := range cb.staleKeys {
				keysCopy[k] = v
			}
			return keysCopy, true, nil
		}
		return nil, false, err
	}

	// Success
	if cb.state == BreakerHalfOpen {
		cb.halfOpenSuccesses++
		if cb.halfOpenSuccesses >= cb.config.HalfOpenSuccessTrials {
			cb.resetLocked()
		}
	} else if cb.state == BreakerClosed {
		cb.consecutiveFailures = 0
	}

	// Cache successful keys as stale fallback
	cb.staleKeys = make(map[string]crypto.PublicKey, len(keys))
	for k, v := range keys {
		cb.staleKeys[k] = v
	}

	return keys, false, nil
}

func (cb *JWKSCircuitBreaker) GetMetrics() JWKSCircuitBreakerMetrics {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return JWKSCircuitBreakerMetrics{
		State:               cb.state,
		ConsecutiveFailures: cb.consecutiveFailures,
		TotalFetches:        cb.totalFetches,
		FallbackInvocations: cb.fallbackInvocations,
		StateTransitions:    cb.stateTransitions,
		LastFailureReason:   cb.lastFailureReason,
		StaleKeyCount:       len(cb.staleKeys),
	}
}
