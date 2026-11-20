package gateway

import (
	"errors"
	"sync"
	"time"
)

// CircuitState represents the current operating state of the circuit breaker.
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateHalfOpen
	StateOpen
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateHalfOpen:
		return "HALF_OPEN"
	case StateOpen:
		return "OPEN"
	default:
		return "UNKNOWN"
	}
}

var (
	ErrCircuitOpen = errors.New("circuit breaker is open: upstream service is degraded")
)

// CircuitBreakerConfig holds configuration parameters for the circuit breaker.
type CircuitBreakerConfig struct {
	MaxFailures      int           // Number of consecutive failures to trip circuit
	BaseCooldown     time.Duration // Base duration to stay in Open state before probing
	MaxCooldown      time.Duration // Maximum cooldown duration cap
	CanaryPassCount  int           // Number of consecutive successes in Half-Open to recover to Closed
}

// CircuitBreakerMetrics captures telemetry counters for monitoring.
type CircuitBreakerMetrics struct {
	TotalRequests       uint64
	TotalSuccesses      uint64
	TotalFailures       uint64
	ConsecutiveFailures int
	StateTransitions    uint64
	CurrentState        CircuitState
	LastTransition      time.Time
}

// CircuitBreaker protects downstream callers from failing upstream MCP services.
type CircuitBreaker struct {
	mu                  sync.RWMutex
	cfg                 CircuitBreakerConfig
	state               CircuitState
	consecutiveFailures int
	consecutiveCanaries int
	cooldownDuration    time.Duration
	lastFailureTime     time.Time
	lastTransitionTime  time.Time
	metrics             CircuitBreakerMetrics
}

// NewCircuitBreaker initializes a thread-safe circuit breaker with safe defaults.
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = 5
	}
	if cfg.BaseCooldown <= 0 {
		cfg.BaseCooldown = 5 * time.Second
	}
	if cfg.MaxCooldown <= 0 {
		cfg.MaxCooldown = 60 * time.Second
	}
	if cfg.CanaryPassCount <= 0 {
		cfg.CanaryPassCount = 2
	}

	now := time.Now()
	return &CircuitBreaker{
		cfg:                cfg,
		state:              StateClosed,
		cooldownDuration:   cfg.BaseCooldown,
		lastTransitionTime: now,
		metrics: CircuitBreakerMetrics{
			CurrentState:   StateClosed,
			LastTransition: now,
		},
	}
}

// Execute wraps an operation with circuit breaker protections.
func (cb *CircuitBreaker) Execute(op func() error) error {
	if err := cb.beforeExecution(); err != nil {
		return err
	}

	err := op()
	cb.afterExecution(err)
	return err
}

// beforeExecution checks if the operation is permitted given the current state.
func (cb *CircuitBreaker) beforeExecution() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.metrics.TotalRequests++
	now := time.Now()

	switch cb.state {
	case StateClosed:
		return nil

	case StateOpen:
		// Check if cooldown has elapsed to transition to Half-Open
		if now.Sub(cb.lastFailureTime) >= cb.cooldownDuration {
			cb.transitionTo(StateHalfOpen, now)
			cb.consecutiveCanaries = 0
			return nil
		}
		return ErrCircuitOpen

	case StateHalfOpen:
		// In Half-Open, allow probe requests
		return nil

	default:
		return nil
	}
}

// afterExecution updates circuit counters and transitions states based on outcome.
func (cb *CircuitBreaker) afterExecution(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	if err == nil {
		cb.metrics.TotalSuccesses++
		cb.onSuccess(now)
	} else {
		cb.metrics.TotalFailures++
		cb.onFailure(now)
	}
}

func (cb *CircuitBreaker) onSuccess(now time.Time) {
	switch cb.state {
	case StateClosed:
		cb.consecutiveFailures = 0

	case StateHalfOpen:
		cb.consecutiveCanaries++
		if cb.consecutiveCanaries >= cb.cfg.CanaryPassCount {
			// Sufficient canaries passed; fully recover to Closed
			cb.consecutiveFailures = 0
			cb.consecutiveCanaries = 0
			cb.cooldownDuration = cb.cfg.BaseCooldown // Reset cooldown backoff
			cb.transitionTo(StateClosed, now)
		}
	}
}

func (cb *CircuitBreaker) onFailure(now time.Time) {
	cb.lastFailureTime = now
	cb.consecutiveFailures++

	switch cb.state {
	case StateClosed:
		if cb.consecutiveFailures >= cb.cfg.MaxFailures {
			cb.transitionTo(StateOpen, now)
		}

	case StateHalfOpen:
		// Any failure during Half-Open immediately trips back to Open with exponential backoff
		newCooldown := cb.cooldownDuration * 2
		if newCooldown > cb.cfg.MaxCooldown {
			newCooldown = cb.cfg.MaxCooldown
		}
		cb.cooldownDuration = newCooldown
		cb.consecutiveCanaries = 0
		cb.transitionTo(StateOpen, now)
	}
}

func (cb *CircuitBreaker) transitionTo(newState CircuitState, now time.Time) {
	if cb.state == newState {
		return
	}
	cb.state = newState
	cb.lastTransitionTime = now
	cb.metrics.StateTransitions++
	cb.metrics.CurrentState = newState
	cb.metrics.LastTransition = now
}

// State returns the current circuit state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Metrics returns a snapshot copy of current metrics.
func (cb *CircuitBreaker) Metrics() CircuitBreakerMetrics {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	m := cb.metrics
	m.ConsecutiveFailures = cb.consecutiveFailures
	return m
}
