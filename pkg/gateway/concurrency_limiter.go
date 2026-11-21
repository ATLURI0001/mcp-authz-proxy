package gateway

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrConcurrencyLimitReached = errors.New("concurrency_limiter: client concurrency limit exceeded")
	ErrQueueFull               = errors.New("concurrency_limiter: wait queue capacity exceeded")
	ErrAcquireTimeout          = errors.New("concurrency_limiter: acquire timed out")
)

type clientConcurrencyState struct {
	activeWorkers int64
	maxLimit      int64
	minLimit      int64
	lastUpdated   time.Time
}

// ConcurrencyLimiterConfig defines parameters for dynamic concurrency management.
type ConcurrencyLimiterConfig struct {
	DefaultMaxConcurrency int64
	MinConcurrency        int64
	MaxQueueSize          int64
	TargetLatencySLA      time.Duration
	BackpressureStep      int64
}

func DefaultConcurrencyConfig() ConcurrencyLimiterConfig {
	return ConcurrencyLimiterConfig{
		DefaultMaxConcurrency: 50,
		MinConcurrency:        5,
		MaxQueueSize:          100,
		TargetLatencySLA:      200 * time.Millisecond,
		BackpressureStep:      2,
	}
}

// ConcurrencyStats provides operational diagnostics.
type ConcurrencyStats struct {
	TotalAdmitted  uint64
	TotalRejected  uint64
	TotalThrottled uint64
	ActiveClients  int
}

// AdaptiveConcurrencyLimiter implements a self-tuning concurrency governor per client key.
type AdaptiveConcurrencyLimiter struct {
	cfg   ConcurrencyLimiterConfig
	mu    sync.RWMutex
	state map[string]*clientConcurrencyState

	stats struct {
		admitted  atomic.Uint64
		rejected  atomic.Uint64
		throttled atomic.Uint64
	}
}

// NewAdaptiveConcurrencyLimiter initializes a limiter with adaptive feedback.
func NewAdaptiveConcurrencyLimiter(cfg ConcurrencyLimiterConfig) *AdaptiveConcurrencyLimiter {
	if cfg.DefaultMaxConcurrency <= 0 {
		cfg.DefaultMaxConcurrency = DefaultConcurrencyConfig().DefaultMaxConcurrency
	}
	if cfg.MinConcurrency <= 0 {
		cfg.MinConcurrency = DefaultConcurrencyConfig().MinConcurrency
	}
	if cfg.TargetLatencySLA <= 0 {
		cfg.TargetLatencySLA = DefaultConcurrencyConfig().TargetLatencySLA
	}
	if cfg.BackpressureStep <= 0 {
		cfg.BackpressureStep = DefaultConcurrencyConfig().BackpressureStep
	}

	return &AdaptiveConcurrencyLimiter{
		cfg:   cfg,
		state: make(map[string]*clientConcurrencyState),
	}
}

func (l *AdaptiveConcurrencyLimiter) getOrCreateClientState(clientKey string) *clientConcurrencyState {
	l.mu.Lock()
	defer l.mu.Unlock()

	cs, exists := l.state[clientKey]
	if !exists {
		cs = &clientConcurrencyState{
			activeWorkers: 0,
			maxLimit:      l.cfg.DefaultMaxConcurrency,
			minLimit:      l.cfg.MinConcurrency,
			lastUpdated:   time.Now(),
		}
		l.state[clientKey] = cs
	}
	return cs
}

// TryAcquire attempts non-blocking acquisition of a concurrency slot for clientKey.
func (l *AdaptiveConcurrencyLimiter) TryAcquire(clientKey string) (bool, error) {
	if clientKey == "" {
		clientKey = "default"
	}

	cs := l.getOrCreateClientState(clientKey)

	l.mu.Lock()
	defer l.mu.Unlock()

	if cs.activeWorkers >= cs.maxLimit {
		l.stats.rejected.Add(1)
		return false, ErrConcurrencyLimitReached
	}

	cs.activeWorkers++
	l.stats.admitted.Add(1)
	return true, nil
}

// Release releases an active worker slot back to the client pool.
func (l *AdaptiveConcurrencyLimiter) Release(clientKey string) {
	if clientKey == "" {
		clientKey = "default"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if cs, exists := l.state[clientKey]; exists && cs.activeWorkers > 0 {
		cs.activeWorkers--
	}
}

// RecordLatency feeds execution latency back into the adaptive governor, tuning max concurrency.
func (l *AdaptiveConcurrencyLimiter) RecordLatency(clientKey string, latency time.Duration) {
	if clientKey == "" {
		clientKey = "default"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	cs, exists := l.state[clientKey]
	if !exists {
		return
	}

	cs.lastUpdated = time.Now()

	// If observed latency breaches target SLA, multiplicatively decrease max concurrency
	if latency > l.cfg.TargetLatencySLA {
		l.stats.throttled.Add(1)
		newLimit := cs.maxLimit - l.cfg.BackpressureStep
		if newLimit < cs.minLimit {
			newLimit = cs.minLimit
		}
		cs.maxLimit = newLimit
	} else if cs.maxLimit < l.cfg.DefaultMaxConcurrency {
		// Latency is within SLA: additively recover limit
		cs.maxLimit++
	}
}

// GetClientLimit returns current active concurrency limit for clientKey.
func (l *AdaptiveConcurrencyLimiter) GetClientLimit(clientKey string) int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if cs, exists := l.state[clientKey]; exists {
		return cs.maxLimit
	}
	return l.cfg.DefaultMaxConcurrency
}

// GetActiveWorkers returns current in-flight workers for clientKey.
func (l *AdaptiveConcurrencyLimiter) GetActiveWorkers(clientKey string) int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if cs, exists := l.state[clientKey]; exists {
		return cs.activeWorkers
	}
	return 0
}

// Stats returns diagnostic metrics.
func (l *AdaptiveConcurrencyLimiter) Stats() ConcurrencyStats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return ConcurrencyStats{
		TotalAdmitted:  l.stats.admitted.Load(),
		TotalRejected:  l.stats.rejected.Load(),
		TotalThrottled: l.stats.throttled.Load(),
		ActiveClients:  len(l.state),
	}
}
