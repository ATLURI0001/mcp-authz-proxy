package gateway

import (
	"sync"
	"time"
)

// RateLimiter defines the token bucket contract for incoming proxy requests.
type RateLimiter interface {
	Allow(clientKey string) bool
}

// SimpleRateLimiter implements an in-memory client rate limiter with time window.
type SimpleRateLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	maxCalls int
	history  map[string][]time.Time
}

// NewSimpleRateLimiter instantiates a SimpleRateLimiter.
func NewSimpleRateLimiter(maxCalls int, window time.Duration) *SimpleRateLimiter {
	return &SimpleRateLimiter{
		window:   window,
		maxCalls: maxCalls,
		history:  make(map[string][]time.Time),
	}
}

// Allow determines if the clientKey has remaining request quota.
func (l *SimpleRateLimiter) Allow(clientKey string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	var filtered []time.Time
	for _, t := range l.history[clientKey] {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}

	if len(filtered) >= l.maxCalls {
		l.history[clientKey] = filtered
		return false
	}

	l.history[clientKey] = append(filtered, now)
	return true
}
