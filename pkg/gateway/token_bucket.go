package gateway

import (
	"math"
	"sync"
	"time"
)

// bucket tracks token level and replenishment timestamps for a single client.
type bucket struct {
	tokens     float64
	lastRefill time.Time
	lastAccess time.Time
}

// TokenBucketLimiter implements a high-throughput, thread-safe token bucket rate limiter
// supporting continuous replenishment, burst tolerances, and stale key eviction.
type TokenBucketLimiter struct {
	mu         sync.Mutex
	capacity   float64
	refillRate float64 // tokens per second
	ttl        time.Duration
	buckets    map[string]*bucket
}

// NewTokenBucketLimiter creates a new TokenBucketLimiter with the specified capacity,
// refill rate (tokens/sec), and idle key expiration TTL.
func NewTokenBucketLimiter(capacity float64, refillRate float64, ttl time.Duration) *TokenBucketLimiter {
	if capacity <= 0 {
		capacity = 1.0
	}
	if refillRate <= 0 {
		refillRate = 1.0
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &TokenBucketLimiter{
		capacity:   capacity,
		refillRate: refillRate,
		ttl:        ttl,
		buckets:    make(map[string]*bucket),
	}
}

// Allow determines if the clientKey has at least 1 token available, consuming it if so.
func (l *TokenBucketLimiter) Allow(clientKey string) bool {
	return l.AllowN(clientKey, 1.0)
}

// AllowN attempts to consume n tokens for the given clientKey. Returns true if permitted.
func (l *TokenBucketLimiter) AllowN(clientKey string, n float64) bool {
	if n <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, exists := l.buckets[clientKey]
	if !exists {
		b = &bucket{
			tokens:     l.capacity,
			lastRefill: now,
			lastAccess: now,
		}
		l.buckets[clientKey] = b
	} else {
		// Continuous linear replenishment
		elapsed := now.Sub(b.lastRefill).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(l.capacity, b.tokens+(elapsed*l.refillRate))
			b.lastRefill = now
		}
		b.lastAccess = now
	}

	if b.tokens >= n {
		b.tokens -= n
		return true
	}

	return false
}

// Tokens returns the current available tokens for clientKey without consuming any.
func (l *TokenBucketLimiter) Tokens(clientKey string) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, exists := l.buckets[clientKey]
	if !exists {
		return l.capacity
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		return math.Min(l.capacity, b.tokens+(elapsed*l.refillRate))
	}
	return b.tokens
}

// Cleanup scans and removes client buckets that have been inactive longer than the TTL.
// Returns the number of evicted client entries.
func (l *TokenBucketLimiter) Cleanup() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	evicted := 0
	for key, b := range l.buckets {
		if now.Sub(b.lastAccess) > l.ttl {
			delete(l.buckets, key)
			evicted++
		}
	}
	return evicted
}

// Capacity returns the maximum configured bucket capacity.
func (l *TokenBucketLimiter) Capacity() float64 {
	return l.capacity
}

// RefillRate returns the configured token replenishment rate per second.
func (l *TokenBucketLimiter) RefillRate() float64 {
	return l.refillRate
}
