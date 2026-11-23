package auth

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrEmptyNonce indicates that a supplied nonce is empty or whitespace only.
	ErrEmptyNonce = errors.New("mcp: nonce cannot be empty")
	// ErrInvalidNonceFormat indicates that a nonce contains illegal characters or invalid length.
	ErrInvalidNonceFormat = errors.New("mcp: invalid nonce format; must be 16-128 alphanumeric, dash, or underscore characters")
	// ErrTimestampExpired indicates that the request timestamp is older than the allowed tolerance window.
	ErrTimestampExpired = errors.New("mcp: request timestamp has expired beyond allowed clock skew")
	// ErrTimestampFutureDrift indicates that the request timestamp is in the future beyond allowed tolerance.
	ErrTimestampFutureDrift = errors.New("mcp: request timestamp is too far in the future")
	// ErrReplayDetected indicates that this exact nonce has already been processed within the validity window.
	ErrReplayDetected = errors.New("mcp: replay attack detected; nonce has already been utilized")
	// ErrCapacityExceeded indicates the nonce cache reached its maximum allowed entries.
	ErrCapacityExceeded = errors.New("mcp: replay cache capacity exceeded")
)

var validNonceRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{16,128}$`)

// ReplayProtectorConfig configures the nonce validation and eviction behavior.
type ReplayProtectorConfig struct {
	// ClockSkewTolerance is the acceptable age and future drift for timestamps (default 5 minutes).
	ClockSkewTolerance time.Duration
	// MaxEntries is the upper bound on active nonces to avoid unbounded memory growth (default 50,000).
	MaxEntries int
	// NowFunc allows injecting mock time in unit tests.
	NowFunc func() time.Time
}

// DefaultReplayProtectorConfig provides production-ready security defaults.
func DefaultReplayProtectorConfig() ReplayProtectorConfig {
	return ReplayProtectorConfig{
		ClockSkewTolerance: 5 * time.Minute,
		MaxEntries:         50000,
		NowFunc:            time.Now,
	}
}

type nonceRecord struct {
	expiresAt time.Time
}

// ReplayProtectorStats contains operational metrics for monitoring.
type ReplayProtectorStats struct {
	TotalEvaluated uint64
	ReplaysBlocked uint64
	ExpiredBlocked uint64
	ActiveEntries  int
}

// ReplayProtector provides thread-safe cryptographic nonce validation and replay prevention.
type ReplayProtector struct {
	mu     sync.RWMutex
	config ReplayProtectorConfig
	cache  map[string]nonceRecord

	totalEvaluated atomic.Uint64
	replaysBlocked atomic.Uint64
	expiredBlocked atomic.Uint64
}

// NewReplayProtector initializes a new replay mitigation engine with the provided config.
func NewReplayProtector(cfg ReplayProtectorConfig) *ReplayProtector {
	if cfg.ClockSkewTolerance <= 0 {
		cfg.ClockSkewTolerance = 5 * time.Minute
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 50000
	}
	if cfg.NowFunc == nil {
		cfg.NowFunc = time.Now
	}

	return &ReplayProtector{
		config: cfg,
		cache:  make(map[string]nonceRecord),
	}
}

// ValidateNonce inspects the nonce, tenantID, clientID, and timestamp for replay signatures.
// Returns nil if the nonce is valid and registers it for future collision checks.
func (rp *ReplayProtector) ValidateNonce(tenantID, clientID, nonce string, requestTime time.Time) error {
	rp.totalEvaluated.Add(1)

	if len(nonce) == 0 {
		return ErrEmptyNonce
	}

	if !validNonceRegex.MatchString(nonce) {
		return ErrInvalidNonceFormat
	}

	now := rp.config.NowFunc()
	skew := rp.config.ClockSkewTolerance

	// Verify timestamp expiration
	if requestTime.Before(now.Add(-skew)) {
		rp.expiredBlocked.Add(1)
		return ErrTimestampExpired
	}

	// Verify future clock drift
	if requestTime.After(now.Add(skew)) {
		rp.expiredBlocked.Add(1)
		return ErrTimestampFutureDrift
	}

	// Compound key isolates nonces by tenant and client identity
	key := fmt.Sprintf("%s:%s:%s", tenantID, clientID, nonce)

	rp.mu.Lock()
	defer rp.mu.Unlock()

	// Check existing nonce record
	if rec, exists := rp.cache[key]; exists {
		if now.Before(rec.expiresAt) {
			rp.replaysBlocked.Add(1)
			return ErrReplayDetected
		}
		// Expired record can be safely overwritten
	}

	// Check capacity guard before insertion
	if len(rp.cache) >= rp.config.MaxEntries {
		// Attempt instant sweep of expired entries
		rp.sweepExpiredLocked(now)
		if len(rp.cache) >= rp.config.MaxEntries {
			return ErrCapacityExceeded
		}
	}

	// Store with expiration matching clock skew window
	rp.cache[key] = nonceRecord{
		expiresAt: requestTime.Add(skew),
	}

	return nil
}

// EvictExpired manually purges stale nonces whose validity window has passed.
func (rp *ReplayProtector) EvictExpired() int {
	now := rp.config.NowFunc()
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return rp.sweepExpiredLocked(now)
}

func (rp *ReplayProtector) sweepExpiredLocked(now time.Time) int {
	evicted := 0
	for k, v := range rp.cache {
		if now.After(v.expiresAt) {
			delete(rp.cache, k)
			evicted++
		}
	}
	return evicted
}

// Stats returns current operational telemetry counters.
func (rp *ReplayProtector) Stats() ReplayProtectorStats {
	rp.mu.RLock()
	active := len(rp.cache)
	rp.mu.RUnlock()

	return ReplayProtectorStats{
		TotalEvaluated: rp.totalEvaluated.Load(),
		ReplaysBlocked: rp.replaysBlocked.Load(),
		ExpiredBlocked: rp.expiredBlocked.Load(),
		ActiveEntries:  active,
	}
}

// Clear resets the internal cache.
func (rp *ReplayProtector) Clear() {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.cache = make(map[string]nonceRecord)
}
