package auth

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrRotaryEmptyToken   = errors.New("token identifier or payload cannot be empty")
	ErrRotaryPastExpiry   = errors.New("token expiration timestamp must be in the future")
	ErrRotaryDuplicate    = errors.New("token fingerprint is already registered in active rotary buckets")
)

// RotaryEntry stores cryptographic fingerprint and revocation context for a token.
type RotaryEntry struct {
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	RevokedAt   time.Time `json:"revoked_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Reason      string    `json:"reason"`
}

// RotaryBucket stores revocations partitioned into a specific expiration epoch window.
type RotaryBucket struct {
	EpochIndex int64                  `json:"epoch_index"`
	ExpiresAt  time.Time              `json:"expires_at"`
	Entries    map[string]RotaryEntry `json:"entries"`
}

// RotaryTelemetry provides operational metrics for the denylist.
type RotaryTelemetry struct {
	ActiveBuckets       int   `json:"active_buckets"`
	TotalActiveEntries  int   `json:"total_active_entries"`
	RevokedTotal        int64 `json:"revoked_total"`
	ChecksTotal         int64 `json:"checks_total"`
	DenylistHitsTotal   int64 `json:"denylist_hits_total"`
	DenylistMissesTotal int64 `json:"denylist_misses_total"`
	EvictedBucketsTotal int64 `json:"evicted_buckets_total"`
}

// TokenRevocationRotary manages time-partitioned token denylist buckets with O(1) epoch pruning.
type TokenRevocationRotary struct {
	mu             sync.RWMutex
	bucketDuration time.Duration
	buckets        map[int64]*RotaryBucket
	clockFn        func() time.Time

	revokedTotal        int64
	checksTotal         int64
	hitsTotal           int64
	missesTotal         int64
	evictedBucketsTotal int64
}

// NewTokenRevocationRotary initializes a time-partitioned rotary with the given bucket duration.
func NewTokenRevocationRotary(bucketDuration time.Duration) *TokenRevocationRotary {
	if bucketDuration < 10*time.Second {
		bucketDuration = 5 * time.Minute
	}
	return &TokenRevocationRotary{
		bucketDuration: bucketDuration,
		buckets:        make(map[int64]*RotaryBucket),
		clockFn:        time.Now,
	}
}

// Revoke places a token fingerprint into the appropriate expiration epoch bucket.
func (r *TokenRevocationRotary) Revoke(tokenOrJTI, subject string, expiresAt time.Time, reason string) (string, error) {
	trimmed := strings.TrimSpace(tokenOrJTI)
	if trimmed == "" {
		return "", ErrRotaryEmptyToken
	}

	now := r.clockFn().UTC()
	if !expiresAt.After(now) {
		return "", ErrRotaryPastExpiry
	}

	fingerprint := HashToken(trimmed)
	bucketSec := int64(r.bucketDuration.Seconds())
	epochIdx := expiresAt.Unix() / bucketSec

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if already revoked across any active bucket
	for _, b := range r.buckets {
		if _, exists := b.Entries[fingerprint]; exists {
			return fingerprint, ErrRotaryDuplicate
		}
	}

	bucket, exists := r.buckets[epochIdx]
	if !exists {
		bucket = &RotaryBucket{
			EpochIndex: epochIdx,
			ExpiresAt:  time.Unix((epochIdx+1)*bucketSec, 0).UTC(),
			Entries:    make(map[string]RotaryEntry),
		}
		r.buckets[epochIdx] = bucket
	}

	cleanSubject := strings.TrimSpace(subject)
	if cleanSubject == "" {
		cleanSubject = "anonymous"
	}
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		cleanReason = "UNSPECIFIED"
	}

	bucket.Entries[fingerprint] = RotaryEntry{
		Fingerprint: fingerprint,
		Subject:     cleanSubject,
		RevokedAt:   now,
		ExpiresAt:   expiresAt.UTC(),
		Reason:      cleanReason,
	}

	atomic.AddInt64(&r.revokedTotal, 1)
	return fingerprint, nil
}

// IsRevoked checks if a token or JTI is present in any non-expired rotary bucket.
func (r *TokenRevocationRotary) IsRevoked(tokenOrJTI string) bool {
	trimmed := strings.TrimSpace(tokenOrJTI)
	if trimmed == "" {
		return false
	}

	fingerprint := HashToken(trimmed)
	atomic.AddInt64(&r.checksTotal, 1)

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, bucket := range r.buckets {
		if _, found := bucket.Entries[fingerprint]; found {
			atomic.AddInt64(&r.hitsTotal, 1)
			return true
		}
	}

	atomic.AddInt64(&r.missesTotal, 1)
	return false
}

// Rotate evicts all buckets whose expiration timestamp has elapsed.
// Returns the count of purged entries.
func (r *TokenRevocationRotary) Rotate(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	purgedEntries := 0
	for epochIdx, bucket := range r.buckets {
		if !bucket.ExpiresAt.After(now) {
			purgedEntries += len(bucket.Entries)
			delete(r.buckets, epochIdx)
			atomic.AddInt64(&r.evictedBucketsTotal, 1)
		}
	}

	return purgedEntries
}

// GetTelemetry compiles active bucket counts, entry totals, and hit/miss statistics.
func (r *TokenRevocationRotary) GetTelemetry() RotaryTelemetry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	totalEntries := 0
	for _, b := range r.buckets {
		totalEntries += len(b.Entries)
	}

	return RotaryTelemetry{
		ActiveBuckets:       len(r.buckets),
		TotalActiveEntries:  totalEntries,
		RevokedTotal:        atomic.LoadInt64(&r.revokedTotal),
		ChecksTotal:         atomic.LoadInt64(&r.checksTotal),
		DenylistHitsTotal:   atomic.LoadInt64(&r.hitsTotal),
		DenylistMissesTotal: atomic.LoadInt64(&r.missesTotal),
		EvictedBucketsTotal: atomic.LoadInt64(&r.evictedBucketsTotal),
	}
}

// ExportPrometheusMetrics renders Prometheus exposition format metrics for the denylist rotary.
func (r *TokenRevocationRotary) ExportPrometheusMetrics() string {
	telemetry := r.GetTelemetry()
	var sb strings.Builder

	sb.WriteString("# HELP authz_token_revocations_total Total tokens placed in revocation denylist\n")
	sb.WriteString("# TYPE authz_token_revocations_total counter\n")
	sb.WriteString(fmt.Sprintf("authz_token_revocations_total %d\n", telemetry.RevokedTotal))

	sb.WriteString("# HELP authz_token_denylist_checks_total Total token revocation validation checks\n")
	sb.WriteString("# TYPE authz_token_denylist_checks_total counter\n")
	sb.WriteString(fmt.Sprintf("authz_token_denylist_checks_total{result=\"hit\"} %d\n", telemetry.DenylistHitsTotal))
	sb.WriteString(fmt.Sprintf("authz_token_denylist_checks_total{result=\"miss\"} %d\n", telemetry.DenylistMissesTotal))

	sb.WriteString("# HELP authz_token_active_denylist_entries Current active revoked tokens across buckets\n")
	sb.WriteString("# TYPE authz_token_active_denylist_entries gauge\n")
	sb.WriteString(fmt.Sprintf("authz_token_active_denylist_entries %d\n", telemetry.TotalActiveEntries))

	return sb.String()
}
