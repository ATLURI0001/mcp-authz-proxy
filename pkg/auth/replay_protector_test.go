package auth

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReplayProtector_ValidateNonce_BasicFlow(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	cfg := DefaultReplayProtectorConfig()
	cfg.NowFunc = func() time.Time { return now }

	rp := NewReplayProtector(cfg)

	nonce := "valid-nonce-token-12345678"
	err := rp.ValidateNonce("tenant-a", "client-1", nonce, now)
	if err != nil {
		t.Fatalf("expected valid nonce to pass, got: %v", err)
	}

	stats := rp.Stats()
	if stats.TotalEvaluated != 1 || stats.ActiveEntries != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	// Replay attempt must fail
	err = rp.ValidateNonce("tenant-a", "client-1", nonce, now)
	if err != ErrReplayDetected {
		t.Fatalf("expected ErrReplayDetected, got: %v", err)
	}

	stats = rp.Stats()
	if stats.ReplaysBlocked != 1 {
		t.Fatalf("expected 1 replay blocked, got: %d", stats.ReplaysBlocked)
	}
}

func TestReplayProtector_FormatAndSanitization(t *testing.T) {
	now := time.Now()
	rp := NewReplayProtector(DefaultReplayProtectorConfig())

	// Empty nonce
	if err := rp.ValidateNonce("t", "c", "", now); err != ErrEmptyNonce {
		t.Fatalf("expected ErrEmptyNonce, got: %v", err)
	}

	// Too short (<16 chars)
	if err := rp.ValidateNonce("t", "c", "short-nonce", now); err != ErrInvalidNonceFormat {
		t.Fatalf("expected ErrInvalidNonceFormat, got: %v", err)
	}

	// Invalid characters (spaces, semicolons)
	if err := rp.ValidateNonce("t", "c", "invalid nonce with spaces!", now); err != ErrInvalidNonceFormat {
		t.Fatalf("expected ErrInvalidNonceFormat, got: %v", err)
	}

	// Too long (>128 chars)
	longNonce := strings.Repeat("a", 129)
	if err := rp.ValidateNonce("t", "c", longNonce, now); err != ErrInvalidNonceFormat {
		t.Fatalf("expected ErrInvalidNonceFormat for oversized nonce, got: %v", err)
	}
}

func TestReplayProtector_TimestampClockSkew(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	cfg := DefaultReplayProtectorConfig()
	cfg.ClockSkewTolerance = 5 * time.Minute
	cfg.NowFunc = func() time.Time { return now }

	rp := NewReplayProtector(cfg)
	nonce := "skew-test-nonce-0000000001"

	// Request 6 minutes in the past (> 5 min tolerance)
	expiredTime := now.Add(-6 * time.Minute)
	if err := rp.ValidateNonce("t", "c", nonce, expiredTime); err != ErrTimestampExpired {
		t.Fatalf("expected ErrTimestampExpired, got: %v", err)
	}

	// Request 6 minutes in the future (> 5 min tolerance)
	futureTime := now.Add(6 * time.Minute)
	if err := rp.ValidateNonce("t", "c", nonce, futureTime); err != ErrTimestampFutureDrift {
		t.Fatalf("expected ErrTimestampFutureDrift, got: %v", err)
	}

	// Within tolerance (3 minutes old)
	validPast := now.Add(-3 * time.Minute)
	if err := rp.ValidateNonce("t", "c", nonce, validPast); err != nil {
		t.Fatalf("expected valid timestamp to pass, got: %v", err)
	}
}

func TestReplayProtector_MultiTenantIsolation(t *testing.T) {
	now := time.Now()
	rp := NewReplayProtector(DefaultReplayProtectorConfig())
	nonce := "shared-nonce-identifier-1234"

	// Tenant A, Client 1
	if err := rp.ValidateNonce("tenant-a", "client-1", nonce, now); err != nil {
		t.Fatalf("expected tenant-a to succeed, got: %v", err)
	}

	// Tenant B, Client 1 (different tenant, same nonce -> allowed)
	if err := rp.ValidateNonce("tenant-b", "client-1", nonce, now); err != nil {
		t.Fatalf("expected tenant-b to succeed, got: %v", err)
	}

	// Tenant A, Client 2 (different client, same nonce -> allowed)
	if err := rp.ValidateNonce("tenant-a", "client-2", nonce, now); err != nil {
		t.Fatalf("expected client-2 to succeed, got: %v", err)
	}
}

func TestReplayProtector_ExpirationAndEviction(t *testing.T) {
	currTime := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	cfg := DefaultReplayProtectorConfig()
	cfg.ClockSkewTolerance = 2 * time.Minute
	cfg.NowFunc = func() time.Time { return currTime }

	rp := NewReplayProtector(cfg)
	nonce := "eviction-test-nonce-1234567"

	if err := rp.ValidateNonce("t", "c", nonce, currTime); err != nil {
		t.Fatalf("expected initial nonce to pass, got: %v", err)
	}

	// Advance time past expiry window (3 minutes later)
	currTime = currTime.Add(3 * time.Minute)

	// Evict should purge the expired nonce
	evicted := rp.EvictExpired()
	if evicted != 1 {
		t.Fatalf("expected 1 evicted entry, got: %d", evicted)
	}

	// Now submitting the same nonce again with the new current time should succeed
	if err := rp.ValidateNonce("t", "c", nonce, currTime); err != nil {
		t.Fatalf("expected post-expiration nonce to succeed, got: %v", err)
	}
}

func TestReplayProtector_CapacityGuard(t *testing.T) {
	now := time.Now()
	cfg := ReplayProtectorConfig{
		ClockSkewTolerance: 10 * time.Minute,
		MaxEntries:         5,
		NowFunc:            func() time.Time { return now },
	}
	rp := NewReplayProtector(cfg)

	for i := 0; i < 5; i++ {
		nonce := fmt.Sprintf("capacity-nonce-%012d", i)
		if err := rp.ValidateNonce("t", "c", nonce, now); err != nil {
			t.Fatalf("insert %d failed: %v", i, err)
		}
	}

	// 6th entry should trigger ErrCapacityExceeded since none are expired
	nonceOverflow := "capacity-nonce-overflow-0001"
	if err := rp.ValidateNonce("t", "c", nonceOverflow, now); err != ErrCapacityExceeded {
		t.Fatalf("expected ErrCapacityExceeded, got: %v", err)
	}
}

func TestReplayProtector_ConcurrentAccess(t *testing.T) {
	now := time.Now()
	rp := NewReplayProtector(DefaultReplayProtectorConfig())

	var wg sync.WaitGroup
	workers := 20
	iterations := 50

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				nonce := fmt.Sprintf("worker-%02d-nonce-%010d", workerID, i)
				_ = rp.ValidateNonce("tenant-c", "client-c", nonce, now)
			}
		}(w)
	}

	wg.Wait()
	stats := rp.Stats()
	if stats.TotalEvaluated != uint64(workers*iterations) {
		t.Fatalf("expected %d evaluated, got: %d", workers*iterations, stats.TotalEvaluated)
	}
}
