package gateway

import (
	"errors"
	"testing"
	"time"
)

func TestAdaptiveConcurrencyLimiter_AcquireAndRelease(t *testing.T) {
	cfg := ConcurrencyLimiterConfig{
		DefaultMaxConcurrency: 3,
		MinConcurrency:        1,
		TargetLatencySLA:      100 * time.Millisecond,
		BackpressureStep:      1,
	}
	limiter := NewAdaptiveConcurrencyLimiter(cfg)

	// Acquire up to limit
	for i := 0; i < 3; i++ {
		ok, err := limiter.TryAcquire("client-1")
		if !ok || err != nil {
			t.Fatalf("expected successful acquire at %d, got ok=%v, err=%v", i, ok, err)
		}
	}

	// 4th acquire should fail
	ok, err := limiter.TryAcquire("client-1")
	if ok || !errors.Is(err, ErrConcurrencyLimitReached) {
		t.Fatalf("expected ErrConcurrencyLimitReached, got ok=%v, err=%v", ok, err)
	}

	// Release 1 worker
	limiter.Release("client-1")
	if limiter.GetActiveWorkers("client-1") != 2 {
		t.Errorf("expected 2 active workers after release, got %d", limiter.GetActiveWorkers("client-1"))
	}

	// Can acquire again
	ok, err = limiter.TryAcquire("client-1")
	if !ok || err != nil {
		t.Fatalf("expected successful acquire after release")
	}
}

func TestAdaptiveConcurrencyLimiter_AdaptiveBackpressureAndRecovery(t *testing.T) {
	cfg := ConcurrencyLimiterConfig{
		DefaultMaxConcurrency: 5,
		MinConcurrency:        2,
		TargetLatencySLA:      50 * time.Millisecond,
		BackpressureStep:      2,
	}
	limiter := NewAdaptiveConcurrencyLimiter(cfg)

	// Initialize state
	_, _ = limiter.TryAcquire("client-adaptive")
	limiter.Release("client-adaptive")

	initialLimit := limiter.GetClientLimit("client-adaptive")
	if initialLimit != 5 {
		t.Fatalf("expected initial limit 5, got %d", initialLimit)
	}

	// Report high latency (breach SLA: 100ms > 50ms)
	limiter.RecordLatency("client-adaptive", 100*time.Millisecond)

	// Limit should decrease by backpressureStep (5 - 2 = 3)
	reducedLimit := limiter.GetClientLimit("client-adaptive")
	if reducedLimit != 3 {
		t.Fatalf("expected limit reduced to 3, got %d", reducedLimit)
	}

	// Another high latency drops to MinConcurrency (2)
	limiter.RecordLatency("client-adaptive", 120*time.Millisecond)
	floorLimit := limiter.GetClientLimit("client-adaptive")
	if floorLimit != 2 {
		t.Fatalf("expected limit clamped at min 2, got %d", floorLimit)
	}

	// Report low latency (within SLA: 20ms < 50ms) -> recovery
	limiter.RecordLatency("client-adaptive", 20*time.Millisecond)
	recoveredLimit := limiter.GetClientLimit("client-adaptive")
	if recoveredLimit != 3 {
		t.Fatalf("expected recovered limit 3, got %d", recoveredLimit)
	}

	stats := limiter.Stats()
	if stats.TotalThrottled != 2 {
		t.Errorf("expected 2 throttled events, got %d", stats.TotalThrottled)
	}
}
