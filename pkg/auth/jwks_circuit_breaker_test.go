package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"
)

func generateTestKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return priv.Public()
}

func TestJWKSCircuitBreaker_NominalExecution(t *testing.T) {
	key := generateTestKey(t)
	fetcher := func(ctx context.Context) (map[string]crypto.PublicKey, error) {
		return map[string]crypto.PublicKey{"key-1": key}, nil
	}

	cb := NewJWKSCircuitBreaker(fetcher, DefaultJWKSCircuitBreakerConfig())
	if cb.State() != BreakerClosed {
		t.Fatalf("expected initial state CLOSED, got %s", cb.State())
	}

	keys, usedFallback, err := cb.FetchKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usedFallback {
		t.Fatalf("expected usedFallback to be false")
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	metrics := cb.GetMetrics()
	if metrics.TotalFetches != 1 || metrics.FallbackInvocations != 0 {
		t.Fatalf("unexpected metrics: %+v", metrics)
	}
}

func TestJWKSCircuitBreaker_ThresholdTrippingAndFallback(t *testing.T) {
	key := generateTestKey(t)
	var failFetch bool

	fetcher := func(ctx context.Context) (map[string]crypto.PublicKey, error) {
		if failFetch {
			return nil, errors.New("upstream connection reset")
		}
		return map[string]crypto.PublicKey{"key-1": key}, nil
	}

	cfg := JWKSCircuitBreakerConfig{
		FailureThreshold:      2,
		RecoveryTimeout:       50 * time.Millisecond,
		HalfOpenSuccessTrials: 1,
		ServeStaleOnOpen:      true,
	}

	cb := NewJWKSCircuitBreaker(fetcher, cfg)

	// 1. Initial success seeds stale keys
	_, fallback, err := cb.FetchKeys(context.Background())
	if err != nil || fallback {
		t.Fatalf("seeding failed: err=%v fallback=%v", err, fallback)
	}

	// 2. Upstream starts failing
	failFetch = true

	// Failure 1: consecutive = 1, still CLOSED, serves stale
	keys, fallback, err := cb.FetchKeys(context.Background())
	if err != nil || !fallback {
		t.Fatalf("expected fallback on fail 1, got fallback=%v err=%v", fallback, err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 fallback key")
	}
	if cb.State() != BreakerClosed {
		t.Fatalf("expected state CLOSED after 1 fail, got %s", cb.State())
	}

	// Failure 2: reaches threshold 2 -> trips to OPEN, serves stale
	_, fallback, err = cb.FetchKeys(context.Background())
	if err != nil || !fallback {
		t.Fatalf("expected fallback on fail 2")
	}
	if cb.State() != BreakerOpen {
		t.Fatalf("expected state OPEN after 2 fails, got %s", cb.State())
	}

	// In OPEN state without calling fetcher, immediately returns fallback
	metrics := cb.GetMetrics()
	if metrics.State != BreakerOpen {
		t.Fatalf("expected metrics state OPEN")
	}

	// 3. Wait past RecoveryTimeout -> HALF_OPEN
	time.Sleep(60 * time.Millisecond)
	if cb.State() != BreakerHalfOpen {
		t.Fatalf("expected state HALF_OPEN after timeout, got %s", cb.State())
	}

	// 4. Upstream recovers
	failFetch = false
	keys, fallback, err = cb.FetchKeys(context.Background())
	if err != nil || fallback {
		t.Fatalf("expected direct success in HALF_OPEN, got fallback=%v err=%v", fallback, err)
	}

	// HalfOpenSuccessTrials = 1 -> immediately recovers to CLOSED
	if cb.State() != BreakerClosed {
		t.Fatalf("expected state CLOSED after trial recovery, got %s", cb.State())
	}
}

func TestJWKSCircuitBreaker_FastFailWhenNoStaleKeys(t *testing.T) {
	fetcher := func(ctx context.Context) (map[string]crypto.PublicKey, error) {
		return nil, errors.New("IdP offline 503")
	}

	cfg := JWKSCircuitBreakerConfig{
		FailureThreshold:      1,
		RecoveryTimeout:       1 * time.Second,
		HalfOpenSuccessTrials: 1,
		ServeStaleOnOpen:      true, // Stale enabled, but no keys cached yet
	}

	cb := NewJWKSCircuitBreaker(fetcher, cfg)

	_, fallback, err := cb.FetchKeys(context.Background())
	if err == nil || fallback {
		t.Fatalf("expected error on initial fail without stale keys, got fallback=%v err=%v", fallback, err)
	}

	if cb.State() != BreakerOpen {
		t.Fatalf("expected OPEN state")
	}

	// Next call fails immediately with ErrCircuitOpen
	_, _, err = cb.FetchKeys(context.Background())
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}
}
