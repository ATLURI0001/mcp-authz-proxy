package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func generateTestECDSAKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return &priv.PublicKey
}

func TestJWKSCache_BasicLookup(t *testing.T) {
	key1 := generateTestECDSAKey(t)
	key2 := generateTestECDSAKey(t)

	fetcher := func(ctx context.Context) (map[string]crypto.PublicKey, error) {
		return map[string]crypto.PublicKey{
			"kid-alpha": key1,
			"kid-beta":  key2,
		}, nil
	}

	cfg := JWKSCacheConfig{
		TTL:                100 * time.Millisecond,
		RefreshInterval:    10 * time.Second,
		MinRefreshInterval: 50 * time.Millisecond,
		GracePeriod:        200 * time.Millisecond,
	}

	cache, err := NewJWKSCache(context.Background(), fetcher, cfg)
	if err != nil {
		t.Fatalf("unexpected NewJWKSCache error: %v", err)
	}
	defer cache.Close()

	// Hit lookup
	k, err := cache.GetKey(context.Background(), "kid-alpha")
	if err != nil {
		t.Fatalf("expected key, got error: %v", err)
	}
	if k != key1 {
		t.Fatalf("expected key1, got %v", k)
	}

	// Miss lookup
	_, err = cache.GetKey(context.Background(), "kid-nonexistent")
	if !errors.Is(err, ErrKeyNotFound) && !errors.Is(err, ErrCooldownActive) {
		t.Fatalf("expected ErrKeyNotFound or ErrCooldownActive, got %v", err)
	}

	stats := cache.Stats()
	if stats.Hits != 1 {
		t.Errorf("expected 1 hit, got %d", stats.Hits)
	}
	if stats.Misses < 1 {
		t.Errorf("expected at least 1 miss, got %d", stats.Misses)
	}
	if stats.ActiveKeys != 2 {
		t.Errorf("expected 2 active keys, got %d", stats.ActiveKeys)
	}
}

func TestJWKSCache_OnDemandRefreshAndCooldown(t *testing.T) {
	keyInitial := generateTestECDSAKey(t)
	keyNew := generateTestECDSAKey(t)

	var callCount int
	fetcher := func(ctx context.Context) (map[string]crypto.PublicKey, error) {
		callCount++
		if callCount == 1 {
			return map[string]crypto.PublicKey{
				"kid-1": keyInitial,
			}, nil
		}
		return map[string]crypto.PublicKey{
			"kid-1": keyInitial,
			"kid-2": keyNew,
		}, nil
	}

	cfg := JWKSCacheConfig{
		TTL:                1 * time.Minute,
		RefreshInterval:    1 * time.Hour,
		MinRefreshInterval: 100 * time.Millisecond,
		GracePeriod:        1 * time.Hour,
	}

	cache, err := NewJWKSCache(context.Background(), fetcher, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cache.Close()

	// Initial key present
	k1, err := cache.GetKey(context.Background(), "kid-1")
	if err != nil || k1 != keyInitial {
		t.Fatalf("expected initial key, got: %v, err: %v", k1, err)
	}

	// Immediate query for kid-2 trips cooldown because initial fetch happened at t=0
	_, err = cache.GetKey(context.Background(), "kid-2")
	if err == nil {
		t.Fatalf("expected error on immediate miss due to cooldown")
	}

	// Wait past cooldown
	time.Sleep(120 * time.Millisecond)

	// Now lookup should trigger on-demand refresh and find kid-2
	k2, err := cache.GetKey(context.Background(), "kid-2")
	if err != nil {
		t.Fatalf("expected to find kid-2 after refresh, got err: %v", err)
	}
	if k2 != keyNew {
		t.Fatalf("expected keyNew, got %v", k2)
	}
}

func TestJWKSCache_Close(t *testing.T) {
	fetcher := func(ctx context.Context) (map[string]crypto.PublicKey, error) {
		return map[string]crypto.PublicKey{}, nil
	}

	cache, err := NewJWKSCache(context.Background(), fetcher, DefaultJWKSCacheConfig())
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	if err := cache.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	_, err = cache.GetKey(context.Background(), "any")
	if !errors.Is(err, ErrCacheClosed) {
		t.Fatalf("expected ErrCacheClosed, got %v", err)
	}
}
