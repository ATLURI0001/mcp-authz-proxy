package gateway

import (
	"sync"
	"testing"
	"time"
)

func TestTokenBucket_BurstAndExhaustion(t *testing.T) {
	limiter := NewTokenBucketLimiter(3.0, 1.0, time.Minute)

	// Consume capacity (3 tokens)
	for i := 0; i < 3; i++ {
		if !limiter.Allow("client-burst") {
			t.Fatalf("expected token %d to be granted", i+1)
		}
	}

	// 4th request must be rejected
	if limiter.Allow("client-burst") {
		t.Fatal("expected request exceeding capacity to be rejected")
	}
}

func TestTokenBucket_Refill(t *testing.T) {
	limiter := NewTokenBucketLimiter(2.0, 10.0, time.Minute) // 10 tokens per sec = 1 token per 100ms

	if !limiter.AllowN("client-refill", 2.0) {
		t.Fatal("expected initial burst of 2 to be allowed")
	}
	if limiter.Allow("client-refill") {
		t.Fatal("expected immediate subsequent call to be rejected")
	}

	// Wait 150ms -> should replenish at least 1 token
	time.Sleep(150 * time.Millisecond)

	if !limiter.Allow("client-refill") {
		t.Fatal("expected replenished token to be allowed after sleep")
	}
}

func TestTokenBucket_AllowN(t *testing.T) {
	limiter := NewTokenBucketLimiter(5.0, 1.0, time.Minute)

	if !limiter.AllowN("client-multi", 3.0) {
		t.Fatal("expected consuming 3 of 5 tokens to succeed")
	}

	remaining := limiter.Tokens("client-multi")
	if remaining < 1.9 || remaining > 2.1 {
		t.Fatalf("expected ~2 tokens remaining, got %f", remaining)
	}

	if limiter.AllowN("client-multi", 3.0) {
		t.Fatal("expected consuming 3 tokens when 2 remain to fail")
	}
}

func TestTokenBucket_Cleanup(t *testing.T) {
	limiter := NewTokenBucketLimiter(5.0, 1.0, 50*time.Millisecond)

	limiter.Allow("stale-client-1")
	limiter.Allow("stale-client-2")

	// Sleep past TTL
	time.Sleep(70 * time.Millisecond)

	evicted := limiter.Cleanup()
	if evicted != 2 {
		t.Fatalf("expected 2 evicted entries, got %d", evicted)
	}
}

func TestTokenBucket_Concurrency(t *testing.T) {
	limiter := NewTokenBucketLimiter(50.0, 50.0, time.Minute)
	var wg sync.WaitGroup
	granted := 0
	var mu sync.Mutex

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.Allow("concurrent-client") {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	if granted < 45 || granted > 55 {
		t.Fatalf("expected ~50 granted tokens concurrently, got %d", granted)
	}
}
