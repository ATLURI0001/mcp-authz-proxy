package gateway

import (
	"testing"
	"time"
)

func TestSimpleRateLimiter(t *testing.T) {
	limiter := NewSimpleRateLimiter(2, 100*time.Millisecond)

	if !limiter.Allow("user-a") {
		t.Fatal("expected 1st call to be allowed")
	}
	if !limiter.Allow("user-a") {
		t.Fatal("expected 2nd call to be allowed")
	}
	if limiter.Allow("user-a") {
		t.Fatal("expected 3rd call to be rejected")
	}

	// Distinct user is allowed
	if !limiter.Allow("user-b") {
		t.Fatal("expected distinct user to be allowed")
	}

	// Wait for window to expire
	time.Sleep(120 * time.Millisecond)
	if !limiter.Allow("user-a") {
		t.Fatal("expected call after window expiration to be allowed")
	}
}
