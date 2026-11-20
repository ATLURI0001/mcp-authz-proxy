package gateway

import (
	"errors"
	"sync"
	"testing"
	"time"
)

var dummyErr = errors.New("upstream failure")

func TestCircuitBreaker_NormalOperation(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:     3,
		BaseCooldown:    50 * time.Millisecond,
		CanaryPassCount: 2,
	})

	if cb.State() != StateClosed {
		t.Fatalf("expected initial state CLOSED, got %s", cb.State())
	}

	for i := 0; i < 10; i++ {
		err := cb.Execute(func() error {
			return nil
		})
		if err != nil {
			t.Fatalf("unexpected error in closed state: %v", err)
		}
	}

	if cb.State() != StateClosed {
		t.Fatalf("expected state to remain CLOSED, got %s", cb.State())
	}

	m := cb.Metrics()
	if m.TotalSuccesses != 10 || m.TotalFailures != 0 {
		t.Fatalf("unexpected metrics: %+v", m)
	}
}

func TestCircuitBreaker_TripToOpenAndFastFail(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:     3,
		BaseCooldown:    100 * time.Millisecond,
		CanaryPassCount: 2,
	})

	// Trigger 2 failures (under threshold)
	for i := 0; i < 2; i++ {
		_ = cb.Execute(func() error { return dummyErr })
	}
	if cb.State() != StateClosed {
		t.Fatalf("expected state CLOSED after 2 failures, got %s", cb.State())
	}

	// 3rd failure triggers trip
	_ = cb.Execute(func() error { return dummyErr })
	if cb.State() != StateOpen {
		t.Fatalf("expected state OPEN after 3 failures, got %s", cb.State())
	}

	// Immediate next request should fast-fail with ErrCircuitOpen
	err := cb.Execute(func() error {
		t.Fatal("upstream operation should not be executed while OPEN")
		return nil
	})
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}
}

func TestCircuitBreaker_HalfOpenRecovery(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:     2,
		BaseCooldown:    30 * time.Millisecond,
		CanaryPassCount: 2,
	})

	// Trip to OPEN
	_ = cb.Execute(func() error { return dummyErr })
	_ = cb.Execute(func() error { return dummyErr })
	if cb.State() != StateOpen {
		t.Fatalf("expected state OPEN, got %s", cb.State())
	}

	// Wait for cooldown to expire
	time.Sleep(35 * time.Millisecond)

	// Next request triggers transition to HALF_OPEN and succeeds
	err1 := cb.Execute(func() error { return nil })
	if err1 != nil {
		t.Fatalf("canary 1 failed: %v", err1)
	}
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected state HALF_OPEN during canary phase, got %s", cb.State())
	}

	// Second canary succeeds -> should transition to CLOSED
	err2 := cb.Execute(func() error { return nil })
	if err2 != nil {
		t.Fatalf("canary 2 failed: %v", err2)
	}
	if cb.State() != StateClosed {
		t.Fatalf("expected state CLOSED after canaries pass, got %s", cb.State())
	}
}

func TestCircuitBreaker_HalfOpenFailureBackoff(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:     1,
		BaseCooldown:    25 * time.Millisecond,
		MaxCooldown:     200 * time.Millisecond,
		CanaryPassCount: 2,
	})

	// Trip to OPEN
	_ = cb.Execute(func() error { return dummyErr })
	if cb.State() != StateOpen {
		t.Fatalf("expected state OPEN, got %s", cb.State())
	}

	time.Sleep(30 * time.Millisecond)

	// Canary fails in HALF_OPEN -> should trip immediately back to OPEN with doubled cooldown (50ms)
	_ = cb.Execute(func() error { return dummyErr })
	if cb.State() != StateOpen {
		t.Fatalf("expected state OPEN after canary failure, got %s", cb.State())
	}

	// Checking after only 30ms (less than new 50ms cooldown) should still be OPEN
	time.Sleep(30 * time.Millisecond)
	errFastFail := cb.Execute(func() error { return nil })
	if !errors.Is(errFastFail, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen under doubled cooldown, got %v", errFastFail)
	}
}

func TestCircuitBreaker_Concurrency(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:     50,
		BaseCooldown:    50 * time.Millisecond,
		CanaryPassCount: 5,
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = cb.Execute(func() error {
					if id%5 == 0 {
						return dummyErr
					}
					return nil
				})
			}
		}(i)
	}
	wg.Wait()

	m := cb.Metrics()
	if m.TotalRequests != 1000 {
		t.Fatalf("expected 1000 total requests, got %d", m.TotalRequests)
	}
}
