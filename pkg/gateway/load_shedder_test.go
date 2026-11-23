package gateway

import (
	"sync"
	"testing"
	"time"
)

func TestAdaptiveLoadShedder_PriorityTiers(t *testing.T) {
	cfg := LoadShedderConfig{
		MaxCapacity:           10,
		LowPriorityLimit:      5,
		StandardPriorityLimit: 8,
		LatencyThreshold:      500 * time.Millisecond,
	}
	shedder := NewAdaptiveLoadShedder(cfg)

	var releases []func()

	// Fill 5 slots with Low priority
	for i := 0; i < 5; i++ {
		rel, err := shedder.Acquire(PriorityLow)
		if err != nil {
			t.Fatalf("expected low priority admission, got: %v", err)
		}
		releases = append(releases, rel)
	}

	// 6th Low priority request should be shed
	_, err := shedder.Acquire(PriorityLow)
	if err != ErrLoadShedLowPriority {
		t.Fatalf("expected ErrLoadShedLowPriority, got: %v", err)
	}

	// Standard priority should still be admitted up to 8
	for i := 0; i < 3; i++ {
		rel, err := shedder.Acquire(PriorityStandard)
		if err != nil {
			t.Fatalf("expected standard priority admission, got: %v", err)
		}
		releases = append(releases, rel)
	}

	// 9th request at Standard priority should be shed
	_, err = shedder.Acquire(PriorityStandard)
	if err != ErrLoadShedStandard {
		t.Fatalf("expected ErrLoadShedStandard, got: %v", err)
	}

	// Critical priority should be admitted up to MaxCapacity (10)
	for i := 0; i < 2; i++ {
		rel, err := shedder.Acquire(PriorityCritical)
		if err != nil {
			t.Fatalf("expected critical priority admission, got: %v", err)
		}
		releases = append(releases, rel)
	}

	// 11th request (Critical) should fail with capacity exhausted
	_, err = shedder.Acquire(PriorityCritical)
	if err != ErrCapacityExhausted {
		t.Fatalf("expected ErrCapacityExhausted, got: %v", err)
	}

	// Release all
	for _, rel := range releases {
		rel()
	}

	stats := shedder.Stats()
	if stats.ActiveInFlight != 0 {
		t.Errorf("expected 0 in flight, got %d", stats.ActiveInFlight)
	}
	if stats.TotalAdmitted != 10 {
		t.Errorf("expected 10 total admitted, got %d", stats.TotalAdmitted)
	}
	if stats.TotalShedLow != 1 || stats.TotalShedStd != 1 || stats.TotalShedCrit != 1 {
		t.Errorf("unexpected shed counts: low=%d std=%d crit=%d", stats.TotalShedLow, stats.TotalShedStd, stats.TotalShedCrit)
	}
}

func TestAdaptiveLoadShedder_LatencyBackpressure(t *testing.T) {
	cfg := LoadShedderConfig{
		MaxCapacity:           20,
		LowPriorityLimit:      15,
		StandardPriorityLimit: 18,
		LatencyThreshold:      50 * time.Millisecond,
	}
	shedder := NewAdaptiveLoadShedder(cfg)

	// Inject slow completion latency into sliding window
	for i := 0; i < 10; i++ {
		rel, err := shedder.Acquire(PriorityStandard)
		if err != nil {
			t.Fatalf("acquire error: %v", err)
		}
		time.Sleep(55 * time.Millisecond)
		rel()
	}

	stats := shedder.Stats()
	if stats.RecentAvgLatency <= 50*time.Millisecond {
		t.Fatalf("expected avg latency > 50ms, got %v", stats.RecentAvgLatency)
	}

	// With elevated latency, low priority should be shed immediately
	_, err := shedder.Acquire(PriorityLow)
	if err != ErrLoadShedLowPriority {
		t.Fatalf("expected ErrLoadShedLowPriority due to latency, got: %v", err)
	}
}

func TestAdaptiveLoadShedder_ConcurrentAccess(t *testing.T) {
	shedder := NewAdaptiveLoadShedder(DefaultLoadShedderConfig())
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p := Priority(idx % 3)
			rel, err := shedder.Acquire(p)
			if err == nil {
				time.Sleep(time.Millisecond)
				rel()
			}
		}(i)
	}

	wg.Wait()
	stats := shedder.Stats()
	if stats.ActiveInFlight != 0 {
		t.Errorf("expected 0 active in flight after concurrent run, got %d", stats.ActiveInFlight)
	}
}
