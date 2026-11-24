package gateway

import (
	"sync"
	"testing"
	"time"
)

func TestGatewayTelemetryEngine_BasicRecording(t *testing.T) {
	cfg := DefaultGatewayTelemetryConfig()
	cfg.LatencySLAThreshold = 100 * time.Millisecond
	cfg.AlertErrorRatePct = 10.0
	engine := NewGatewayTelemetryEngine(cfg)

	// Record 10 calls: 8 success, 2 error
	for i := 0; i < 8; i++ {
		engine.RecordCall("tools/read_file", 10*time.Millisecond, 100, 500, OutcomeSuccess)
	}
	engine.RecordCall("tools/write_file", 50*time.Millisecond, 200, 100, OutcomeRateLimited)
	engine.RecordCall("tools/execute", 150*time.Millisecond, 300, 50, OutcomeLoadShed)

	snap := engine.Snapshot()
	if snap.TotalCalls != 10 {
		t.Fatalf("expected 10 total calls, got %d", snap.TotalCalls)
	}
	if snap.SuccessCount != 8 {
		t.Fatalf("expected 8 successes, got %d", snap.SuccessCount)
	}
	if snap.ErrorCount != 2 {
		t.Fatalf("expected 2 errors, got %d", snap.ErrorCount)
	}
	if snap.GlobalErrorRate != 20.0 {
		t.Fatalf("expected 20%% error rate, got %.2f%%", snap.GlobalErrorRate)
	}

	// Should have breached SLA because error rate 20% > 10%
	if !snap.SLABreached {
		t.Fatalf("expected SLA breach due to error rate")
	}

	// Check route breakdown
	rf, ok := snap.Routes["tools/read_file"]
	if !ok {
		t.Fatalf("missing route tools/read_file")
	}
	if rf.TotalCalls != 8 || rf.SuccessCount != 8 || rf.ErrorCount != 0 {
		t.Fatalf("unexpected read_file metrics: %+v", rf)
	}
	if rf.BytesIn != 800 || rf.BytesOut != 4000 {
		t.Fatalf("unexpected read_file byte counters: in=%d, out=%d", rf.BytesIn, rf.BytesOut)
	}
}

func TestGatewayTelemetryEngine_LatencyPercentiles(t *testing.T) {
	cfg := DefaultGatewayTelemetryConfig()
	cfg.AlertErrorRatePct = 50.0 // prevent error rate breach
	cfg.LatencySLAThreshold = 50 * time.Millisecond
	engine := NewGatewayTelemetryEngine(cfg)

	// 100 calls with durations 1ms .. 100ms
	for i := 1; i <= 100; i++ {
		engine.RecordCall("tools/query", time.Duration(i)*time.Millisecond, 10, 10, OutcomeSuccess)
	}

	snap := engine.Snapshot()
	if snap.TotalCalls != 100 {
		t.Fatalf("expected 100 calls, got %d", snap.TotalCalls)
	}

	if snap.P50Latency < 50*time.Millisecond || snap.P50Latency > 52*time.Millisecond {
		t.Fatalf("unexpected P50: %v", snap.P50Latency)
	}
	if snap.P90Latency < 90*time.Millisecond || snap.P90Latency > 92*time.Millisecond {
		t.Fatalf("unexpected P90: %v", snap.P90Latency)
	}
	if snap.P99Latency < 99*time.Millisecond || snap.P99Latency > 100*time.Millisecond {
		t.Fatalf("unexpected P99: %v", snap.P99Latency)
	}

	// P99 is ~100ms > 50ms SLA threshold
	if !snap.SLABreached {
		t.Fatalf("expected SLA breach due to high P99 latency")
	}
}

func TestGatewayTelemetryEngine_ConcurrentRecording(t *testing.T) {
	cfg := DefaultGatewayTelemetryConfig()
	engine := NewGatewayTelemetryEngine(cfg)

	var wg sync.WaitGroup
	workers := 10
	iterations := 100

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				engine.RecordCall("tools/concurrent", 5*time.Millisecond, 50, 50, OutcomeSuccess)
			}
		}(w)
	}

	wg.Wait()

	snap := engine.Snapshot()
	expectedCalls := int64(workers * iterations)
	if snap.TotalCalls != expectedCalls {
		t.Fatalf("expected %d calls, got %d", expectedCalls, snap.TotalCalls)
	}
}

func TestGatewayTelemetryEngine_ResetAndEmpty(t *testing.T) {
	cfg := DefaultGatewayTelemetryConfig()
	engine := NewGatewayTelemetryEngine(cfg)

	snapEmpty := engine.Snapshot()
	if snapEmpty.TotalCalls != 0 || snapEmpty.SLABreached {
		t.Fatalf("expected empty snapshot")
	}

	engine.RecordCall("route/test", 10*time.Millisecond, 10, 10, OutcomeSuccess)
	if engine.Snapshot().TotalCalls != 1 {
		t.Fatalf("expected 1 call before reset")
	}

	engine.Reset()
	if engine.Snapshot().TotalCalls != 0 {
		t.Fatalf("expected 0 calls after reset")
	}
}
