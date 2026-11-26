package auth

import (
	"testing"
)

func TestPolicyTelemetryRotary_Summary(t *testing.T) {
	rotary := NewPolicyTelemetryRotary(5)

	// Insert 10 records (wraps around capacity 5)
	for i := 1; i <= 10; i++ {
		allowed := i%2 != 0
		rotary.Record("rbac-read", allowed, int64(i*100))
	}

	summary := rotary.GetSummary()
	if summary.SampleCount != 5 {
		t.Fatalf("expected sample count 5, got %d", summary.SampleCount)
	}
	if summary.AllowCount+summary.DenyCount != 5 {
		t.Fatalf("expected allow + deny = 5, got %d", summary.AllowCount+summary.DenyCount)
	}
	if summary.P50LatencyUs <= 0 {
		t.Fatalf("expected positive P50 latency, got %d", summary.P50LatencyUs)
	}
}
