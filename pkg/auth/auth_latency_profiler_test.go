package auth

import (
	"testing"
	"time"
)

func TestAuthLatencyProfiler(t *testing.T) {
	p := NewAuthLatencyProfiler()
	p.Record(10 * time.Millisecond)
	p.Record(20 * time.Millisecond)
	avg := p.Avg()
	if avg != 15*time.Millisecond {
		t.Fatalf("expected 15ms avg, got %v", avg)
	}
}
