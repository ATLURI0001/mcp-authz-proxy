package auth

import (
	"testing"
	"time"
)

func TestRbacEvalProfiler(t *testing.T) {
	p := NewRbacEvalProfiler()
	p.Record(2 * time.Millisecond)
	p.Record(4 * time.Millisecond)
	if p.Count() != 2 {
		t.Fatalf("expected 2 samples, got %d", p.Count())
	}
}
