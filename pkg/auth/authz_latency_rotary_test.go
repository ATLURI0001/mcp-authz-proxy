package auth

import "testing"

func TestAuthzLatencyRotary(t *testing.T) {
	r := NewAuthzLatencyRotary(2)
	r.Record(2)
	r.Record(4)
	r.Record(8)
	if got := r.Avg(); got != 6 {
		t.Fatalf("expected 6, got %v", got)
	}
}
