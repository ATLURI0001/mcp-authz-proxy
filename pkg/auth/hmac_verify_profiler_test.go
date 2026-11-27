package auth

import "testing"

func TestBenchmarkHmacVerify(t *testing.T) {
	d := BenchmarkHmacVerify([]byte("secret"), []byte("payload"), 1000)
	if d < 0 {
		t.Fatalf("expected non-negative duration, got %v", d)
	}
}
