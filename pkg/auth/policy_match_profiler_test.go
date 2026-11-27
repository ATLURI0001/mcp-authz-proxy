package auth

import "testing"

func TestBenchmarkPolicyMatch(t *testing.T) {
	ok, d := BenchmarkPolicyMatch([]string{"fs:*", "git:status"}, "fs:read", 200)
	if !ok || d < 0 {
		t.Fatalf("unexpected match result: %v, %v", ok, d)
	}
}
