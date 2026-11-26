package auth

import "testing"

func TestTokenCacheProfiler(t *testing.T) {
	p := NewTokenCacheProfiler(map[string]string{"tok1": "user1", "tok2": "user2"})
	hits, _ := p.RunBenchmark([]string{"tok1", "tok2", "missing"}, 100)
	if hits != 200 {
		t.Fatalf("expected 200 hits, got %d", hits)
	}
}
