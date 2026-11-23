package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

func generateBenchmarkRSAKey() crypto.PublicKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &key.PublicKey
}

func TestCalculatePercentiles(t *testing.T) {
	durations := make([]time.Duration, 100)
	for i := 1; i <= 100; i++ {
		durations[i-1] = time.Duration(i) * time.Millisecond
	}

	p50, p90, p95, p99, min, max, mean, stddev := CalculatePercentiles(durations)
	if min != 1.0 {
		t.Errorf("expected min 1.0, got %f", min)
	}
	if max != 100.0 {
		t.Errorf("expected max 100.0, got %f", max)
	}
	if p50 != 50.0 {
		t.Errorf("expected p50 50.0, got %f", p50)
	}
	if p90 != 90.0 {
		t.Errorf("expected p90 90.0, got %f", p90)
	}
	if p95 != 95.0 {
		t.Errorf("expected p95 95.0, got %f", p95)
	}
	if p99 != 99.0 {
		t.Errorf("expected p99 99.0, got %f", p99)
	}
	if mean != 50.5 {
		t.Errorf("expected mean 50.5, got %f", mean)
	}
	if stddev <= 0 {
		t.Errorf("expected positive stddev, got %f", stddev)
	}
}

func TestTokenBenchmarkProfilerExecution(t *testing.T) {
	pubKey := generateBenchmarkRSAKey()
	fetcher := MockKeyFetcher(map[string]crypto.PublicKey{
		"key-1": pubKey,
	})

	cfg := DefaultJWKSCacheConfig()
	ctx := context.Background()
	cache, err := NewJWKSCache(ctx, fetcher, cfg)
	if err != nil {
		t.Fatalf("failed to create jwks cache: %v", err)
	}
	defer cache.Close()

	// Pre-warm cache
	if _, err := cache.GetKey(ctx, "key-1"); err != nil {
		t.Fatalf("failed to pre-warm cache: %v", err)
	}

	profiler := NewTokenBenchmarkProfiler(cache)

	// Sequential
	seqMetrics := profiler.RunSequentialBenchmark(ctx, "key-1", 100)
	if seqMetrics.TotalOps != 100 {
		t.Errorf("expected 100 ops, got %d", seqMetrics.TotalOps)
	}
	if seqMetrics.ErrorCount != 0 {
		t.Errorf("expected 0 errors, got %d", seqMetrics.ErrorCount)
	}
	if seqMetrics.ThroughputRPS <= 0 {
		t.Errorf("expected positive throughput, got %f", seqMetrics.ThroughputRPS)
	}

	// Concurrent
	concurMetrics := profiler.RunConcurrentBenchmark(ctx, "key-1", 4, 50)
	if concurMetrics.TotalOps != 200 {
		t.Errorf("expected 200 ops, got %d", concurMetrics.TotalOps)
	}
	if concurMetrics.ErrorCount != 0 {
		t.Errorf("expected 0 errors, got %d", concurMetrics.ErrorCount)
	}

	// Markdown output
	md := seqMetrics.FormatMarkdown()
	if len(md) == 0 {
		t.Errorf("expected non-empty markdown output")
	}
}

func BenchmarkJWKSCacheLookup(b *testing.B) {
	pubKey := generateBenchmarkRSAKey()
	fetcher := MockKeyFetcher(map[string]crypto.PublicKey{
		"key-1": pubKey,
	})
	cfg := DefaultJWKSCacheConfig()
	ctx := context.Background()
	cache, err := NewJWKSCache(ctx, fetcher, cfg)
	if err != nil {
		b.Fatalf("failed to create cache: %v", err)
	}
	defer cache.Close()

	cache.GetKey(ctx, "key-1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.GetKey(ctx, "key-1")
	}
}

func BenchmarkJWKSCacheLookupParallel(b *testing.B) {
	pubKey := generateBenchmarkRSAKey()
	fetcher := MockKeyFetcher(map[string]crypto.PublicKey{
		"key-1": pubKey,
	})
	cfg := DefaultJWKSCacheConfig()
	ctx := context.Background()
	cache, err := NewJWKSCache(ctx, fetcher, cfg)
	if err != nil {
		b.Fatalf("failed to create cache: %v", err)
	}
	defer cache.Close()

	cache.GetKey(ctx, "key-1")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = cache.GetKey(ctx, "key-1")
		}
	})
}
