package auth

import (
	"context"
	"crypto"
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// BenchmarkMetrics holds computed statistical metrics for benchmark executions.
type BenchmarkMetrics struct {
	Name           string
	TotalOps       int
	DurationSec    float64
	ThroughputRPS  float64
	P50Ms          float64
	P90Ms          float64
	P95Ms          float64
	P99Ms          float64
	MinMs          float64
	MaxMs          float64
	MeanMs         float64
	StdDevMs       float64
	ErrorCount     int
}

// TokenBenchmarkProfiler executes synthetic performance benchmarks on token validation and JWKS caching.
type TokenBenchmarkProfiler struct {
	cache *JWKSCache
}

// NewTokenBenchmarkProfiler constructs a profiler bound to a JWKSCache instance.
func NewTokenBenchmarkProfiler(cache *JWKSCache) *TokenBenchmarkProfiler {
	return &TokenBenchmarkProfiler{cache: cache}
}

// CalculatePercentiles calculates fine-grained percentile distributions from duration slices.
func CalculatePercentiles(durations []time.Duration) (p50, p90, p95, p99, min, max, mean, stddev float64) {
	n := len(durations)
	if n == 0 {
		return 0, 0, 0, 0, 0, 0, 0, 0
	}

	floats := make([]float64, n)
	var sum float64
	for i, d := range durations {
		ms := float64(d.Nanoseconds()) / 1e6
		floats[i] = ms
		sum += ms
	}
	sort.Float64s(floats)

	percentile := func(p float64) float64 {
		idx := int(math.Ceil((p / 100.0) * float64(n))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= n {
			idx = n - 1
		}
		return floats[idx]
	}

	p50 = percentile(50)
	p90 = percentile(90)
	p95 = percentile(95)
	p99 = percentile(99)
	min = floats[0]
	max = floats[n-1]
	mean = sum / float64(n)

	var varianceSum float64
	for _, v := range floats {
		diff := v - mean
		varianceSum += diff * diff
	}
	stddev = math.Sqrt(varianceSum / float64(n))
	return
}

// RunSequentialBenchmark profiles single-threaded lookup throughput and latency.
func (p *TokenBenchmarkProfiler) RunSequentialBenchmark(ctx context.Context, kid string, iterations int) BenchmarkMetrics {
	durations := make([]time.Duration, 0, iterations)
	errors := 0

	start := time.Now()
	for i := 0; i < iterations; i++ {
		t0 := time.Now()
		_, err := p.cache.GetKey(ctx, kid)
		dur := time.Since(t0)
		durations = append(durations, dur)
		if err != nil {
			errors++
		}
	}
	totalDuration := time.Since(start)

	p50, p90, p95, p99, min, max, mean, stddev := CalculatePercentiles(durations)
	rps := float64(iterations) / totalDuration.Seconds()

	return BenchmarkMetrics{
		Name:          "JWKS Cache Sequential Lookup",
		TotalOps:      iterations,
		DurationSec:   totalDuration.Seconds(),
		ThroughputRPS: rps,
		P50Ms:         p50,
		P90Ms:         p90,
		P95Ms:         p95,
		P99Ms:         p99,
		MinMs:         min,
		MaxMs:         max,
		MeanMs:        mean,
		StdDevMs:      stddev,
		ErrorCount:    errors,
	}
}

// RunConcurrentBenchmark profiles multi-goroutine concurrent lookup throughput.
func (p *TokenBenchmarkProfiler) RunConcurrentBenchmark(ctx context.Context, kid string, workers int, iterationsPerWorker int) BenchmarkMetrics {
	totalOps := workers * iterationsPerWorker
	durations := make([]time.Duration, totalOps)
	var errCount int64

	var wg sync.WaitGroup
	start := time.Now()

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			offset := workerID * iterationsPerWorker
			for i := 0; i < iterationsPerWorker; i++ {
				t0 := time.Now()
				_, err := p.cache.GetKey(ctx, kid)
				durations[offset+i] = time.Since(t0)
				if err != nil {
					syncAtomicAdd(&errCount, 1)
				}
			}
		}(w)
	}
	wg.Wait()
	totalDuration := time.Since(start)

	p50, p90, p95, p99, min, max, mean, stddev := CalculatePercentiles(durations)
	rps := float64(totalOps) / totalDuration.Seconds()

	return BenchmarkMetrics{
		Name:          fmt.Sprintf("JWKS Cache Concurrent Lookup (Workers: %d)", workers),
		TotalOps:      totalOps,
		DurationSec:   totalDuration.Seconds(),
		ThroughputRPS: rps,
		P50Ms:         p50,
		P90Ms:         p90,
		P95Ms:         p95,
		P99Ms:         p99,
		MinMs:         min,
		MaxMs:         max,
		MeanMs:        mean,
		StdDevMs:      stddev,
		ErrorCount:    int(errCount),
	}
}

// FormatMarkdown formats benchmark results as a markdown table.
func (m *BenchmarkMetrics) FormatMarkdown() string {
	return fmt.Sprintf("| Metric | Value |\n"+
		"| :--- | :--- |\n"+
		"| **Benchmark** | `%s` |\n"+
		"| **Total Operations** | `%d` ops |\n"+
		"| **Elapsed Duration** | `%.4f` s |\n"+
		"| **Throughput** | `%.2f` ops/sec |\n"+
		"| **P50 Latency** | `%.4f` ms |\n"+
		"| **P90 Latency** | `%.4f` ms |\n"+
		"| **P95 Latency** | `%.4f` ms |\n"+
		"| **P99 Latency** | `%.4f` ms |\n"+
		"| **Min / Max Latency** | `%.4f` ms / `%.4f` ms |\n"+
		"| **Mean / StdDev** | `%.4f` ms ± `%.4f` ms |\n"+
		"| **Error Count** | `%d` |\n",
		m.Name, m.TotalOps, m.DurationSec, m.ThroughputRPS,
		m.P50Ms, m.P90Ms, m.P95Ms, m.P99Ms, m.MinMs, m.MaxMs, m.MeanMs, m.StdDevMs, m.ErrorCount)
}

func syncAtomicAdd(val *int64, delta int64) {
	atomic.AddInt64(val, delta)
}

// MockKeyFetcher returns a static key map for micro-benchmarking without network IO.
func MockKeyFetcher(keys map[string]crypto.PublicKey) KeyFetcher {
	return func(ctx context.Context) (map[string]crypto.PublicKey, error) {
		return keys, nil
	}
}
