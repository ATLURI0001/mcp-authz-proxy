package auth

import "time"

// TokenCacheProfiler benchmarks token lookup throughput.
type TokenCacheProfiler struct {
	cache map[string]string
}

func NewTokenCacheProfiler(entries map[string]string) *TokenCacheProfiler {
	return &TokenCacheProfiler{cache: entries}
}

func (p *TokenCacheProfiler) RunBenchmark(keys []string, iterations int) (hits int, elapsed time.Duration) {
	start := time.Now()
	for i := 0; i < iterations; i++ {
		for _, k := range keys {
			if _, ok := p.cache[k]; ok {
				hits++
			}
		}
	}
	return hits, time.Since(start)
}
