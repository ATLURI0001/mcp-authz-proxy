package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// SignatureProfileResult contains statistical latency and throughput metrics for signature verification.
type SignatureProfileResult struct {
	EngineName       string
	TotalOperations  int
	ElapsedSeconds   float64
	OperationsPerSec float64
	CacheHitRatio    float64
	MinMicroseconds  float64
	P50Microseconds  float64
	P90Microseconds  float64
	P99Microseconds  float64
	MaxMicroseconds  float64
	MeanMicroseconds float64
}

// CachedSignatureVerifier provides a high-throughput memory cache for verified token signatures.
type CachedSignatureVerifier struct {
	secret []byte
	ttl    time.Duration
	cache  sync.Map
	hits   int64
	misses int64
}

type cacheEntry struct {
	valid     bool
	expiresAt time.Time
}

// NewCachedSignatureVerifier creates an authenticated signature verifier with caching.
func NewCachedSignatureVerifier(secret []byte, ttl time.Duration) *CachedSignatureVerifier {
	return &CachedSignatureVerifier{
		secret: secret,
		ttl:    ttl,
	}
}

// VerifySignature verifies HMAC-SHA256 signature, leveraging cache when available.
func (c *CachedSignatureVerifier) VerifySignature(payload, signature string) bool {
	cacheKey := payload + ":" + signature
	now := time.Now()

	if val, ok := c.cache.Load(cacheKey); ok {
		entry := val.(cacheEntry)
		if now.Before(entry.expiresAt) {
			atomic.AddInt64(&c.hits, 1)
			return entry.valid
		}
		c.cache.Delete(cacheKey)
	}

	atomic.AddInt64(&c.misses, 1)

	// Perform actual cryptographic verification
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(payload))
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	isValid := hmac.Equal([]byte(expectedMAC), []byte(signature))

	c.cache.Store(cacheKey, cacheEntry{
		valid:     isValid,
		expiresAt: now.Add(c.ttl),
	})

	return isValid
}

// HitRatio returns cache hit ratio.
func (c *CachedSignatureVerifier) HitRatio() float64 {
	h := atomic.LoadInt64(&c.hits)
	m := atomic.LoadInt64(&c.misses)
	total := h + m
	if total == 0 {
		return 0.0
	}
	return float64(h) / float64(total)
}

// SignatureBenchmarkProfiler benchmarks cryptographic signature verification throughput.
type SignatureBenchmarkProfiler struct {
	secret []byte
}

// NewSignatureBenchmarkProfiler constructs a signature profiler with benchmark secret.
func NewSignatureBenchmarkProfiler(secret []byte) *SignatureBenchmarkProfiler {
	return &SignatureBenchmarkProfiler{secret: secret}
}

// GenerateSignature generates a valid signature for a payload.
func (p *SignatureBenchmarkProfiler) GenerateSignature(payload string) string {
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// ProfileDirectVerification profiles raw HMAC verification without cache.
func (p *SignatureBenchmarkProfiler) ProfileDirectVerification(iterations int, concurrency int) SignatureProfileResult {
	if iterations <= 0 {
		iterations = 1000
	}
	if concurrency <= 0 {
		concurrency = 1
	}

	payloads := make([]string, iterations)
	sigs := make([]string, iterations)
	for i := 0; i < iterations; i++ {
		payloads[i] = fmt.Sprintf("tenant-%d:user-%d:perm-read", i%50, i%100)
		sigs[i] = p.GenerateSignature(payloads[i])
	}

	latencies := make([]time.Duration, iterations)
	opsPerWorker := iterations / concurrency

	start := time.Now()
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		wIdx := w
		go func() {
			defer wg.Done()
			wStart := wIdx * opsPerWorker
			wEnd := wStart + opsPerWorker
			if wIdx == concurrency-1 {
				wEnd = iterations
			}

			for i := wStart; i < wEnd; i++ {
				t0 := time.Now()
				mac := hmac.New(sha256.New, p.secret)
				mac.Write([]byte(payloads[i]))
				expected := hex.EncodeToString(mac.Sum(nil))
				_ = hmac.Equal([]byte(expected), []byte(sigs[i]))
				latencies[i] = time.Since(t0)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()

	return p.calculateResult("DirectCryptoHMAC", iterations, elapsed, 0.0, latencies)
}

// ProfileCachedVerification profiles cached signature verification with warm hit ratio.
func (p *SignatureBenchmarkProfiler) ProfileCachedVerification(iterations int, concurrency int, uniqueTokens int) SignatureProfileResult {
	if iterations <= 0 {
		iterations = 1000
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	if uniqueTokens <= 0 {
		uniqueTokens = 20
	}

	verifier := NewCachedSignatureVerifier(p.secret, 5*time.Minute)

	// Pre-generate unique tokens
	uniquePayloads := make([]string, uniqueTokens)
	uniqueSigs := make([]string, uniqueTokens)
	for i := 0; i < uniqueTokens; i++ {
		uniquePayloads[i] = fmt.Sprintf("tenant-fixed:user-%d:mcp-tools", i)
		uniqueSigs[i] = p.GenerateSignature(uniquePayloads[i])
		// Warm up cache
		verifier.VerifySignature(uniquePayloads[i], uniqueSigs[i])
	}

	// Reset hits/misses after warmup
	atomic.StoreInt64(&verifier.hits, 0)
	atomic.StoreInt64(&verifier.misses, 0)

	latencies := make([]time.Duration, iterations)
	opsPerWorker := iterations / concurrency

	start := time.Now()
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		wIdx := w
		go func() {
			defer wg.Done()
			wStart := wIdx * opsPerWorker
			wEnd := wStart + opsPerWorker
			if wIdx == concurrency-1 {
				wEnd = iterations
			}

			for i := wStart; i < wEnd; i++ {
				tokenIdx := i % uniqueTokens
				t0 := time.Now()
				_ = verifier.VerifySignature(uniquePayloads[tokenIdx], uniqueSigs[tokenIdx])
				latencies[i] = time.Since(t0)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()

	return p.calculateResult("CachedSignatureVerifier", iterations, elapsed, verifier.HitRatio(), latencies)
}

func (p *SignatureBenchmarkProfiler) calculateResult(
	name string,
	totalOps int,
	elapsedSec float64,
	hitRatio float64,
	latencies []time.Duration,
) SignatureProfileResult {
	n := len(latencies)
	if n == 0 {
		return SignatureProfileResult{EngineName: name}
	}

	micros := make([]float64, n)
	var sum float64
	for i, d := range latencies {
		us := float64(d.Nanoseconds()) / 1e3
		micros[i] = us
		sum += us
	}
	sort.Float64s(micros)

	percentile := func(pct float64) float64 {
		idx := int(math.Ceil((pct/100.0)*float64(n))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= n {
			idx = n - 1
		}
		return micros[idx]
	}

	opsPerSec := float64(totalOps) / math.Max(0.000001, elapsedSec)

	return SignatureProfileResult{
		EngineName:       name,
		TotalOperations:  totalOps,
		ElapsedSeconds:   math.Round(elapsedSec*10000) / 10000,
		OperationsPerSec: math.Round(opsPerSec),
		CacheHitRatio:    math.Round(hitRatio*1000) / 1000,
		MinMicroseconds:  math.Round(micros[0]*100) / 100,
		P50Microseconds:  math.Round(percentile(50.0)*100) / 100,
		P90Microseconds:  math.Round(percentile(90.0)*100) / 100,
		P99Microseconds:  math.Round(percentile(99.0)*100) / 100,
		MaxMicroseconds:  math.Round(micros[n-1]*100) / 100,
		MeanMicroseconds: math.Round((sum/float64(n))*100) / 100,
	}
}

// FormatMarkdownReport renders benchmark comparison table in markdown.
func (p *SignatureBenchmarkProfiler) FormatMarkdownReport(direct, cached SignatureProfileResult) string {
	speedup := 1.0
	if direct.MeanMicroseconds > 0 && cached.MeanMicroseconds > 0 {
		speedup = direct.MeanMicroseconds / cached.MeanMicroseconds
	}

	return fmt.Sprintf(`# Token Signature Verification Benchmark Profiler

| Metric | Direct Crypto HMAC | Cached Signature Verifier | Speedup |
| :--- | :--- | :--- | :--- |
| **Throughput** | %0.0f ops/sec | %0.0f ops/sec | **%.1fx** |
| **Cache Hit Ratio** | %.1f%% | %.1f%% | - |
| **P50 (Median) Latency** | %.2f µs | %.2f µs | - |
| **P90 Latency** | %.2f µs | %.2f µs | - |
| **P99 Latency** | %.2f µs | %.2f µs | - |
| **Mean Latency** | %.2f µs | %.2f µs | - |
| **Min / Max Latency** | %.2f µs / %.2f µs | %.2f µs / %.2f µs | - |
`,
		direct.OperationsPerSec, cached.OperationsPerSec, speedup,
		direct.CacheHitRatio*100, cached.CacheHitRatio*100,
		direct.P50Microseconds, cached.P50Microseconds,
		direct.P90Microseconds, cached.P90Microseconds,
		direct.P99Microseconds, cached.P99Microseconds,
		direct.MeanMicroseconds, cached.MeanMicroseconds,
		direct.MinMicroseconds, direct.MaxMicroseconds,
		cached.MinMicroseconds, cached.MaxMicroseconds,
	)
}
