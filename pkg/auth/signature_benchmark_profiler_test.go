package auth

import (
	"strings"
	"testing"
	"time"
)

func TestCachedSignatureVerifier_Basic(t *testing.T) {
	secret := []byte("benchmark-secret-key-12345")
	verifier := NewCachedSignatureVerifier(secret, 100*time.Millisecond)

	profiler := NewSignatureBenchmarkProfiler(secret)
	payload := "user-123:mcp:exec"
	validSig := profiler.GenerateSignature(payload)
	invalidSig := "deadbeefbadf00d"

	// 1. Initial verify -> miss
	if !verifier.VerifySignature(payload, validSig) {
		t.Fatalf("expected valid signature to verify successfully")
	}

	// 2. Repeat verify -> hit
	if !verifier.VerifySignature(payload, validSig) {
		t.Fatalf("expected cached signature to verify successfully")
	}

	if verifier.HitRatio() < 0.5 {
		t.Fatalf("expected hit ratio >= 0.5, got %f", verifier.HitRatio())
	}

	// 3. Invalid signature
	if verifier.VerifySignature(payload, invalidSig) {
		t.Fatalf("expected invalid signature to fail")
	}
}

func TestSignatureBenchmarkProfiler_Execution(t *testing.T) {
	secret := []byte("benchmark-secret-key-12345")
	profiler := NewSignatureBenchmarkProfiler(secret)

	// Profile Direct
	resDirect := profiler.ProfileDirectVerification(100, 2)
	if resDirect.TotalOperations != 100 {
		t.Fatalf("expected 100 total operations, got %d", resDirect.TotalOperations)
	}
	if resDirect.OperationsPerSec <= 0 {
		t.Fatalf("expected positive operations per sec")
	}
	if resDirect.P50Microseconds > resDirect.P99Microseconds {
		t.Fatalf("percentile inversion: P50 %f > P99 %f", resDirect.P50Microseconds, resDirect.P99Microseconds)
	}

	// Profile Cached
	resCached := profiler.ProfileCachedVerification(200, 4, 10)
	if resCached.TotalOperations != 200 {
		t.Fatalf("expected 200 total operations, got %d", resCached.TotalOperations)
	}
	if resCached.CacheHitRatio <= 0.8 {
		t.Fatalf("expected high cache hit ratio, got %f", resCached.CacheHitRatio)
	}

	// Format report
	report := profiler.FormatMarkdownReport(resDirect, resCached)
	if !strings.Contains(report, "# Token Signature Verification Benchmark Profiler") {
		t.Fatalf("report missing header")
	}
	if !strings.Contains(report, "Direct Crypto HMAC") {
		t.Fatalf("report missing Direct Crypto HMAC")
	}
	if !strings.Contains(report, "Cached Signature Verifier") {
		t.Fatalf("report missing Cached Signature Verifier")
	}
}
