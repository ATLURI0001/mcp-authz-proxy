package auth

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTokenRevocationRotary_RevocationAndLookup(t *testing.T) {
	rotary := NewTokenRevocationRotary(1 * time.Minute)

	now := time.Now().UTC()
	expiresAt := now.Add(5 * time.Minute)

	rawToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJzZXNzaW9uLTEyMyJ9.sig"
	fp, err := rotary.Revoke(rawToken, "user_42", expiresAt, "ADMIN_REVOCATION")
	if err != nil {
		t.Fatalf("expected successful revocation, got: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("expected 64-char hex SHA-256 fingerprint, got: %s", fp)
	}

	// 1. Should be detected as revoked
	if !rotary.IsRevoked(rawToken) {
		t.Fatal("expected token to be detected as revoked")
	}

	// 2. Unrelated token must not be revoked
	if rotary.IsRevoked("unrelated-clean-token") {
		t.Fatal("clean token reported as revoked")
	}

	// 3. Telemetry check
	telemetry := rotary.GetTelemetry()
	if telemetry.RevokedTotal != 1 || telemetry.DenylistHitsTotal != 1 || telemetry.DenylistMissesTotal != 1 {
		t.Fatalf("unexpected telemetry counts: %+v", telemetry)
	}
}

func TestTokenRevocationRotary_ValidationGuards(t *testing.T) {
	rotary := NewTokenRevocationRotary(1 * time.Minute)
	now := time.Now().UTC()

	// Empty token
	_, err := rotary.Revoke("", "user_1", now.Add(1*time.Minute), "TEST")
	if err != ErrRotaryEmptyToken {
		t.Fatalf("expected ErrRotaryEmptyToken, got: %v", err)
	}

	// Past expiry
	_, err = rotary.Revoke("token-abc", "user_1", now.Add(-1*time.Minute), "TEST")
	if err != ErrRotaryPastExpiry {
		t.Fatalf("expected ErrRotaryPastExpiry, got: %v", err)
	}

	// Duplicate
	_, err = rotary.Revoke("token-dup", "user_1", now.Add(2*time.Minute), "TEST")
	if err != nil {
		t.Fatalf("first revoke failed: %v", err)
	}
	_, err = rotary.Revoke("token-dup", "user_1", now.Add(2*time.Minute), "TEST")
	if err != ErrRotaryDuplicate {
		t.Fatalf("expected ErrRotaryDuplicate, got: %v", err)
	}
}

func TestTokenRevocationRotary_EpochPruning(t *testing.T) {
	rotary := NewTokenRevocationRotary(1 * time.Minute)
	baseTime := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	rotary.clockFn = func() time.Time { return baseTime }

	// Add token expiring in 2 minutes
	token1 := "token-short-lived"
	_, _ = rotary.Revoke(token1, "u1", baseTime.Add(2*time.Minute), "SHORT")

	// Add token expiring in 10 minutes
	token2 := "token-long-lived"
	_, _ = rotary.Revoke(token2, "u2", baseTime.Add(10*time.Minute), "LONG")

	if !rotary.IsRevoked(token1) || !rotary.IsRevoked(token2) {
		t.Fatal("expected both tokens to be active")
	}

	// Advance time by 4 minutes and rotate
	pruned := rotary.Rotate(baseTime.Add(4 * time.Minute))
	if pruned != 1 {
		t.Fatalf("expected exactly 1 short-lived entry pruned, got: %d", pruned)
	}

	// token1 should now be gone from denylist (expired)
	if rotary.IsRevoked(token1) {
		t.Fatal("token1 should have been evicted by rotary prune")
	}

	// token2 must still remain active
	if !rotary.IsRevoked(token2) {
		t.Fatal("token2 should remain active in unexpired bucket")
	}
}

func TestTokenRevocationRotary_PrometheusExport(t *testing.T) {
	rotary := NewTokenRevocationRotary(1 * time.Minute)
	now := time.Now().UTC()
	_, _ = rotary.Revoke("test-prom", "admin", now.Add(5*time.Minute), "TEST")

	_ = rotary.IsRevoked("test-prom")
	_ = rotary.IsRevoked("other")

	metrics := rotary.ExportPrometheusMetrics()
	if !strings.Contains(metrics, "authz_token_revocations_total 1") {
		t.Fatalf("missing revocations total in metrics:\n%s", metrics)
	}
	if !strings.Contains(metrics, `authz_token_denylist_checks_total{result="hit"} 1`) {
		t.Fatalf("missing hit count in metrics:\n%s", metrics)
	}
}

func TestTokenRevocationRotary_ConcurrentAccess(t *testing.T) {
	rotary := NewTokenRevocationRotary(1 * time.Minute)
	now := time.Now().UTC()

	var wg sync.WaitGroup
	workers := 10
	iterations := 50

	for i := 0; i < workers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				token := strings.Repeat("x", 10) + string(rune(workerID*1000+j))
				_, _ = rotary.Revoke(token, "sub", now.Add(time.Duration(j+10)*time.Minute), "CONCURRENT")
				_ = rotary.IsRevoked(token)
				_ = rotary.GetTelemetry()
			}
		}()
	}

	wg.Wait()
	telemetry := rotary.GetTelemetry()
	if telemetry.TotalActiveEntries == 0 {
		t.Fatal("expected active entries recorded under concurrent load")
	}
}
