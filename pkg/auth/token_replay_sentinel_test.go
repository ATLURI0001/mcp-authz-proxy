package auth

import (
	"testing"
	"time"
)

func TestTokenReplaySentinel_ValidToken(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	cfg := DefaultTokenReplaySentinelConfig()
	cfg.NowFunc = func() time.Time { return now }

	sentinel := NewTokenReplaySentinel(cfg)

	claims := TokenClaims{
		JTI:       "nonce-unique-12345",
		Subject:   "user-service-agent",
		ClientID:  "client-mcp-gateway",
		IssuedAt:  now.Add(-10 * time.Second),
		ExpiresAt: now.Add(5 * time.Minute),
	}

	err := sentinel.ValidateTokenIngress(claims)
	if err != nil {
		t.Fatalf("expected valid token ingress, got %v", err)
	}

	if sentinel.GetReplayCount() != 0 {
		t.Fatalf("expected 0 replays, got %d", sentinel.GetReplayCount())
	}
}

func TestTokenReplaySentinel_ReplayAttackDetection(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	cfg := DefaultTokenReplaySentinelConfig()
	cfg.NowFunc = func() time.Time { return now }

	sentinel := NewTokenReplaySentinel(cfg)

	claims := TokenClaims{
		JTI:       "nonce-replay-target",
		Subject:   "agent-007",
		ClientID:  "client-alpha",
		IssuedAt:  now.Add(-5 * time.Second),
		ExpiresAt: now.Add(2 * time.Minute),
	}

	// First pass should succeed
	if err := sentinel.ValidateTokenIngress(claims); err != nil {
		t.Fatalf("first ingress must succeed: %v", err)
	}

	// Second pass with exact same JTI, Subject, ClientID must fail as replay
	err := sentinel.ValidateTokenIngress(claims)
	if err != ErrSentinelReplayDetected {
		t.Fatalf("expected ErrSentinelReplayDetected, got %v", err)
	}

	if sentinel.GetReplayCount() != 1 {
		t.Fatalf("expected 1 replay count, got %d", sentinel.GetReplayCount())
	}

	records := sentinel.GetQuarantineRecords()
	if len(records) != 1 {
		t.Fatalf("expected 1 quarantine record, got %d", len(records))
	}
	if records[0].IncidentID != "INC-2026-AUTH-9201" {
		t.Fatalf("unexpected incident ID: %s", records[0].IncidentID)
	}
}

func TestTokenReplaySentinel_ClockSkewAndExpiration(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	cfg := DefaultTokenReplaySentinelConfig()
	cfg.MaxClockSkew = 30 * time.Second
	cfg.NowFunc = func() time.Time { return now }

	sentinel := NewTokenReplaySentinel(cfg)

	// Future drift > 30s
	driftedClaims := TokenClaims{
		JTI:      "nonce-drift",
		Subject:  "agent-drift",
		IssuedAt: now.Add(45 * time.Second),
	}
	if err := sentinel.ValidateTokenIngress(driftedClaims); err != ErrSentinelClockSkewDrift {
		t.Fatalf("expected ErrSentinelClockSkewDrift, got %v", err)
	}

	// Expired token
	expiredClaims := TokenClaims{
		JTI:       "nonce-expired",
		Subject:   "agent-expired",
		IssuedAt:  now.Add(-10 * time.Minute),
		ExpiresAt: now.Add(-1 * time.Minute),
	}
	if err := sentinel.ValidateTokenIngress(expiredClaims); err != ErrSentinelTokenExpired {
		t.Fatalf("expected ErrSentinelTokenExpired, got %v", err)
	}
}
