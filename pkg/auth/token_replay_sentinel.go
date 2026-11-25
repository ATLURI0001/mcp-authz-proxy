package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrSentinelMissingJTI indicates a token claim is missing a valid JTI nonce.
	ErrSentinelMissingJTI = errors.New("sentinel: token claims must specify non-empty jti (JWT ID)")
	// ErrSentinelMissingSubject indicates a token claim is missing a subject.
	ErrSentinelMissingSubject = errors.New("sentinel: token claims must specify non-empty subject")
	// ErrSentinelTokenExpired indicates the token issued-at or expires-at is beyond valid window.
	ErrSentinelTokenExpired = errors.New("sentinel: token expired or issued too far in the past")
	// ErrSentinelClockSkewDrift indicates token issued-at is too far into the future.
	ErrSentinelClockSkewDrift = errors.New("sentinel: token issued-at timestamp drifts too far into the future")
	// ErrSentinelReplayDetected indicates duplicate token presentation within the active TTL window.
	ErrSentinelReplayDetected = errors.New("sentinel: INC-2026-AUTH-9201 token replay attack intercepted; duplicate jti fingerprint")
)

// TokenClaims represents incoming authorization token metadata.
type TokenClaims struct {
	JTI       string
	Subject   string
	ClientID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// TokenReplayIncidentRecord details quarantined replay events for incident postmortem logging.
type TokenReplayIncidentRecord struct {
	Fingerprint string
	Subject     string
	JTI         string
	ClientID    string
	FirstSeen   time.Time
	ReplayTime  time.Time
	IncidentID  string
}

// TokenReplaySentinelConfig configures Sentinel invariants and capacities.
type TokenReplaySentinelConfig struct {
	MaxEntries       int
	MaxClockSkew     time.Duration
	DefaultTTL       time.Duration
	NowFunc          func() time.Time
}

// DefaultTokenReplaySentinelConfig provides production security defaults.
func DefaultTokenReplaySentinelConfig() TokenReplaySentinelConfig {
	return TokenReplaySentinelConfig{
		MaxEntries:   25000,
		MaxClockSkew: 60 * time.Second,
		DefaultTTL:   10 * time.Minute,
		NowFunc:      time.Now,
	}
}

type sentinelEntry struct {
	fingerprint string
	subject     string
	jti         string
	clientID    string
	firstSeen   time.Time
	expiresAt   time.Time
}

// TokenReplaySentinel defends authorization proxies against token replay and nonce collision attacks.
type TokenReplaySentinel struct {
	mu           sync.RWMutex
	cfg          TokenReplaySentinelConfig
	entries      map[string]*sentinelEntry
	quarantine   []TokenReplayIncidentRecord
	quarantineMu sync.Mutex

	totalReplays atomic.Uint64
	totalPassed  atomic.Uint64
}

// NewTokenReplaySentinel initializes the sentinel.
func NewTokenReplaySentinel(cfg TokenReplaySentinelConfig) *TokenReplaySentinel {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 25000
	}
	if cfg.MaxClockSkew <= 0 {
		cfg.MaxClockSkew = 60 * time.Second
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 10 * time.Minute
	}
	if cfg.NowFunc == nil {
		cfg.NowFunc = time.Now
	}

	return &TokenReplaySentinel{
		cfg:        cfg,
		entries:    make(map[string]*sentinelEntry, 1024),
		quarantine: make([]TokenReplayIncidentRecord, 0, 128),
	}
}

// ComputeTokenFingerprint generates a cryptographic SHA-256 hash of (subject:jti:clientId).
func ComputeTokenFingerprint(subject, jti, clientID string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s:%s:%s", subject, jti, clientID)
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateTokenIngress checks incoming token claims against replay fingerprints and clock skew.
func (s *TokenReplaySentinel) ValidateTokenIngress(claims TokenClaims) error {
	if claims.JTI == "" {
		return ErrSentinelMissingJTI
	}
	if claims.Subject == "" {
		return ErrSentinelMissingSubject
	}

	now := s.cfg.NowFunc()

	// Clock skew validation
	if !claims.IssuedAt.IsZero() {
		if claims.IssuedAt.After(now.Add(s.cfg.MaxClockSkew)) {
			return ErrSentinelClockSkewDrift
		}
		if now.Sub(claims.IssuedAt) > s.cfg.DefaultTTL+s.cfg.MaxClockSkew {
			return ErrSentinelTokenExpired
		}
	}

	if !claims.ExpiresAt.IsZero() && claims.ExpiresAt.Before(now.Add(-s.cfg.MaxClockSkew)) {
		return ErrSentinelTokenExpired
	}

	fp := ComputeTokenFingerprint(claims.Subject, claims.JTI, claims.ClientID)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already seen
	if existing, found := s.entries[fp]; found {
		if existing.expiresAt.After(now) {
			s.totalReplays.Add(1)
			s.recordQuarantine(TokenReplayIncidentRecord{
				Fingerprint: fp,
				Subject:     claims.Subject,
				JTI:         claims.JTI,
				ClientID:    claims.ClientID,
				FirstSeen:   existing.firstSeen,
				ReplayTime:  now,
				IncidentID:  "INC-2026-AUTH-9201",
			})
			return ErrSentinelReplayDetected
		}
	}

	// Evict expired entries if approaching capacity
	if len(s.entries) >= s.cfg.MaxEntries {
		for k, v := range s.entries {
			if v.expiresAt.Before(now) {
				delete(s.entries, k)
			}
		}
	}

	exp := claims.ExpiresAt
	if exp.IsZero() || exp.Before(now) {
		exp = now.Add(s.cfg.DefaultTTL)
	}

	s.entries[fp] = &sentinelEntry{
		fingerprint: fp,
		subject:     claims.Subject,
		jti:         claims.JTI,
		clientID:    claims.ClientID,
		firstSeen:   now,
		expiresAt:   exp,
	}

	s.totalPassed.Add(1)
	return nil
}

func (s *TokenReplaySentinel) recordQuarantine(rec TokenReplayIncidentRecord) {
	s.quarantineMu.Lock()
	defer s.quarantineMu.Unlock()
	if len(s.quarantine) >= 500 {
		s.quarantine = s.quarantine[1:]
	}
	s.quarantine = append(s.quarantine, rec)
}

// GetReplayCount returns total intercepted replay attempts.
func (s *TokenReplaySentinel) GetReplayCount() uint64 {
	return s.totalReplays.Load()
}

// GetQuarantineRecords returns recent quarantined incident telemetry.
func (s *TokenReplaySentinel) GetQuarantineRecords() []TokenReplayIncidentRecord {
	s.quarantineMu.Lock()
	defer s.quarantineMu.Unlock()
	copied := make([]TokenReplayIncidentRecord, len(s.quarantine))
	copy(copied, s.quarantine)
	return copied
}
