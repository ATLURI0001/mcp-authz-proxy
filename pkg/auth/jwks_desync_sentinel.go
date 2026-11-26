package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrUnknownKid           = errors.New("jwks: key ID not found in active set")
	ErrJWKSRefreshThrottled = errors.New("jwks: out-of-band refresh rate limit exceeded")
	ErrJWKSEmptyKeySet      = errors.New("jwks: refreshed key set is empty")
)

// JWKSKeyRecord represents an active RSA public key in the JWKS set.
type JWKSKeyRecord struct {
	Kid       string
	PublicKey string
	CachedAt  time.Time
	Usage     string
}

// JWKSDesyncSentinelConfig defines operational bounds for the desync sentinel.
type JWKSDesyncSentinelConfig struct {
	MinRefreshInterval time.Duration
	KeyTTL             time.Duration
	MaxCachedKeys      int
}

// JWKSDesyncSentinel detects JWKS rotation desynchronization and executes bounded refresh.
type JWKSDesyncSentinel struct {
	mu                 sync.RWMutex
	config             JWKSDesyncSentinelConfig
	keys               map[string]JWKSKeyRecord
	lastRefreshTime    time.Time
	refreshCount       int
	desyncEventsCount  int
	quarantinedKids    map[string]time.Time
	fetchKeysFunc      func(issuer string) (map[string]string, error)
}

// NewJWKSDesyncSentinel creates a new sentinel instance with the specified key fetcher.
func NewJWKSDesyncSentinel(
	cfg JWKSDesyncSentinelConfig,
	fetcher func(issuer string) (map[string]string, error),
) *JWKSDesyncSentinel {
	if cfg.MinRefreshInterval <= 0 {
		cfg.MinRefreshInterval = 2 * time.Second
	}
	if cfg.KeyTTL <= 0 {
		cfg.KeyTTL = 1 * time.Hour
	}
	if cfg.MaxCachedKeys <= 0 {
		cfg.MaxCachedKeys = 100
	}

	return &JWKSDesyncSentinel{
		config:          cfg,
		keys:            make(map[string]JWKSKeyRecord),
		quarantinedKids: make(map[string]time.Time),
		fetchKeysFunc:   fetcher,
	}
}

// ComputeJWKSKeyFingerprint generates a SHA-256 fingerprint for a raw public key string.
func ComputeJWKSKeyFingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// LookupKey retrieves a public key for a given kid. If the kid is missing,
// it initiates an out-of-band desynchronization refresh to acquire newly rotated keys.
func (s *JWKSDesyncSentinel) LookupKey(issuer, kid string) (string, error) {
	if kid == "" {
		return "", errors.New("jwks: kid cannot be empty")
	}

	// 1. Fast read lock lookup
	s.mu.RLock()
	rec, exists := s.keys[kid]
	s.mu.RUnlock()

	if exists {
		return rec.PublicKey, nil
	}

	// 2. Key miss -> Potential IdP rotation desynchronization
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check under write lock
	if rec, exists := s.keys[kid]; exists {
		return rec.PublicKey, nil
	}

	// Rate-limit out-of-band refresh probes
	now := time.Now()
	if !s.lastRefreshTime.IsZero() && now.Sub(s.lastRefreshTime) < s.config.MinRefreshInterval {
		s.desyncEventsCount++
		s.quarantinedKids[kid] = now
		return "", fmt.Errorf("%w: refresh throttled, retry in %v", ErrUnknownKid, s.config.MinRefreshInterval)
	}

	// Execute fetch
	if s.fetchKeysFunc == nil {
		return "", errors.New("jwks: no fetch function configured")
	}

	newKeys, err := s.fetchKeysFunc(issuer)
	if err != nil {
		s.desyncEventsCount++
		return "", fmt.Errorf("jwks: remote refresh failed: %w", err)
	}

	if len(newKeys) == 0 {
		return "", ErrJWKSEmptyKeySet
	}

	s.lastRefreshTime = now
	s.refreshCount++

	// Populate fresh key set
	for k, v := range newKeys {
		s.keys[k] = JWKSKeyRecord{
			Kid:       k,
			PublicKey: v,
			CachedAt:  now,
			Usage:     "sig",
		}
	}

	// Check if the requested kid is present in the newly refreshed key set
	if refreshedRec, found := s.keys[kid]; found {
		delete(s.quarantinedKids, kid)
		return refreshedRec.PublicKey, nil
	}

	s.desyncEventsCount++
	s.quarantinedKids[kid] = now
	return "", fmt.Errorf("%w: key %s absent even after remote JWKS refresh", ErrUnknownKid, kid)
}

// GetDesyncPostmortem generates incident analysis metrics.
func (s *JWKSDesyncSentinel) GetDesyncPostmortem(incidentID string) map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"incident_id":        incidentID,
		"status":             "RESOLVED",
		"total_refreshes":    s.refreshCount,
		"desync_events":      s.desyncEventsCount,
		"cached_keys_count":  len(s.keys),
		"quarantined_keys":   len(s.quarantinedKids),
		"last_refresh_time":  s.lastRefreshTime.Format(time.RFC3339),
		"root_cause":         "Fixed-TTL cache failed to track out-of-band IdP RSA key rotation events.",
	}
}
