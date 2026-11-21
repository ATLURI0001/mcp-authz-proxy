package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

// RevocationReason specifies why a token was revoked.
type RevocationReason string

const (
	RevocationReasonCompromised RevocationReason = "REVOKED_COMPROMISED"
	RevocationReasonUserLogout  RevocationReason = "USER_LOGOUT"
	RevocationReasonAdminAction RevocationReason = "ADMIN_ACTION"
)

var (
	ErrEmptyTokenID       = errors.New("token ID or hash cannot be empty")
	ErrInvalidExpiry      = errors.New("token expiry must be in the future")
	ErrAlreadyRevoked     = errors.New("token is already present in blacklist")
)

// RevocationRecord stores metadata about a blacklisted token.
type RevocationRecord struct {
	TokenHash   string           `json:"token_hash"`
	Reason      RevocationReason `json:"reason"`
	RevokedAt   time.Time        `json:"revoked_at"`
	ExpiresAt   time.Time        `json:"expires_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// TokenBlacklist manages thread-safe token revocation and TTL-based pruning.
type TokenBlacklist struct {
	mu      sync.RWMutex
	records map[string]RevocationRecord
}

// NewTokenBlacklist constructs an empty revocation blacklist.
func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{
		records: make(map[string]RevocationRecord),
	}
}

// HashToken computes a deterministic SHA-256 hex digest of a token ID or raw bearer token.
func HashToken(rawTokenOrJTI string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(rawTokenOrJTI)))
	return hex.EncodeToString(sum[:])
}

// Revoke registers a token in the blacklist until its original expiration timestamp.
func (b *TokenBlacklist) Revoke(tokenOrJTI string, reason RevocationReason, expiresAt time.Time, metadata map[string]string) error {
	trimmed := strings.TrimSpace(tokenOrJTI)
	if trimmed == "" {
		return ErrEmptyTokenID
	}
	if !expiresAt.After(time.Now()) {
		return ErrInvalidExpiry
	}

	h := HashToken(trimmed)

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.records[h]; exists {
		return ErrAlreadyRevoked
	}

	metaCopy := make(map[string]string, len(metadata))
	for k, v := range metadata {
		metaCopy[k] = v
	}

	b.records[h] = RevocationRecord{
		TokenHash: h,
		Reason:    reason,
		RevokedAt: time.Now(),
		ExpiresAt: expiresAt,
		Metadata:  metaCopy,
	}

	return nil
}

// IsRevoked checks if a token ID or raw token is currently revoked.
func (b *TokenBlacklist) IsRevoked(tokenOrJTI string) (bool, *RevocationRecord) {
	trimmed := strings.TrimSpace(tokenOrJTI)
	if trimmed == "" {
		return false, nil
	}

	h := HashToken(trimmed)

	b.mu.RLock()
	defer b.mu.RUnlock()

	rec, exists := b.records[h]
	if !exists {
		return false, nil
	}

	// If entry has already passed expiry, treat as not revoked (expired in JWT logic)
	if time.Now().After(rec.ExpiresAt) {
		return false, nil
	}

	recCopy := rec
	return true, &recCopy
}

// PurgeExpired removes all blacklist entries whose original JWT expiration has passed.
func (b *TokenBlacklist) PurgeExpired(now time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	purgedCount := 0
	for h, rec := range b.records {
		if now.After(rec.ExpiresAt) {
			delete(b.records, h)
			purgedCount++
		}
	}

	return purgedCount
}

// Count returns the active number of revoked tokens in the blacklist.
func (b *TokenBlacklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.records)
}
