package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestTokenBlacklist_BasicRevocation(t *testing.T) {
	bl := NewTokenBlacklist()
	token := "jti-jwt-token-12345"
	exp := time.Now().Add(1 * time.Hour)

	// Check initially not revoked
	revoked, _ := bl.IsRevoked(token)
	if revoked {
		t.Fatalf("expected token not to be revoked initially")
	}

	// Revoke
	err := bl.Revoke(token, RevocationReasonCompromised, exp, map[string]string{"actor": "secops"})
	if err != nil {
		t.Fatalf("unexpected revocation error: %v", err)
	}

	// Verify revoked
	revoked, rec := bl.IsRevoked(token)
	if !revoked {
		t.Fatalf("expected token to be revoked")
	}
	if rec.Reason != RevocationReasonCompromised {
		t.Errorf("expected reason %s, got %s", RevocationReasonCompromised, rec.Reason)
	}
	if rec.Metadata["actor"] != "secops" {
		t.Errorf("expected metadata actor 'secops', got %s", rec.Metadata["actor"])
	}

	// Duplicate revocation fails
	if err := bl.Revoke(token, RevocationReasonAdminAction, exp, nil); err != ErrAlreadyRevoked {
		t.Errorf("expected ErrAlreadyRevoked, got %v", err)
	}
}

func TestTokenBlacklist_Validation(t *testing.T) {
	bl := NewTokenBlacklist()

	// Empty token
	if err := bl.Revoke("", RevocationReasonUserLogout, time.Now().Add(time.Hour), nil); err != ErrEmptyTokenID {
		t.Errorf("expected ErrEmptyTokenID, got %v", err)
	}

	// Expiry in past
	past := time.Now().Add(-10 * time.Minute)
	if err := bl.Revoke("t1", RevocationReasonUserLogout, past, nil); err != ErrInvalidExpiry {
		t.Errorf("expected ErrInvalidExpiry, got %v", err)
	}
}

func TestTokenBlacklist_PurgeExpired(t *testing.T) {
	bl := NewTokenBlacklist()
	now := time.Now()

	// Add 2 tokens expiring soon, 1 expiring in 2 hours
	bl.Revoke("t-exp-1", RevocationReasonUserLogout, now.Add(50*time.Millisecond), nil)
	bl.Revoke("t-exp-2", RevocationReasonUserLogout, now.Add(50*time.Millisecond), nil)
	bl.Revoke("t-long", RevocationReasonAdminAction, now.Add(2*time.Hour), nil)

	if bl.Count() != 3 {
		t.Fatalf("expected count 3, got %d", bl.Count())
	}

	// Purge after 100ms
	future := now.Add(100 * time.Millisecond)
	purged := bl.PurgeExpired(future)
	if purged != 2 {
		t.Errorf("expected 2 purged tokens, got %d", purged)
	}

	if bl.Count() != 1 {
		t.Errorf("expected 1 remaining token, got %d", bl.Count())
	}

	revoked, _ := bl.IsRevoked("t-long")
	if !revoked {
		t.Errorf("expected t-long to still be revoked")
	}
}

func TestTokenBlacklist_Concurrency(t *testing.T) {
	bl := NewTokenBlacklist()
	var wg sync.WaitGroup
	workers := 8
	iterations := 50
	exp := time.Now().Add(time.Hour)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				tokenID := fmt.Sprintf("worker-%d-token-%d", workerID, i)
				_ = bl.Revoke(tokenID, RevocationReasonUserLogout, exp, nil)
				isRev, _ := bl.IsRevoked(tokenID)
				if !isRev {
					t.Errorf("expected token %s to be revoked", tokenID)
				}
			}
		}(w)
	}

	wg.Wait()
	if bl.Count() != workers*iterations {
		t.Errorf("expected count %d, got %d", workers*iterations, bl.Count())
	}
}
