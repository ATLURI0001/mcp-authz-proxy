package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestJWKSDesyncSentinel_LookupAndRotation(t *testing.T) {
	mockIdPStore := map[string]string{
		"key-v1": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----",
	}

	fetcher := func(issuer string) (map[string]string, error) {
		res := make(map[string]string)
		for k, v := range mockIdPStore {
			res[k] = v
		}
		return res, nil
	}

	cfg := JWKSDesyncSentinelConfig{
		MinRefreshInterval: 50 * time.Millisecond,
		KeyTTL:             1 * time.Hour,
		MaxCachedKeys:      10,
	}

	sentinel := NewJWKSDesyncSentinel(cfg, fetcher)

	// 1. Initial lookup -> triggers fetch and returns key-v1
	pubKey, err := sentinel.LookupKey("https://idp.example.com", "key-v1")
	if err != nil {
		t.Fatalf("unexpected error looking up initial key: %v", err)
	}
	if !strings.Contains(pubKey, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A") {
		t.Errorf("unexpected public key content: %s", pubKey)
	}

	// 2. Second lookup of cached key -> fast read without refresh
	pubKeyCached, err := sentinel.LookupKey("https://idp.example.com", "key-v1")
	if err != nil {
		t.Fatalf("unexpected error on cached lookup: %v", err)
	}
	if pubKeyCached != pubKey {
		t.Errorf("cached key mismatch")
	}

	// 3. IdP rotates key to key-v2
	mockIdPStore["key-v2"] = "-----BEGIN PUBLIC KEY-----\nNEW_ROTATED_KEY_MATERIAL...\n-----END PUBLIC KEY-----"

	// Wait for min refresh interval
	time.Sleep(60 * time.Millisecond)

	// Lookup of new rotated key-v2 -> sentinel detects desync, refreshes, and finds key-v2
	pubKeyRotated, err := sentinel.LookupKey("https://idp.example.com", "key-v2")
	if err != nil {
		t.Fatalf("failed to retrieve newly rotated key: %v", err)
	}
	if !strings.Contains(pubKeyRotated, "NEW_ROTATED_KEY_MATERIAL") {
		t.Errorf("expected new key material, got: %s", pubKeyRotated)
	}
}

func TestJWKSDesyncSentinel_UnknownKeyQuarantine(t *testing.T) {
	mockIdPStore := map[string]string{
		"key-legit": "pub-key-1",
	}

	fetcher := func(issuer string) (map[string]string, error) {
		return mockIdPStore, nil
	}

	cfg := JWKSDesyncSentinelConfig{
		MinRefreshInterval: 50 * time.Millisecond,
	}

	sentinel := NewJWKSDesyncSentinel(cfg, fetcher)

	// Lookup of non-existent key-bogus
	_, err := sentinel.LookupKey("https://idp.example.com", "key-bogus")
	if err == nil {
		t.Fatal("expected error for bogus key, got nil")
	}
	if !errors.Is(err, ErrUnknownKid) {
		t.Errorf("expected ErrUnknownKid, got: %v", err)
	}

	// Verify postmortem generation
	report := sentinel.GetDesyncPostmortem("INC-2026-AUTHZ-7719")
	if report["incident_id"] != "INC-2026-AUTHZ-7719" {
		t.Errorf("unexpected incident ID: %v", report["incident_id"])
	}
	if report["quarantined_keys"].(int) != 1 {
		t.Errorf("expected 1 quarantined key, got: %v", report["quarantined_keys"])
	}
}
