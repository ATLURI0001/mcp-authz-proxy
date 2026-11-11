package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestTokenValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "key1", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer server.Close()
	valid := func() Claims {
		return Claims{Scope: "mcp:connect tools:read", RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://issuer", Subject: "alice", Audience: jwt.ClaimStrings{"https://gateway/mcp"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute))}}
	}
	for _, tc := range []struct {
		name   string
		change func(*Claims)
		alg    jwt.SigningMethod
		kid    string
		ok     bool
	}{
		{"valid", func(*Claims) {}, jwt.SigningMethodRS256, "key1", true},
		{"wrong issuer", func(c *Claims) { c.Issuer = "https://evil" }, jwt.SigningMethodRS256, "key1", false},
		{"wrong audience", func(c *Claims) { c.Audience = jwt.ClaimStrings{"other"} }, jwt.SigningMethodRS256, "key1", false},
		{"expired", func(c *Claims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute)) }, jwt.SigningMethodRS256, "key1", false},
		{"missing expiry", func(c *Claims) { c.ExpiresAt = nil }, jwt.SigningMethodRS256, "key1", false},
		{"future not before", func(c *Claims) { c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour)) }, jwt.SigningMethodRS256, "key1", false},
		{"missing subject", func(c *Claims) { c.Subject = "" }, jwt.SigningMethodRS256, "key1", false},
		{"unknown kid", func(*Claims) {}, jwt.SigningMethodRS256, "other", false},
		{"algorithm confusion", func(*Claims) {}, jwt.SigningMethodHS256, "key1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.change(&c)
			tok := jwt.NewWithClaims(tc.alg, c)
			tok.Header["kid"] = tc.kid
			var signing any = key
			if tc.alg == jwt.SigningMethodHS256 {
				signing = []byte("wrong")
			}
			raw, e := tok.SignedString(signing)
			if e != nil {
				t.Fatal(e)
			}
			v := &JWT{Issuer: "https://issuer", Audience: "https://gateway/mcp", JWKSURL: server.URL}
			identity, e := v.Verify(context.Background(), raw)
			if (e == nil) != tc.ok {
				t.Fatalf("unexpected validation: %v", e)
			}
			if tc.ok && !identity.Scopes["tools:read"] {
				t.Fatal("scope missing")
			}
		})
	}
	v := &JWT{Issuer: "https://issuer", Audience: "https://gateway/mcp", JWKSURL: server.URL}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, valid())
	tok.Header["kid"] = "key1"
	raw, _ := tok.SignedString(key)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(context.Background(), raw); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestTokenRevocationAndLeeway(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "key1", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer server.Close()

	sign := func(c Claims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
		tok.Header["kid"] = "key1"
		raw, e := tok.SignedString(key)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}

	v := &JWT{
		Issuer:   "https://issuer",
		Audience: "https://gateway/mcp",
		JWKSURL:  server.URL,
		Leeway:   30 * time.Second,
	}

	// Token expired 10s ago succeeds within 30s clock-skew leeway
	skewed := sign(Claims{
		Scope: "tools:read",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://issuer",
			Subject:   "bob",
			ID:        "jti-skew-1",
			Audience:  jwt.ClaimStrings{"https://gateway/mcp"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-10 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	})
	if _, err := v.Verify(context.Background(), skewed); err != nil {
		t.Fatalf("expected token within leeway to verify: %v", err)
	}

	// Revoking JTI blocks subsequent verification
	v.Revoke("jti-skew-1", time.Now().Add(time.Hour))
	if !v.IsRevoked("jti-skew-1") {
		t.Fatal("expected jti-skew-1 to be marked revoked")
	}
	if _, err := v.Verify(context.Background(), skewed); err == nil {
		t.Fatal("expected revoked token to fail verification")
	}

	// Revoking an already-expired JTI does not retain stale entries; PruneRevoked evicts future ones at cutoff
	v.Revoke("jti-already-expired", time.Now().Add(-time.Second))
	if v.IsRevoked("jti-already-expired") {
		t.Fatal("already-expired jti must not be retained")
	}
	if remaining := v.PruneRevoked(time.Now().Add(2 * time.Hour)); remaining != 0 {
		t.Fatalf("expected 0 revoked entries after TTL eviction, got %d", remaining)
	}
}
