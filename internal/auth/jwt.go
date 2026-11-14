// Package auth validates access tokens against a fixed, operator-selected issuer.
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Identity struct {
	Subject string
	Scopes  map[string]bool
}
type Verifier interface {
	Verify(context.Context, string) (Identity, error)
}
type Claims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}
type JWT struct {
	Issuer, Audience, JWKSURL string
	Client                    *http.Client
	Leeway                    time.Duration
	mu                        sync.Mutex
	keys                      map[string]*rsa.PublicKey
	fetched                   time.Time
	revMu                     sync.RWMutex
	revoked                   map[string]time.Time
}

// Revoke adds a token JTI to the in-memory revocation cache until expiresAt,
// automatically pruning any previously expired entries to bound memory usage.
func (v *JWT) Revoke(jti string, expiresAt time.Time) {
	if jti == "" {
		return
	}
	now := time.Now()
	if !expiresAt.After(now) {
		return
	}
	v.revMu.Lock()
	defer v.revMu.Unlock()
	if v.revoked == nil {
		v.revoked = make(map[string]time.Time)
	}
	for id, exp := range v.revoked {
		if !exp.After(now) {
			delete(v.revoked, id)
		}
	}
	v.revoked[jti] = expiresAt
}

// PruneRevoked removes expired JTI revocation entries and returns the remaining active count.
func (v *JWT) PruneRevoked(now time.Time) int {
	v.revMu.Lock()
	defer v.revMu.Unlock()
	for id, exp := range v.revoked {
		if !exp.After(now) {
			delete(v.revoked, id)
		}
	}
	return len(v.revoked)
}

// IsRevoked reports whether jti is currently actively revoked.
func (v *JWT) IsRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	now := time.Now()
	v.revMu.RLock()
	exp, exists := v.revoked[jti]
	v.revMu.RUnlock()
	return exists && exp.After(now)
}

func (v *JWT) Verify(ctx context.Context, raw string) (Identity, error) {
	c := &Claims{}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.Issuer),
		jwt.WithAudience(v.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	}
	if v.Leeway > 0 {
		opts = append(opts, jwt.WithLeeway(v.Leeway))
	}
	_, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("missing key id")
		}
		return v.key(ctx, kid)
	}, opts...)
	if err != nil || c.Subject == "" {
		return Identity{}, errors.New("invalid access token")
	}
	if c.ID != "" && v.IsRevoked(c.ID) {
		return Identity{}, errors.New("token revoked")
	}
	scopes := map[string]bool{}
	// OAuth scopes are space-delimited, not comma-separated.
	for _, s := range splitScopes(c.Scope) {
		scopes[s] = true
	}
	return Identity{c.Subject, scopes}, nil
}
func splitScopes(s string) []string {
	return strings.Fields(s)
}
func (v *JWT) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	// Bound refreshes, including unknown kid attacks. Rotation overlap should exceed 60s.
	if time.Since(v.fetched) < time.Minute {
		if k := v.keys[kid]; k != nil {
			return k, nil
		}
		return nil, errors.New("unknown key")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", v.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("JWKS unavailable")
	}
	var set struct {
		Keys []struct{ Kty, Kid, Use, Alg, N, E string }
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 262145))
	if err != nil || len(b) > 262144 {
		return nil, errors.New("JWKS size")
	}
	if err = json.Unmarshal(b, &set); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if j.Kty != "RSA" || j.Kid == "" || (j.Use != "" && j.Use != "sig") || (j.Alg != "" && j.Alg != "RS256") {
			continue
		}
		n, e1 := base64.RawURLEncoding.DecodeString(j.N)
		e, e2 := base64.RawURLEncoding.DecodeString(j.E)
		if e1 != nil || e2 != nil || len(e) > 4 || len(e) == 0 {
			continue
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent*256 + int(b)
		}
		modulus := new(big.Int).SetBytes(n)
		if modulus.BitLen() < 2048 || exponent < 3 || exponent%2 == 0 {
			continue
		}
		if _, exists := keys[j.Kid]; exists {
			return nil, errors.New("duplicate key id")
		}
		keys[j.Kid] = &rsa.PublicKey{N: modulus, E: exponent}
	}
	v.keys = keys
	v.fetched = time.Now()
	if k := keys[kid]; k != nil {
		return k, nil
	}
	return nil, errors.New("unknown key")
}
