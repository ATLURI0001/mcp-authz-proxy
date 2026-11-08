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
	mu                        sync.Mutex
	keys                      map[string]*rsa.PublicKey
	fetched                   time.Time
}

func (v *JWT) Verify(ctx context.Context, raw string) (Identity, error) {
	c := &Claims{}
	_, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("missing key id")
		}
		return v.key(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(v.Issuer), jwt.WithAudience(v.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || c.Subject == "" {
		return Identity{}, errors.New("invalid access token")
	}
	scopes := map[string]bool{}
	// OAuth scopes are space-delimited, not comma-separated.
	for _, s := range splitScopes(c.Scope) {
		scopes[s] = true
	}
	return Identity{c.Subject, scopes}, nil
}
func splitScopes(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
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
