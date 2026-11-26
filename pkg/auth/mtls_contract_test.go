package auth

import (
	"errors"
	"net/url"
	"testing"
	"time"
)

func TestMtlsContractEnforcer_ValidSpiffe(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	enforcer := NewMtlsContractEnforcer([]string{"cluster.local"}, []string{"prod", "staging"}, true)
	enforcer.ClockFunc = func() time.Time { return now }

	spiffeURL, err := url.Parse("spiffe://cluster.local/ns/prod/sa/payment-gateway")
	if err != nil {
		t.Fatalf("unexpected url parse error: %v", err)
	}

	claims := CertClaims{
		URIs:      []*url.URL{spiffeURL},
		DNSNames:  []string{"payment-gateway.prod.svc"},
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
	}

	identity, err := enforcer.Validate(claims)
	if err != nil {
		t.Fatalf("expected valid mTLS claims, got: %v", err)
	}

	if identity.TrustDomain != "cluster.local" {
		t.Errorf("expected trust domain cluster.local, got %s", identity.TrustDomain)
	}
	if identity.Namespace != "prod" {
		t.Errorf("expected namespace prod, got %s", identity.Namespace)
	}
	if identity.ServiceAccount != "payment-gateway" {
		t.Errorf("expected service account payment-gateway, got %s", identity.ServiceAccount)
	}
}

func TestMtlsContractEnforcer_ExpiredCertificate(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	enforcer := NewMtlsContractEnforcer([]string{"cluster.local"}, nil, false)
	enforcer.ClockFunc = func() time.Time { return now }

	claims := CertClaims{
		DNSNames:  []string{"agent.internal"},
		NotBefore: now.Add(-48 * time.Hour),
		NotAfter:  now.Add(-1 * time.Hour), // Expired
	}

	_, err := enforcer.Validate(claims)
	if !errors.Is(err, ErrMtlsCertificateExpired) {
		t.Fatalf("expected ErrMtlsCertificateExpired, got %v", err)
	}
}

func TestMtlsContractEnforcer_DisallowWildcard(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	enforcer := NewMtlsContractEnforcer([]string{"cluster.local"}, nil, false)
	enforcer.ClockFunc = func() time.Time { return now }

	claims := CertClaims{
		DNSNames:  []string{"*.cluster.local"},
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(1 * time.Hour),
	}

	_, err := enforcer.Validate(claims)
	if !errors.Is(err, ErrMtlsWildcardDisallowed) {
		t.Fatalf("expected ErrMtlsWildcardDisallowed, got %v", err)
	}
}

func TestMtlsContractEnforcer_UnauthorizedNamespace(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	enforcer := NewMtlsContractEnforcer([]string{"cluster.local"}, []string{"prod"}, true)
	enforcer.ClockFunc = func() time.Time { return now }

	spiffeURL, _ := url.Parse("spiffe://cluster.local/ns/dev/sa/test-agent")
	claims := CertClaims{
		URIs:      []*url.URL{spiffeURL},
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(1 * time.Hour),
	}

	_, err := enforcer.Validate(claims)
	if !errors.Is(err, ErrMtlsUnauthorizedNS) {
		t.Fatalf("expected ErrMtlsUnauthorizedNS, got %v", err)
	}
}
