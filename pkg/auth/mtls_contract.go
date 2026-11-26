package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var (
	ErrMtlsMissingSAN         = errors.New("mtls: client certificate missing required SAN entries")
	ErrMtlsInvalidSpiffeID    = errors.New("mtls: invalid SPIFFE ID format or trust domain mismatch")
	ErrMtlsUnauthorizedNS    = errors.New("mtls: SPIFFE namespace not authorized")
	ErrMtlsCertificateExpired = errors.New("mtls: client certificate is expired or not yet valid")
	ErrMtlsWildcardDisallowed = errors.New("mtls: wildcard SAN entries are strictly forbidden")
)

// ValidatedClientIdentity holds claims extracted from an mTLS client certificate.
type ValidatedClientIdentity struct {
	TrustDomain    string
	Namespace      string
	ServiceAccount string
	SpiffeID       string
	DNSNames       []string
	ExpiresAt      time.Time
}

// MtlsContractEnforcer enforces schema and boundary invariants on mTLS certificates.
type MtlsContractEnforcer struct {
	AllowedTrustDomains map[string]bool
	AllowedNamespaces   map[string]bool
	RequireSpiffeID     bool
	ClockFunc           func() time.Time
}

// NewMtlsContractEnforcer creates an enforcer with defined trust domains and namespaces.
func NewMtlsContractEnforcer(trustDomains []string, namespaces []string, requireSpiffe bool) *MtlsContractEnforcer {
	tdMap := make(map[string]bool)
	for _, td := range trustDomains {
		tdMap[strings.ToLower(td)] = true
	}

	nsMap := make(map[string]bool)
	for _, ns := range namespaces {
		nsMap[strings.ToLower(ns)] = true
	}

	return &MtlsContractEnforcer{
		AllowedTrustDomains: tdMap,
		AllowedNamespaces:   nsMap,
		RequireSpiffeID:     requireSpiffe,
		ClockFunc:           time.Now,
	}
}

// CertClaims represents metadata parsed from an x509 certificate.
type CertClaims struct {
	URIs      []*url.URL
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
}

// Validate enforces mTLS schema invariants against client certificate claims.
func (e *MtlsContractEnforcer) Validate(claims CertClaims) (*ValidatedClientIdentity, error) {
	now := e.ClockFunc()

	// 1. Time validity check
	if now.Before(claims.NotBefore) || now.After(claims.NotAfter) {
		return nil, ErrMtlsCertificateExpired
	}

	// 2. Reject wildcards in DNS SANs
	for _, dns := range claims.DNSNames {
		if strings.Contains(dns, "*") {
			return nil, ErrMtlsWildcardDisallowed
		}
	}

	// 3. Extract and validate SPIFFE ID
	var spiffeURI *url.URL
	for _, u := range claims.URIs {
		if u != nil && strings.EqualFold(u.Scheme, "spiffe") {
			spiffeURI = u
			break
		}
	}

	if spiffeURI == nil {
		if e.RequireSpiffeID {
			return nil, ErrMtlsMissingSAN
		}
		if len(claims.DNSNames) == 0 {
			return nil, ErrMtlsMissingSAN
		}
		return &ValidatedClientIdentity{
			DNSNames:  claims.DNSNames,
			ExpiresAt: claims.NotAfter,
		}, nil
	}

	// Validate SPIFFE URI structure: spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>
	trustDomain := strings.ToLower(spiffeURI.Host)
	if trustDomain == "" || !e.AllowedTrustDomains[trustDomain] {
		return nil, fmt.Errorf("%w: unrecognized trust domain '%s'", ErrMtlsInvalidSpiffeID, trustDomain)
	}

	parts := strings.Split(strings.Trim(spiffeURI.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "ns" || parts[2] != "sa" {
		return nil, fmt.Errorf("%w: expected /ns/<namespace>/sa/<serviceaccount>, got '%s'", ErrMtlsInvalidSpiffeID, spiffeURI.Path)
	}

	namespace := strings.ToLower(parts[1])
	serviceAccount := parts[3]

	if len(e.AllowedNamespaces) > 0 && !e.AllowedNamespaces[namespace] {
		return nil, fmt.Errorf("%w: namespace '%s' not permitted", ErrMtlsUnauthorizedNS, namespace)
	}

	return &ValidatedClientIdentity{
		TrustDomain:    trustDomain,
		Namespace:      namespace,
		ServiceAccount: serviceAccount,
		SpiffeID:       spiffeURI.String(),
		DNSNames:       claims.DNSNames,
		ExpiresAt:      claims.NotAfter,
	}, nil
}
