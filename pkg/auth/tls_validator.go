package auth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrNilCertificate       = errors.New("client certificate cannot be nil")
	ErrCertificateExpired   = errors.New("client certificate is expired")
	ErrCertificateNotYetValid = errors.New("client certificate is not yet valid")
	ErrCertificateRevoked   = errors.New("client certificate fingerprint has been revoked")
	ErrDisallowedSAN        = errors.New("certificate SAN or SPIFFE ID does not match allowed patterns")
	ErrInvalidKeyUsage      = errors.New("certificate lacks required digital signature or key encipherment usage")
)

// CertValidationStatus summarizes the validation evaluation of an X.509 client certificate.
type CertValidationStatus struct {
	SubjectDN         string    `json:"subject_dn"`
	IssuerDN          string    `json:"issuer_dn"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	DaysRemaining     int       `json:"days_remaining"`
	IsNearExpiry      bool      `json:"is_near_expiry"`
	MatchedSAN        string    `json:"matched_san"`
	SpiffeID          string    `json:"spiffe_id,omitempty"`
}

// ClientCertValidator configures mTLS client certificate verification rules and revocation lists.
type ClientCertValidator struct {
	mu                sync.RWMutex
	allowedDomains    []string
	allowedSpiffePrefixes []string
	revokedFingerprints map[string]string // sha256 -> reason
	expiryWarningDays int
}

// NewClientCertValidator creates a configured client certificate validator.
func NewClientCertValidator(
	allowedDomains []string,
	allowedSpiffePrefixes []string,
	expiryWarningDays int,
) *ClientCertValidator {
	if expiryWarningDays <= 0 {
		expiryWarningDays = 14
	}

	normDomains := make([]string, 0, len(allowedDomains))
	for _, d := range allowedDomains {
		trimmed := strings.ToLower(strings.TrimSpace(d))
		if trimmed != "" {
			normDomains = append(normDomains, trimmed)
		}
	}

	normSpiffe := make([]string, 0, len(allowedSpiffePrefixes))
	for _, s := range allowedSpiffePrefixes {
		trimmed := strings.ToLower(strings.TrimSpace(s))
		if trimmed != "" {
			normSpiffe = append(normSpiffe, trimmed)
		}
	}

	return &ClientCertValidator{
		allowedDomains:        normDomains,
		allowedSpiffePrefixes: normSpiffe,
		revokedFingerprints:   make(map[string]string),
		expiryWarningDays:     expiryWarningDays,
	}
}

// RevokeFingerprint marks a certificate SHA-256 fingerprint as explicitly revoked.
func (v *ClientCertValidator) RevokeFingerprint(fingerprintHex, reason string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	cleaned := strings.ToLower(strings.ReplaceAll(fingerprintHex, ":", ""))
	v.revokedFingerprints[cleaned] = reason
}

// ComputeFingerprint returns uppercase hex colon-delimited SHA-256 fingerprint of a cert.
func ComputeFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// ValidateClientCert rigorously verifies an mTLS peer certificate against temporal, SAN, and revocation rules.
func (v *ClientCertValidator) ValidateClientCert(
	cert *x509.Certificate,
	currentTime time.Time,
) (*CertValidationStatus, error) {
	if cert == nil {
		return nil, ErrNilCertificate
	}

	now := currentTime
	if now.IsZero() {
		now = time.Now()
	}

	// 1. Temporal validation
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("%w: valid from %s", ErrCertificateNotYetValid, cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("%w: expired at %s", ErrCertificateExpired, cert.NotAfter)
	}

	// 2. Revocation check
	fp := ComputeFingerprint(cert)
	v.mu.RLock()
	reason, isRevoked := v.revokedFingerprints[fp]
	v.mu.RUnlock()

	if isRevoked {
		return nil, fmt.Errorf("%w: %s (fingerprint %s)", ErrCertificateRevoked, reason, fp)
	}

	// 3. Key Usage checks (DigitalSignature or KeyEncipherment required for TLS authentication)
	if cert.KeyUsage != 0 {
		hasDigitalSig := (cert.KeyUsage & x509.KeyUsageDigitalSignature) != 0
		hasKeyEncipher := (cert.KeyUsage & x509.KeyUsageKeyEncipherment) != 0
		if !hasDigitalSig && !hasKeyEncipher {
			return nil, ErrInvalidKeyUsage
		}
	}

	// 4. SAN / SPIFFE validation
	matchedSAN, spiffeID, err := v.validateSANs(cert)
	if err != nil {
		return nil, err
	}

	// 5. Expiration warning computation
	durationLeft := cert.NotAfter.Sub(now)
	daysLeft := int(durationLeft.Hours() / 24)
	isNearExpiry := daysLeft <= v.expiryWarningDays

	return &CertValidationStatus{
		SubjectDN:         cert.Subject.String(),
		IssuerDN:          cert.Issuer.String(),
		FingerprintSHA256: fp,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		DaysRemaining:     daysLeft,
		IsNearExpiry:      isNearExpiry,
		MatchedSAN:        matchedSAN,
		SpiffeID:          spiffeID,
	}, nil
}

func (v *ClientCertValidator) validateSANs(cert *x509.Certificate) (string, string, error) {
	// If no domain or SPIFFE constraints configured, accept subject CN
	if len(v.allowedDomains) == 0 && len(v.allowedSpiffePrefixes) == 0 {
		return cert.Subject.CommonName, "", nil
	}

	// Check SPIFFE URIs
	var foundSpiffe string
	for _, u := range cert.URIs {
		uriStr := strings.ToLower(u.String())
		if strings.HasPrefix(uriStr, "spiffe://") {
			foundSpiffe = uriStr
			for _, prefix := range v.allowedSpiffePrefixes {
				if strings.HasPrefix(uriStr, prefix) {
					return uriStr, uriStr, nil
				}
			}
		}
	}

	// Check DNS SANs
	for _, dns := range cert.DNSNames {
		dnsLower := strings.ToLower(dns)
		for _, domain := range v.allowedDomains {
			if dnsLower == domain || strings.HasSuffix(dnsLower, "."+domain) {
				return dns, foundSpiffe, nil
			}
		}
	}

	// Check Common Name as fallback
	cnLower := strings.ToLower(cert.Subject.CommonName)
	for _, domain := range v.allowedDomains {
		if cnLower == domain || strings.HasSuffix(cnLower, "."+domain) {
			return cert.Subject.CommonName, foundSpiffe, nil
		}
	}

	return "", "", fmt.Errorf("%w: subject CN='%s', DNSNames=%v, URIs=%v",
		ErrDisallowedSAN, cert.Subject.CommonName, cert.DNSNames, cert.URIs)
}
