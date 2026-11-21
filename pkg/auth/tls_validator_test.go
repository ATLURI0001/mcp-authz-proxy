package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func createTestCert(
	t *testing.T,
	cn string,
	dnsNames []string,
	uris []*url.URL,
	notBefore, notAfter time.Time,
	keyUsage x509.KeyUsage,
) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Atlas MCP Security"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		URIs:                  uris,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	return cert
}

func TestClientCertValidator_ValidCert(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	spiffeURI, _ := url.Parse("spiffe://cluster.local/ns/prod/sa/mcp-gateway")

	cert := createTestCert(
		t,
		"mcp-gateway.corp.internal",
		[]string{"mcp-gateway.corp.internal"},
		[]*url.URL{spiffeURI},
		now.Add(-24*time.Hour),
		now.Add(30*24*time.Hour),
		x509.KeyUsageDigitalSignature,
	)

	validator := NewClientCertValidator(
		[]string{"corp.internal"},
		[]string{"spiffe://cluster.local/ns/prod"},
		14,
	)

	status, err := validator.ValidateClientCert(cert, now)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if status.DaysRemaining < 29 || status.DaysRemaining > 30 {
		t.Errorf("expected ~30 days remaining, got %d", status.DaysRemaining)
	}
	if status.IsNearExpiry {
		t.Errorf("expected not near expiry with 30 days remaining")
	}
	if status.MatchedSAN != "spiffe://cluster.local/ns/prod/sa/mcp-gateway" {
		t.Errorf("unexpected matched SAN: %s", status.MatchedSAN)
	}
}

func TestClientCertValidator_ExpiredAndNotYetValid(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	// Expired Cert
	expiredCert := createTestCert(
		t,
		"agent.corp.internal",
		[]string{"agent.corp.internal"},
		nil,
		now.Add(-60*24*time.Hour),
		now.Add(-1*time.Hour),
		x509.KeyUsageDigitalSignature,
	)

	validator := NewClientCertValidator([]string{"corp.internal"}, nil, 14)

	_, err := validator.ValidateClientCert(expiredCert, now)
	if err == nil {
		t.Fatalf("expected ErrCertificateExpired, got nil")
	}

	// Future Cert
	futureCert := createTestCert(
		t,
		"agent.corp.internal",
		[]string{"agent.corp.internal"},
		nil,
		now.Add(1*time.Hour),
		now.Add(30*24*time.Hour),
		x509.KeyUsageDigitalSignature,
	)

	_, err = validator.ValidateClientCert(futureCert, now)
	if err == nil {
		t.Fatalf("expected ErrCertificateNotYetValid, got nil")
	}
}

func TestClientCertValidator_Revocation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	cert := createTestCert(
		t,
		"agent.corp.internal",
		[]string{"agent.corp.internal"},
		nil,
		now.Add(-1*time.Hour),
		now.Add(30*24*time.Hour),
		x509.KeyUsageDigitalSignature,
	)

	validator := NewClientCertValidator([]string{"corp.internal"}, nil, 14)

	fp := ComputeFingerprint(cert)
	validator.RevokeFingerprint(fp, "Key compromise reported by security team")

	_, err := validator.ValidateClientCert(cert, now)
	if err == nil {
		t.Fatalf("expected ErrCertificateRevoked, got nil")
	}
}

func TestClientCertValidator_DisallowedSAN(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	cert := createTestCert(
		t,
		"untrusted.external.org",
		[]string{"untrusted.external.org"},
		nil,
		now.Add(-1*time.Hour),
		now.Add(30*24*time.Hour),
		x509.KeyUsageDigitalSignature,
	)

	validator := NewClientCertValidator([]string{"corp.internal"}, []string{"spiffe://corp"}, 14)

	_, err := validator.ValidateClientCert(cert, now)
	if err == nil {
		t.Fatalf("expected ErrDisallowedSAN, got nil")
	}
}
