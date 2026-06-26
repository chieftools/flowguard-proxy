package certmanager

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCombinedPEM(t *testing.T, path string, cert *tls.Certificate) {
	t.Helper()

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})

	var keyPEM []byte
	switch key := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("marshal EC key: %v", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})
	default:
		t.Fatalf("unsupported private key type: %T", cert.PrivateKey)
	}

	body := append(certPEM, keyPEM...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write combined PEM: %v", err)
	}
}

func TestProbeCertificateDirectoryAcceptsValidCombinedPEM(t *testing.T) {
	dir := t.TempDir()
	cert := createSelfSignedRSACert(t, "example.com", time.Now().Add(24*time.Hour))
	writeCombinedPEM(t, filepath.Join(dir, "example.pem"), cert)

	summary, err := ProbeCertificateDirectorySummary(dir)
	if err != nil {
		t.Fatalf("ProbeCertificateDirectorySummary: %v", err)
	}
	if summary.CertificateCount != 1 {
		t.Fatalf("expected 1 certificate, got %d", summary.CertificateCount)
	}
	if summary.HostnameCount != 1 {
		t.Fatalf("expected 1 hostname, got %d", summary.HostnameCount)
	}
}

func TestProbeCertificateDirectoryRejectsExpiredAndInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	expired := createSelfSignedRSACert(t, "example.com", time.Now().Add(-24*time.Hour))
	writeCombinedPEM(t, filepath.Join(dir, "expired.pem"), expired)
	if err := os.WriteFile(filepath.Join(dir, "invalid.pem"), []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("write invalid PEM: %v", err)
	}

	err := ProbeCertificateDirectory(dir)
	if err == nil {
		t.Fatal("expected invalid directory to be rejected")
	}
	if !strings.Contains(err.Error(), "no valid certificates") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProbeCertificateDirectoryRejectsMissingPath(t *testing.T) {
	err := ProbeCertificateDirectory(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected missing directory to be rejected")
	}
}

func TestProbeNginxConfigAcceptsConfigWithoutCertificates(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(configPath, []byte("events {}\nhttp {}\n"), 0o644); err != nil {
		t.Fatalf("write nginx config: %v", err)
	}

	summary, err := ProbeNginxConfigSummary(configPath)
	if err != nil {
		t.Fatalf("ProbeNginxConfigSummary: %v", err)
	}
	if summary.CertificateCount != 0 {
		t.Fatalf("expected 0 certificates, got %d", summary.CertificateCount)
	}
	if summary.HostnameCount != 0 {
		t.Fatalf("expected 0 hostnames, got %d", summary.HostnameCount)
	}
	if summary.ConfigFileCount != 1 {
		t.Fatalf("expected 1 config file, got %d", summary.ConfigFileCount)
	}
}

func TestProbeNginxConfigRejectsMissingPath(t *testing.T) {
	err := ProbeNginxConfig(filepath.Join(t.TempDir(), "missing.conf"))
	if err == nil {
		t.Fatal("expected missing nginx config to be rejected")
	}
}
