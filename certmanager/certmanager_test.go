package certmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"
)

// Helper function to create a test certificate
func createTestCert(t *testing.T, template, parent *x509.Certificate, pubKey interface{}, privKey interface{}) *tls.Certificate {
	t.Helper()

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	var privKeyPEM []byte
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		privKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("Failed to marshal EC private key: %v", err)
		}
		privKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	tlsCert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create TLS certificate: %v", err)
	}

	tlsCert.Leaf = cert
	return &tlsCert
}

// Create a self-signed RSA certificate
func createSelfSignedRSACert(t *testing.T, hostname string, notAfter time.Time) *tls.Certificate {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		DNSNames:  []string{hostname},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	return createTestCert(t, template, template, &privKey.PublicKey, privKey)
}

func TestGetTLSConfigAdvertisesHTTP2AndHTTP1(t *testing.T) {
	manager := &Manager{}

	tlsConfig := manager.GetTlsConfig()

	if !slices.Equal(tlsConfig.NextProtos, []string{"h2", "http/1.1"}) {
		t.Fatalf("unexpected ALPN protocols: %v", tlsConfig.NextProtos)
	}
}

func TestGetTLSConfigUsesConfiguredALPNProtocols(t *testing.T) {
	manager := &Manager{
		config: Config{
			TLSNextProtos: []string{"http/1.1"},
		},
	}

	tlsConfig := manager.GetTlsConfig()

	if !slices.Equal(tlsConfig.NextProtos, []string{"http/1.1"}) {
		t.Fatalf("unexpected ALPN protocols: %v", tlsConfig.NextProtos)
	}
}

// Create a CA-signed ECDSA certificate
func createCASignedECDSACert(t *testing.T, hostname string, notAfter time.Time) *tls.Certificate {
	t.Helper()

	// Create CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create ECDSA leaf cert
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		DNSNames:  []string{hostname},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	// Sign with CA key, but return the leaf cert with its own key
	certDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &ecKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("Failed to marshal EC private key: %v", err)
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	tlsCert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create TLS certificate: %v", err)
	}

	tlsCert.Leaf = cert
	return &tlsCert
}

// Create a wildcard certificate
func createWildcardCert(t *testing.T, domain string, notAfter time.Time, selfSigned bool) *tls.Certificate {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	hostname := "*." + domain
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		DNSNames:  []string{hostname},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	if selfSigned {
		return createTestCert(t, template, template, &privKey.PublicKey, privKey)
	}

	// Create with different issuer (CA-signed)
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA: %v", err)
	}

	// Create leaf certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create wildcard certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse wildcard certificate: %v", err)
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	tlsCert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create TLS certificate: %v", err)
	}

	tlsCert.Leaf = cert
	return &tlsCert
}

func TestGetCertificateForHostnameFallsBackWhenMatchesAreExpired(t *testing.T) {
	now := time.Now()
	defaultCert := createSelfSignedRSACert(t, "fallback.test", now.Add(24*time.Hour))
	expiredExactCert := createSelfSignedRSACert(t, "retired.test", now.Add(-time.Hour))
	expiredWildcardCert := createWildcardCert(t, "legacy.test", now.Add(-time.Hour), true)
	validExactCert := createSelfSignedRSACert(t, "active.test", now.Add(24*time.Hour))
	expiredDefaultCert := createSelfSignedRSACert(t, "expired-fallback.test", now.Add(-time.Hour))

	metadata := func(cert *tls.Certificate, path string) *certificateWithMetadata {
		return &certificateWithMetadata{
			cert:      cert,
			filePath:  path,
			notAfter:  cert.Leaf.NotAfter,
			isTrusted: isTrustedCertificate(cert.Leaf),
			keyType:   getKeyType(cert),
		}
	}

	tests := []struct {
		name            string
		hostname        string
		defaultHostname string
		hostnameCache   map[string][]*certificateWithMetadata
		want            *tls.Certificate
	}{
		{
			name:            "expired exact match uses default",
			hostname:        "retired.test",
			defaultHostname: "fallback.test",
			hostnameCache: map[string][]*certificateWithMetadata{
				"retired.test":  {metadata(expiredExactCert, "/certs/retired.pem")},
				"fallback.test": {metadata(defaultCert, "/certs/fallback.pem")},
			},
			want: defaultCert,
		},
		{
			name:            "expired wildcard match uses default",
			hostname:        "app.legacy.test",
			defaultHostname: "fallback.test",
			hostnameCache: map[string][]*certificateWithMetadata{
				"*.legacy.test": {metadata(expiredWildcardCert, "/certs/legacy.pem")},
				"fallback.test": {metadata(defaultCert, "/certs/fallback.pem")},
			},
			want: defaultCert,
		},
		{
			name:            "valid exact match remains preferred",
			hostname:        "active.test",
			defaultHostname: "fallback.test",
			hostnameCache: map[string][]*certificateWithMetadata{
				"active.test":   {metadata(validExactCert, "/certs/active.pem")},
				"fallback.test": {metadata(defaultCert, "/certs/fallback.pem")},
			},
			want: validExactCert,
		},
		{
			name:            "expired match and expired default return nil",
			hostname:        "retired.test",
			defaultHostname: "expired-fallback.test",
			hostnameCache: map[string][]*certificateWithMetadata{
				"retired.test":          {metadata(expiredExactCert, "/certs/retired.pem")},
				"expired-fallback.test": {metadata(expiredDefaultCert, "/certs/expired-fallback.pem")},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := &Manager{
				config:        Config{DefaultHostname: tt.defaultHostname},
				hostnameCache: tt.hostnameCache,
			}

			if got := manager.GetCertificateForHostname(tt.hostname); got != tt.want {
				t.Fatalf("GetCertificateForHostname(%q) returned %p, want %p", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestIsTrustedCertificate(t *testing.T) {
	tests := []struct {
		name     string
		certFunc func() *tls.Certificate
		want     bool
	}{
		{
			name: "self-signed certificate",
			certFunc: func() *tls.Certificate {
				return createSelfSignedRSACert(t, "example.com", time.Now().Add(24*time.Hour))
			},
			want: false, // Self-signed = not trusted
		},
		{
			name: "CA-signed certificate",
			certFunc: func() *tls.Certificate {
				return createCASignedECDSACert(t, "example.com", time.Now().Add(24*time.Hour))
			},
			want: true, // CA-signed = trusted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := tt.certFunc()
			got := isTrustedCertificate(cert.Leaf)
			if got != tt.want {
				t.Errorf("isTrustedCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetKeyType(t *testing.T) {
	tests := []struct {
		name     string
		certFunc func() *tls.Certificate
		want     string
	}{
		{
			name: "RSA certificate",
			certFunc: func() *tls.Certificate {
				return createSelfSignedRSACert(t, "example.com", time.Now().Add(24*time.Hour))
			},
			want: "RSA",
		},
		{
			name: "ECDSA certificate",
			certFunc: func() *tls.Certificate {
				return createCASignedECDSACert(t, "example.com", time.Now().Add(24*time.Hour))
			},
			want: "ECDSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := tt.certFunc()
			got := getKeyType(cert)
			if got != tt.want {
				t.Errorf("getKeyType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSelectBestCertificate(t *testing.T) {
	now := time.Now()
	future := now.Add(90 * 24 * time.Hour)
	nearFuture := now.Add(30 * 24 * time.Hour)
	past := now.Add(-24 * time.Hour)

	tests := []struct {
		name       string
		candidates func() []*certificateWithMetadata
		wantNil    bool
		checkFunc  func(*testing.T, *tls.Certificate)
	}{
		{
			name: "empty candidates",
			candidates: func() []*certificateWithMetadata {
				return []*certificateWithMetadata{}
			},
			wantNil: true,
		},
		{
			name: "all expired certificates",
			candidates: func() []*certificateWithMetadata {
				cert1 := createSelfSignedRSACert(t, "example.com", past)
				cert2 := createCASignedECDSACert(t, "example.com", past)
				return []*certificateWithMetadata{
					{cert: cert1, notAfter: cert1.Leaf.NotAfter, isTrusted: false, keyType: "RSA"},
					{cert: cert2, notAfter: cert2.Leaf.NotAfter, isTrusted: true, keyType: "ECDSA"},
				}
			},
			wantNil: true,
		},
		{
			name: "prefer CA-signed over self-signed",
			candidates: func() []*certificateWithMetadata {
				selfSigned := createSelfSignedRSACert(t, "example.com", future)
				caSigned := createCASignedECDSACert(t, "example.com", future)
				return []*certificateWithMetadata{
					{cert: selfSigned, notAfter: selfSigned.Leaf.NotAfter, isTrusted: false, keyType: "RSA", isWildcard: false},
					{cert: caSigned, notAfter: caSigned.Leaf.NotAfter, isTrusted: true, keyType: "ECDSA", isWildcard: false},
				}
			},
			wantNil: false,
			checkFunc: func(t *testing.T, cert *tls.Certificate) {
				if !isTrustedCertificate(cert.Leaf) {
					t.Error("Expected CA-signed certificate, got self-signed")
				}
			},
		},
		{
			name: "prefer wildcard over exact match",
			candidates: func() []*certificateWithMetadata {
				exact := createCASignedECDSACert(t, "example.com", future)
				wildcard := createWildcardCert(t, "example.com", future, false)
				return []*certificateWithMetadata{
					{cert: exact, notAfter: exact.Leaf.NotAfter, isTrusted: true, keyType: "ECDSA", isWildcard: false},
					{cert: wildcard, notAfter: wildcard.Leaf.NotAfter, isTrusted: true, keyType: "RSA", isWildcard: true},
				}
			},
			wantNil: false,
			checkFunc: func(t *testing.T, cert *tls.Certificate) {
				// Check if it's a wildcard cert
				if len(cert.Leaf.DNSNames) == 0 || cert.Leaf.DNSNames[0][0] != '*' {
					t.Error("Expected wildcard certificate, got exact match")
				}
			},
		},
		{
			name: "prefer ECDSA over RSA (same CA-signed, same wildcard status)",
			candidates: func() []*certificateWithMetadata {
				rsaCert := createSelfSignedRSACert(t, "example.com", future)
				ecdsaCert := createCASignedECDSACert(t, "example.com", future)
				return []*certificateWithMetadata{
					{cert: rsaCert, notAfter: rsaCert.Leaf.NotAfter, isTrusted: false, keyType: "RSA", isWildcard: false},
					{cert: ecdsaCert, notAfter: ecdsaCert.Leaf.NotAfter, isTrusted: false, keyType: "ECDSA", isWildcard: false},
				}
			},
			wantNil: false,
			checkFunc: func(t *testing.T, cert *tls.Certificate) {
				if _, ok := cert.Leaf.PublicKey.(*ecdsa.PublicKey); !ok {
					t.Error("Expected ECDSA certificate, got RSA")
				}
			},
		},
		{
			name: "prefer longer validity period",
			candidates: func() []*certificateWithMetadata {
				shortValidity := createCASignedECDSACert(t, "example.com", nearFuture)
				longValidity := createCASignedECDSACert(t, "example.com", future)
				return []*certificateWithMetadata{
					{cert: shortValidity, notAfter: shortValidity.Leaf.NotAfter, isTrusted: true, keyType: "ECDSA", isWildcard: false},
					{cert: longValidity, notAfter: longValidity.Leaf.NotAfter, isTrusted: true, keyType: "ECDSA", isWildcard: false},
				}
			},
			wantNil: false,
			checkFunc: func(t *testing.T, cert *tls.Certificate) {
				// The selected cert should have longer validity
				if cert.Leaf.NotAfter.Before(future.Add(-24 * time.Hour)) {
					t.Error("Expected certificate with longer validity")
				}
			},
		},
		{
			name: "single valid certificate",
			candidates: func() []*certificateWithMetadata {
				cert := createCASignedECDSACert(t, "example.com", future)
				return []*certificateWithMetadata{
					{cert: cert, notAfter: cert.Leaf.NotAfter, isTrusted: true, keyType: "ECDSA", isWildcard: false},
				}
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates := tt.candidates()
			got := selectBestCertificate(candidates)

			if tt.wantNil {
				if got != nil {
					t.Errorf("selectBestCertificate() should return nil, got certificate")
				}
			} else {
				if got == nil {
					t.Errorf("selectBestCertificate() returned nil, want certificate")
				} else if tt.checkFunc != nil {
					tt.checkFunc(t, got)
				}
			}
		})
	}
}
