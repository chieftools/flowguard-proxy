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
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
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

func TestGetTLSConfigUsesAEADCipherSuitesForTLS12(t *testing.T) {
	manager := &Manager{}
	want := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	tlsConfig := manager.GetTlsConfig()

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %#x, want %#x", tlsConfig.MinVersion, tls.VersionTLS12)
	}
	if tlsConfig.Renegotiation != tls.RenegotiateNever {
		t.Fatalf("renegotiation policy = %d, want %d", tlsConfig.Renegotiation, tls.RenegotiateNever)
	}
	if !slices.Equal(tlsConfig.CipherSuites, want) {
		t.Fatalf("unexpected TLS 1.2 cipher suites: %v", tlsConfig.CipherSuites)
	}
}

func TestGetTLSConfigHandshakePolicy(t *testing.T) {
	now := time.Now()
	rsaCert := createSelfSignedRSACert(t, "edge.test", now.Add(time.Hour))
	ecdsaCert := createCASignedECDSACert(t, "edge.test", now.Add(time.Hour))

	tests := []struct {
		name          string
		certificate   *tls.Certificate
		minVersion    uint16
		maxVersion    uint16
		cipherSuites  []uint16
		wantVersion   uint16
		wantCipher    uint16
		wantHandshake bool
	}{
		{
			name:          "TLS 1.2 RSA AES-GCM",
			certificate:   rsaCert,
			minVersion:    tls.VersionTLS12,
			maxVersion:    tls.VersionTLS12,
			cipherSuites:  []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			wantVersion:   tls.VersionTLS12,
			wantCipher:    tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			wantHandshake: true,
		},
		{
			name:          "TLS 1.2 ECDSA ChaCha20-Poly1305",
			certificate:   ecdsaCert,
			minVersion:    tls.VersionTLS12,
			maxVersion:    tls.VersionTLS12,
			cipherSuites:  []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
			wantVersion:   tls.VersionTLS12,
			wantCipher:    tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			wantHandshake: true,
		},
		{
			name:          "TLS 1.2 CBC with SHA-1",
			certificate:   rsaCert,
			minVersion:    tls.VersionTLS12,
			maxVersion:    tls.VersionTLS12,
			cipherSuites:  []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			wantHandshake: false,
		},
		{
			name:          "TLS 1.3 remains available",
			certificate:   rsaCert,
			minVersion:    tls.VersionTLS13,
			maxVersion:    tls.VersionTLS13,
			wantVersion:   tls.VersionTLS13,
			wantHandshake: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := &Manager{hostnameCache: make(map[string][]*certificateWithMetadata)}
			manager.hostnameCache["edge.test"] = []*certificateWithMetadata{
				manager.extractCertificateMetadata(tt.certificate, "edge.test.pem", []string{"edge.test"}),
			}
			serverConfig := manager.GetTlsConfig()

			clientConfig := &tls.Config{
				CipherSuites:       tt.cipherSuites,
				InsecureSkipVerify: true,
				MinVersion:         tt.minVersion,
				MaxVersion:         tt.maxVersion,
				ServerName:         "edge.test",
			}

			state, clientErr, serverErr := performTLSHandshake(t, serverConfig, clientConfig)
			if !tt.wantHandshake {
				if clientErr == nil || serverErr == nil {
					t.Fatalf("handshake errors = client %v, server %v; want both sides to reject the connection", clientErr, serverErr)
				}
				return
			}

			if clientErr != nil || serverErr != nil {
				t.Fatalf("handshake errors = client %v, server %v", clientErr, serverErr)
			}
			if state.Version != tt.wantVersion {
				t.Fatalf("negotiated TLS version = %#x, want %#x", state.Version, tt.wantVersion)
			}
			if tt.wantCipher != 0 && state.CipherSuite != tt.wantCipher {
				t.Fatalf("negotiated cipher suite = %#x, want %#x", state.CipherSuite, tt.wantCipher)
			}
		})
	}
}

func performTLSHandshake(t *testing.T, serverConfig, clientConfig *tls.Config) (tls.ConnectionState, error, error) {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set server connection deadline: %v", err)
	}
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set client connection deadline: %v", err)
	}

	server := tls.Server(serverConn, serverConfig)
	client := tls.Client(clientConn, clientConfig)
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- server.Handshake()
	}()

	clientErr := client.Handshake()
	serverErr := <-serverResult
	return client.ConnectionState(), clientErr, serverErr
}

func TestGetTLSConfigRejectsSessionResumptionAfterCertificateRemoval(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
	}{
		{name: "TLS 1.2", version: tls.VersionTLS12},
		{name: "TLS 1.3", version: tls.VersionTLS13},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certDir := t.TempDir()
			certFile := filepath.Join(certDir, "tenant.test.pem")
			writeCombinedPEM(t, certFile, createSelfSignedRSACert(t, "tenant.test", time.Now().Add(time.Hour)))

			manager := &Manager{config: Config{CertPath: certDir}}
			manager.loadAllCertificates(false)
			serverConfig := manager.GetTlsConfig()

			clientConfig := &tls.Config{
				ClientSessionCache: tls.NewLRUClientSessionCache(1),
				InsecureSkipVerify: true,
				MinVersion:         tt.version,
				MaxVersion:         tt.version,
				ServerName:         "tenant.test",
			}

			if state, err := performLoopbackTLSHandshake(t, serverConfig, clientConfig); err != nil || state.DidResume {
				t.Fatalf("first handshake: resumed %v, error %v; want a full handshake", state.DidResume, err)
			}
			if state, err := performLoopbackTLSHandshake(t, serverConfig, clientConfig); err != nil || !state.DidResume {
				t.Fatalf("second handshake: resumed %v, error %v; want a resumed session", state.DidResume, err)
			}

			if err := os.Remove(certFile); err != nil {
				t.Fatalf("remove certificate: %v", err)
			}
			manager.loadAllCertificates(false)

			if state, err := performLoopbackTLSHandshake(t, serverConfig, clientConfig); err == nil {
				t.Fatalf("handshake after certificate removal succeeded (resumed %v); want it rejected", state.DidResume)
			}
		})
	}
}

func TestGetTLSConfigServesTheDefaultCertificateWithoutResumptionAfterCertificateRemoval(t *testing.T) {
	certDir := t.TempDir()
	tenantFile := filepath.Join(certDir, "tenant.test.pem")
	writeCombinedPEM(t, tenantFile, createSelfSignedRSACert(t, "tenant.test", time.Now().Add(time.Hour)))
	writeCombinedPEM(t, filepath.Join(certDir, "default.test.pem"), createSelfSignedRSACert(t, "default.test", time.Now().Add(time.Hour)))

	manager := &Manager{config: Config{CertPath: certDir, DefaultHostname: "default.test"}}
	manager.loadAllCertificates(false)
	serverConfig := manager.GetTlsConfig()
	clientConfig := &tls.Config{
		ClientSessionCache: tls.NewLRUClientSessionCache(1),
		InsecureSkipVerify: true,
		ServerName:         "tenant.test",
	}

	if _, err := performLoopbackTLSHandshake(t, serverConfig, clientConfig); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if state, err := performLoopbackTLSHandshake(t, serverConfig, clientConfig); err != nil || !state.DidResume {
		t.Fatalf("second handshake: resumed %v, error %v; want a resumed session", state.DidResume, err)
	}

	if err := os.Remove(tenantFile); err != nil {
		t.Fatalf("remove certificate: %v", err)
	}
	manager.loadAllCertificates(false)

	state, err := performLoopbackTLSHandshake(t, serverConfig, clientConfig)
	if err != nil {
		t.Fatalf("handshake after certificate removal: %v", err)
	}
	if state.DidResume {
		t.Fatal("expected the session not to be resumed after the certificate was removed")
	}
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != "default.test" {
		t.Fatal("expected the default certificate after the certificate was removed")
	}
}

// performLoopbackTLSHandshake completes a handshake over TCP and reads one
// byte from the server, so the client also processes TLS 1.3 session tickets.
func performLoopbackTLSHandshake(t *testing.T, serverConfig, clientConfig *tls.Config) (tls.ConnectionState, error) {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte{1})
	}()

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", listener.Addr().String(), clientConfig)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		return conn.ConnectionState(), err
	}

	return conn.ConnectionState(), nil
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

func TestGetCertificateForHostnameMatchesWildcardsOneLabelDeep(t *testing.T) {
	now := time.Now()
	exactCert := createSelfSignedRSACert(t, "www.example.test", now.Add(24*time.Hour))
	wildcardCert := createWildcardCert(t, "example.test", now.Add(24*time.Hour), true)

	manager := &Manager{hostnameCache: make(map[string][]*certificateWithMetadata)}
	for path, cert := range map[string]*tls.Certificate{"/certs/www.pem": exactCert, "/certs/wild.pem": wildcardCert} {
		hostnames := manager.getCertificateHostnames(cert.Leaf)
		metadata := manager.extractCertificateMetadata(cert, path, hostnames)
		for _, name := range hostnames {
			manager.hostnameCache[name] = append(manager.hostnameCache[name], metadata)
		}
	}

	tests := map[string]*tls.Certificate{
		"api.example.test": wildcardCert,
		// Both certificates cover it, and wildcards are preferred
		"www.example.test":     wildcardCert,
		"a.api.example.test":   nil,
		"example.test":         nil,
		"api.other.test":       nil,
		"localhost":            nil,
		"":                     nil,
		"api.example.test.com": nil,
	}
	for hostname, want := range tests {
		t.Run(hostname, func(t *testing.T) {
			if got := manager.GetCertificateForHostname(hostname); got != want {
				t.Fatalf("GetCertificateForHostname(%q) returned %p, want %p", hostname, got, want)
			}
		})
	}
}

func TestGetCertificateForHostnameIgnoresCase(t *testing.T) {
	now := time.Now()
	exactCert := createSelfSignedRSACert(t, "App.Example.TEST", now.Add(24*time.Hour))
	wildcardCert := createWildcardCert(t, "Wild.Example.TEST", now.Add(24*time.Hour), true)
	defaultCert := createSelfSignedRSACert(t, "fallback.test", now.Add(24*time.Hour))

	manager := New(Config{DefaultHostname: "Fallback.TEST."})
	defer manager.Stop()
	manager.hostnameCache = make(map[string][]*certificateWithMetadata)
	for path, cert := range map[string]*tls.Certificate{"/certs/app.pem": exactCert, "/certs/wild.pem": wildcardCert, "/certs/fallback.pem": defaultCert} {
		metadata := &certificateWithMetadata{cert: cert, filePath: path, notAfter: cert.Leaf.NotAfter, keyType: getKeyType(cert)}
		for _, name := range manager.getCertificateHostnames(cert.Leaf) {
			manager.hostnameCache[name] = append(manager.hostnameCache[name], metadata)
		}
	}

	tests := map[string]*tls.Certificate{
		"app.example.test":      exactCert,
		"APP.EXAMPLE.TEST":      exactCert,
		"app.example.test.":     exactCert,
		"api.wild.example.test": wildcardCert,
		"API.Wild.Example.Test": wildcardCert,
		"unknown.example.test":  defaultCert,
	}
	for hostname, want := range tests {
		t.Run(hostname, func(t *testing.T) {
			if got := manager.GetCertificateForHostname(hostname); got != want {
				t.Fatalf("GetCertificateForHostname(%q) returned %p, want %p", hostname, got, want)
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

func TestReloadParsesOnlyChangedCertificates(t *testing.T) {
	dir := t.TempDir()
	keptPath := filepath.Join(dir, "kept.test.pem")
	changedPath := filepath.Join(dir, "changed.test.pem")
	removedPath := filepath.Join(dir, "removed.test.pem")
	writeCombinedPEM(t, keptPath, createSelfSignedRSACert(t, "kept.test", time.Now().Add(time.Hour)))
	writeCombinedPEM(t, changedPath, createSelfSignedRSACert(t, "changed.test", time.Now().Add(time.Hour)))
	writeCombinedPEM(t, removedPath, createSelfSignedRSACert(t, "removed.test", time.Now().Add(time.Hour)))

	manager := &Manager{config: Config{CertPath: dir}}
	manager.loadAllCertificates(false)
	kept := manager.GetCertificateForHostname("kept.test")
	changed := manager.GetCertificateForHostname("changed.test")

	writeCombinedPEM(t, changedPath, createSelfSignedRSACert(t, "changed.test", time.Now().Add(2*time.Hour)))
	if err := os.Remove(removedPath); err != nil {
		t.Fatalf("remove certificate: %v", err)
	}
	manager.loadAllCertificates(false)

	if manager.GetCertificateForHostname("kept.test") != kept {
		t.Fatal("expected the unchanged certificate to be reused")
	}
	if renewed := manager.GetCertificateForHostname("changed.test"); renewed == nil || renewed == changed {
		t.Fatal("expected the replaced certificate to be parsed again")
	}
	if manager.GetCertificateForHostname("removed.test") != nil || len(manager.parsedCertificates) != 2 {
		t.Fatalf("parsed certificates = %d, want the removed certificate dropped", len(manager.parsedCertificates))
	}
}
