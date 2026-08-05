package certmanager

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testACMECertificate struct {
	Domain      map[string]any `json:"domain,omitempty"`
	Certificate []byte         `json:"certificate"`
	Key         []byte         `json:"key"`
	Store       string         `json:"Store,omitempty"`
}

type testACMEResolver struct {
	Account      map[string]any        `json:"Account,omitempty"`
	Certificates []testACMECertificate `json:"Certificates"`
}

type testCertificateChain struct {
	CertificatePEM []byte
	KeyPEM         []byte
	Certificates   []*x509.Certificate
	Root           *x509.Certificate
}

func createTestCertificateChain(t *testing.T, hostname string, notAfter time.Time, includeRoot bool) testCertificateChain {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root certificate: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root certificate: %v", err)
	}

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create intermediate certificate: %v", err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatalf("parse intermediate certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER})...)
	certificates := []*x509.Certificate{leaf, intermediate}
	if includeRoot {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
		certificates = append(certificates, root)
	}

	return testCertificateChain{
		CertificatePEM: certificatePEM,
		KeyPEM:         pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}),
		Certificates:   certificates,
		Root:           root,
	}
}

func writeTestACMEStore(t *testing.T, path string, resolvers map[string]testACMEResolver) {
	t.Helper()

	data, err := json.Marshal(resolvers)
	if err != nil {
		t.Fatalf("marshal test ACME store: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test ACME store: %v", err)
	}
}

func TestParseACMECertificateBundlePreservesAndServesChain(t *testing.T) {
	chain := createTestCertificateChain(t, "chain.example.com", time.Now().Add(90*24*time.Hour), true)

	certificate, err := parseACMECertificateBundle(chain.CertificatePEM, chain.KeyPEM)
	if err != nil {
		t.Fatalf("parseACMECertificateBundle: %v", err)
	}
	if len(certificate.Certificate) != len(chain.Certificates) {
		t.Fatalf("expected %d certificates, got %d", len(chain.Certificates), len(certificate.Certificate))
	}
	for index, expected := range chain.Certificates {
		if !bytes.Equal(certificate.Certificate[index], expected.Raw) {
			t.Fatalf("certificate %d was not preserved", index)
		}
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(chain.Root)
	serverConn, clientConn := net.Pipe()
	server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{*certificate}})
	client := tls.Client(clientConn, &tls.Config{RootCAs: rootPool, ServerName: "chain.example.com"})
	t.Cleanup(func() {
		server.Close()
		client.Close()
	})

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if got := len(client.ConnectionState().PeerCertificates); got != len(chain.Certificates) {
		t.Fatalf("expected peer to receive %d certificates, got %d", len(chain.Certificates), got)
	}

	withoutRoot := createTestCertificateChain(t, "no-root.example.com", time.Now().Add(90*24*time.Hour), false)
	withoutRootCertificate, err := parseACMECertificateBundle(withoutRoot.CertificatePEM, withoutRoot.KeyPEM)
	if err != nil {
		t.Fatalf("parse bundle without root: %v", err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range withoutRootCertificate.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse intermediate: %v", err)
		}
		intermediates.AddCert(intermediate)
	}
	roots := x509.NewCertPool()
	roots.AddCert(withoutRoot.Root)
	if _, err := withoutRootCertificate.Leaf.Verify(x509.VerifyOptions{
		DNSName:       "no-root.example.com",
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		t.Fatalf("verify bundle without root: %v", err)
	}
}

func TestParseACMECertificateBundleRejectsInvalidChains(t *testing.T) {
	chain := createTestCertificateChain(t, "valid.example.com", time.Now().Add(90*24*time.Hour), false)
	unrelated := createTestCertificateChain(t, "unrelated.example.com", time.Now().Add(90*24*time.Hour), true)

	leafBlock, rest := pem.Decode(chain.CertificatePEM)
	if leafBlock == nil {
		t.Fatal("decode leaf certificate")
	}
	_, unrelatedRest := pem.Decode(unrelated.CertificatePEM)
	unrelatedIntermediate, _ := pem.Decode(unrelatedRest)
	if unrelatedIntermediate == nil {
		t.Fatal("decode unrelated intermediate certificate")
	}
	unrelatedBundle := append(pem.EncodeToMemory(leafBlock), pem.EncodeToMemory(unrelatedIntermediate)...)

	intermediateBlock, _ := pem.Decode(rest)
	reversedBundle := append(pem.EncodeToMemory(intermediateBlock), pem.EncodeToMemory(leafBlock)...)

	for _, test := range []struct {
		name    string
		certPEM []byte
		keyPEM  []byte
	}{
		{name: "unrelated intermediate", certPEM: unrelatedBundle, keyPEM: chain.KeyPEM},
		{name: "reversed chain", certPEM: reversedBundle, keyPEM: chain.KeyPEM},
		{name: "mismatched key", certPEM: chain.CertificatePEM, keyPEM: unrelated.KeyPEM},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseACMECertificateBundle(test.certPEM, test.keyPEM); err == nil {
				t.Fatal("expected invalid bundle to be rejected")
			}
		})
	}
}

func TestTraefikACMELoadsResolversAndSkipsInvalidEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme.json")
	first := createTestCertificateChain(t, "first.example.com", time.Now().Add(90*24*time.Hour), false)
	second := createTestCertificateChain(t, "second.example.com", time.Now().Add(90*24*time.Hour), true)
	expired := createTestCertificateChain(t, "expired.example.com", time.Now().Add(-time.Hour), false)
	writeTestACMEStore(t, path, map[string]testACMEResolver{
		"z-resolver": {
			Account: map[string]any{"PrivateKey": "ignored-account-material"},
			Certificates: []testACMECertificate{
				{Domain: map[string]any{"main": "wrong.example.com"}, Certificate: second.CertificatePEM, Key: second.KeyPEM, Store: "default"},
				{Certificate: expired.CertificatePEM, Key: expired.KeyPEM},
			},
		},
		"a-resolver": {
			Certificates: []testACMECertificate{
				{Certificate: first.CertificatePEM, Key: first.KeyPEM},
				{Certificate: []byte("not PEM"), Key: first.KeyPEM},
			},
		},
	})

	manager := New(Config{ACMEPath: path})
	t.Cleanup(manager.Stop)
	if manager.GetCertificateForHostname("first.example.com") == nil {
		t.Fatal("expected first resolver certificate")
	}
	if manager.GetCertificateForHostname("second.example.com") == nil {
		t.Fatal("expected second resolver certificate")
	}
	if manager.GetCertificateForHostname("wrong.example.com") != nil {
		t.Fatal("expected JSON domain metadata to be ignored")
	}
	if manager.GetCertificateForHostname("expired.example.com") != nil {
		t.Fatal("expected expired certificate to be skipped")
	}
	if got := manager.HostnameCount(); got != 2 {
		t.Fatalf("expected 2 loaded hostnames, got %d", got)
	}

	summary, err := ProbeTraefikACMEFileSummary(path)
	if err != nil {
		t.Fatalf("ProbeTraefikACMEFileSummary: %v", err)
	}
	if summary.CertificateCount != 2 || summary.HostnameCount != 2 {
		t.Fatalf("unexpected probe summary: %+v", summary)
	}
}

func TestTraefikACMEInvalidBase64EntryDoesNotHideValidCertificate(t *testing.T) {
	chain := createTestCertificateChain(t, "valid.example.com", time.Now().Add(90*24*time.Hour), false)
	data := `{"resolver":{"Certificates":[{"certificate":"%%%","key":"%%%"},{"certificate":"` +
		base64.StdEncoding.EncodeToString(chain.CertificatePEM) + `","key":"` +
		base64.StdEncoding.EncodeToString(chain.KeyPEM) + `"}]}}`

	entries, err := parseTraefikACME([]byte(data))
	if err != nil {
		t.Fatalf("parseTraefikACME: %v", err)
	}
	if len(entries) != 2 || entries[0].DecodeError == nil || entries[1].DecodeError != nil {
		t.Fatalf("unexpected decoded entries: %+v", entries)
	}

	path := filepath.Join(t.TempDir(), "acme.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write ACME storage: %v", err)
	}
	summary, err := ProbeTraefikACMEFileSummary(path)
	if err != nil {
		t.Fatalf("ProbeTraefikACMEFileSummary: %v", err)
	}
	if summary.CertificateCount != 1 || summary.HostnameCount != 1 {
		t.Fatalf("unexpected probe summary: %+v", summary)
	}
}

func TestTraefikACMEUsesUniqueSourceIDsForOverlappingCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme.json")
	first := createTestCertificateChain(t, "overlap.example.com", time.Now().Add(60*24*time.Hour), false)
	second := createTestCertificateChain(t, "overlap.example.com", time.Now().Add(90*24*time.Hour), false)
	writeTestACMEStore(t, path, map[string]testACMEResolver{
		"resolver": {Certificates: []testACMECertificate{
			{Certificate: first.CertificatePEM, Key: first.KeyPEM},
			{Certificate: second.CertificatePEM, Key: second.KeyPEM},
		}},
	})

	manager := New(Config{ACMEPath: path})
	t.Cleanup(manager.Stop)
	manager.cacheMutex.RLock()
	candidates := manager.hostnameCache["overlap.example.com"]
	manager.cacheMutex.RUnlock()
	if len(candidates) != 2 {
		t.Fatalf("expected 2 overlapping candidates, got %d", len(candidates))
	}
	if candidates[0].filePath == candidates[1].filePath {
		t.Fatalf("expected unique source IDs, got %q", candidates[0].filePath)
	}
	selected := manager.GetCertificateForHostname("overlap.example.com")
	if selected == nil || !selected.Leaf.NotAfter.Equal(second.Certificates[0].NotAfter) {
		t.Fatal("expected the longer-lived overlapping certificate to be selected")
	}
}

func TestTraefikACMEReloadRetainsLastKnownGoodOnMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme.json")
	first := createTestCertificateChain(t, "first.example.com", time.Now().Add(90*24*time.Hour), false)
	writeTestACMEStore(t, path, map[string]testACMEResolver{
		"resolver": {Certificates: []testACMECertificate{{Certificate: first.CertificatePEM, Key: first.KeyPEM}}},
	})

	manager := &Manager{config: Config{ACMEPath: path}, hostnameCache: make(map[string][]*certificateWithMetadata)}
	manager.loadAllCertificates(false)
	if manager.GetCertificateForHostname("first.example.com") == nil {
		t.Fatal("expected initial certificate")
	}

	if err := os.WriteFile(path, []byte(`{"resolver":`), 0o600); err != nil {
		t.Fatalf("write malformed ACME storage: %v", err)
	}
	manager.loadAllCertificates(false)
	if manager.GetCertificateForHostname("first.example.com") == nil {
		t.Fatal("expected last known-good certificate to be retained")
	}

	second := createTestCertificateChain(t, "second.example.com", time.Now().Add(90*24*time.Hour), false)
	writeTestACMEStore(t, path, map[string]testACMEResolver{
		"resolver": {Certificates: []testACMECertificate{{Certificate: second.CertificatePEM, Key: second.KeyPEM}}},
	})
	manager.loadAllCertificates(false)
	if manager.GetCertificateForHostname("first.example.com") != nil {
		t.Fatal("expected removed certificate to leave the cache")
	}
	if manager.GetCertificateForHostname("second.example.com") == nil {
		t.Fatal("expected replacement certificate")
	}
}

func TestTraefikACMEWatcherReloadsRenewedCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme.json")
	first := createTestCertificateChain(t, "first.example.com", time.Now().Add(90*24*time.Hour), false)
	writeTestACMEStore(t, path, map[string]testACMEResolver{
		"resolver": {Certificates: []testACMECertificate{{Certificate: first.CertificatePEM, Key: first.KeyPEM}}},
	})

	manager := New(Config{ACMEPath: path})
	t.Cleanup(manager.Stop)
	second := createTestCertificateChain(t, "second.example.com", time.Now().Add(90*24*time.Hour), false)
	writeTestACMEStore(t, path, map[string]testACMEResolver{
		"resolver": {Certificates: []testACMECertificate{{Certificate: second.CertificatePEM, Key: second.KeyPEM}}},
	})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if manager.GetCertificateForHostname("second.example.com") != nil &&
			manager.GetCertificateForHostname("first.example.com") == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for renewed Traefik ACME certificate")
}

func TestProbeTraefikACMEFileRejectsMalformedAndEmptyStores(t *testing.T) {
	for _, contents := range []string{"not json", `{}`} {
		path := filepath.Join(t.TempDir(), "acme.json")
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write ACME storage: %v", err)
		}
		if err := ProbeTraefikACMEFile(path); err == nil {
			t.Fatalf("expected %q to be rejected", contents)
		}
	}

	err := ProbeTraefikACMEFile(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "not readable") {
		t.Fatalf("unexpected missing-file error: %v", err)
	}
}
