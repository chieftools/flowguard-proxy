package certmanager

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeDirectAdminFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func certificatePEM(cert *tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
}

func privateKeyPEM(t *testing.T, cert *tls.Certificate) []byte {
	t.Helper()
	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
}

// writeDirectAdminTestRoot creates a DirectAdmin installation with a valid and
// an expired domain certificate, a certificate without a key, and a hostname
// certificate with a separate chain file.
func writeDirectAdminTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeDirectAdminFile(t, filepath.Join(root, "conf", "directadmin.conf"), []byte("servername=server.example.net\nssl=1\n"))

	domains := filepath.Join(root, "data", "users", "alice", "domains")
	valid := createSelfSignedRSACert(t, "example.com", time.Now().Add(24*time.Hour))
	writeDirectAdminFile(t, filepath.Join(domains, "example.com.cert.combined"), certificatePEM(valid))
	writeDirectAdminFile(t, filepath.Join(domains, "example.com.key"), privateKeyPEM(t, valid))
	writeDirectAdminFile(t, filepath.Join(domains, "example.com.conf"), []byte("ssl=ON\n"))

	expired := createSelfSignedRSACert(t, "expired.example", time.Now().Add(-24*time.Hour))
	writeDirectAdminFile(t, filepath.Join(domains, "expired.example.cert.combined"), certificatePEM(expired))
	writeDirectAdminFile(t, filepath.Join(domains, "expired.example.key"), privateKeyPEM(t, expired))

	keyless := createSelfSignedRSACert(t, "keyless.example", time.Now().Add(24*time.Hour))
	writeDirectAdminFile(t, filepath.Join(root, "data", "users", "bob", "domains", "keyless.example.cert.combined"), certificatePEM(keyless))

	hostname := createSelfSignedRSACert(t, "server.example.net", time.Now().Add(24*time.Hour))
	chain := createSelfSignedRSACert(t, "intermediate.example.net", time.Now().Add(24*time.Hour))
	writeDirectAdminFile(t, filepath.Join(root, "conf", "cacert.pem"), certificatePEM(hostname))
	writeDirectAdminFile(t, filepath.Join(root, "conf", "carootcert.pem"), certificatePEM(chain))
	writeDirectAdminFile(t, filepath.Join(root, "conf", "cakey.pem"), privateKeyPEM(t, hostname))

	return root
}

func TestIsDirectAdminRoot(t *testing.T) {
	if !IsDirectAdminRoot(writeDirectAdminTestRoot(t)) {
		t.Fatal("expected a DirectAdmin installation to be recognized")
	}

	dir := t.TempDir()
	writeCombinedPEM(t, filepath.Join(dir, "example.pem"), createSelfSignedRSACert(t, "example.com", time.Now().Add(24*time.Hour)))
	if IsDirectAdminRoot(dir) {
		t.Fatal("expected a certificate directory not to be recognized as DirectAdmin")
	}
	if IsDirectAdminRoot("") {
		t.Fatal("expected an empty path not to be recognized as DirectAdmin")
	}
}

func TestDirectAdminCertificatesListsHostnameAndDomainPairs(t *testing.T) {
	root := writeDirectAdminTestRoot(t)
	domains := filepath.Join(root, "data", "users", "alice", "domains")

	want := []Certificate{
		{
			CertPath:  filepath.Join(root, "conf", "cacert.pem"),
			ChainPath: filepath.Join(root, "conf", "carootcert.pem"),
			KeyPath:   filepath.Join(root, "conf", "cakey.pem"),
		},
		{CertPath: filepath.Join(domains, "example.com.cert.combined"), KeyPath: filepath.Join(domains, "example.com.key")},
		{CertPath: filepath.Join(domains, "expired.example.cert.combined"), KeyPath: filepath.Join(domains, "expired.example.key")},
	}
	if got := directAdminCertificates(root); !reflect.DeepEqual(got, want) {
		t.Fatalf("directAdminCertificates() =\n%#v\nwant\n%#v", got, want)
	}

	wantDirs := []string{
		filepath.Join(root, "data", "users"),
		domains,
		filepath.Join(root, "data", "users", "bob", "domains"),
		filepath.Join(root, "conf"),
	}
	if got := directAdminWatchDirs(root); !reflect.DeepEqual(got, wantDirs) {
		t.Fatalf("directAdminWatchDirs() = %#v, want %#v", got, wantDirs)
	}
}

func TestDirectAdminHostnameCertificateFollowsDirectAdminConf(t *testing.T) {
	root := writeDirectAdminTestRoot(t)
	custom := t.TempDir()
	writeDirectAdminFile(t, filepath.Join(root, "conf", "directadmin.conf"), []byte(
		"cacert="+filepath.Join(custom, "host.crt")+"\ncakey="+filepath.Join(custom, "host.key")+"\ncarootcert=relative.pem\n",
	))

	want := Certificate{
		CertPath:  filepath.Join(custom, "host.crt"),
		ChainPath: filepath.Join(root, "conf", "carootcert.pem"),
		KeyPath:   filepath.Join(custom, "host.key"),
	}
	if got := directAdminHostnameCertificate(root); got != want {
		t.Fatalf("directAdminHostnameCertificate() = %#v, want %#v", got, want)
	}
}

func TestManagerLoadsDirectAdminCertificates(t *testing.T) {
	root := writeDirectAdminTestRoot(t)
	cm := New(Config{CertPath: root})
	defer cm.Stop()

	if cm.GetCertificateForHostname("example.com") == nil {
		t.Fatal("expected the domain certificate to be served")
	}
	hostname := cm.GetCertificateForHostname("server.example.net")
	if hostname == nil {
		t.Fatal("expected the hostname certificate to be served")
	}
	if len(hostname.Certificate) != 2 {
		t.Fatalf("expected the hostname certificate to include its chain, got %d certificate(s)", len(hostname.Certificate))
	}
	if cm.HostnameCount() != 2 {
		t.Fatalf("expected 2 hostnames, got %d", cm.HostnameCount())
	}
	for _, name := range []string{"expired.example", "keyless.example"} {
		if _, ok := cm.hostnameCache[name]; ok {
			t.Fatalf("did not expect %s to be loaded", name)
		}
	}
}

func TestProbeCertificateDirectoryAcceptsDirectAdminRoot(t *testing.T) {
	summary, err := ProbeCertificateDirectorySummary(writeDirectAdminTestRoot(t))
	if err != nil {
		t.Fatalf("ProbeCertificateDirectorySummary: %v", err)
	}
	if summary.CertificateCount != 2 || summary.HostnameCount != 2 {
		t.Fatalf("expected 2 certificates covering 2 hostnames, got %d covering %d", summary.CertificateCount, summary.HostnameCount)
	}
}

func writeDirectAdminIP(t *testing.T, root, ip, linkedIPs string) {
	t.Helper()
	body := "status=server\nvalue=1\n"
	if linkedIPs != "" {
		body = "linked_ips=" + linkedIPs + "\n" + body
	}
	writeDirectAdminFile(t, filepath.Join(root, "data", "admin", "ips", ip), []byte(body))
}

func TestDiscoverDirectAdminAddressPairs(t *testing.T) {
	root := writeDirectAdminTestRoot(t)
	// Copied from a DirectAdmin server, which percent-encodes every character.
	writeDirectAdminIP(t, root, "185.133.88.5", "%32a%31%30%3A%37%31%38%30%3A%31%30%30%3A%30%3A%31%38%35%3A%31%33%33%3A%38%38%3A%35=apache%3Dyes%26dns%3Dyes")
	writeDirectAdminIP(t, root, "2a10:7180:100:0:185:133:88:5", "")
	// Linked from the IPv6 side only.
	writeDirectAdminIP(t, root, "2001:db8::20", url.Values{"192.0.2.20": {"apache=yes&dns=no"}}.Encode())
	writeDirectAdminIP(t, root, "192.0.2.20", "")
	// Not applied to the web server.
	writeDirectAdminIP(t, root, "192.0.2.30", url.Values{"2001:db8::30": {"apache=no&dns=yes"}}.Encode())

	pairs, warnings, diagnostics := DiscoverDirectAdminAddressPairs(root)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	want := []AddressPair{
		{IPv4: "185.133.88.5", IPv6: "2a10:7180:100:0:185:133:88:5"},
		{IPv4: "192.0.2.20", IPv6: "2001:db8::20"},
	}
	if !reflect.DeepEqual(pairs, want) {
		t.Fatalf("pairs = %#v, want %#v", pairs, want)
	}
	if joined := strings.Join(diagnostics, "\n"); !strings.Contains(joined, "ignored link 192.0.2.30 <-> 2001:db8::30 because it does not apply to the web server") {
		t.Fatalf("expected a diagnostic for the ignored link, got:\n%s", joined)
	}
}

func TestDiscoverDirectAdminAddressPairsRejectsAmbiguousLinks(t *testing.T) {
	root := writeDirectAdminTestRoot(t)
	writeDirectAdminIP(t, root, "192.0.2.10", url.Values{
		"2001:db8::10": {"apache=yes"},
		"2001:db8::11": {"apache=yes"},
	}.Encode())

	pairs, warnings, _ := DiscoverDirectAdminAddressPairs(root)
	if len(pairs) != 0 {
		t.Fatalf("expected no pairs, got %#v", pairs)
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], "ambiguous") {
		t.Fatalf("expected two ambiguity warnings, got %v", warnings)
	}
}
