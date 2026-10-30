package certmanager

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// writeCertbotLineage writes version of a certbot lineage to archive/<name>/
// and points the live/<name>/ symlinks at it the way certbot does, by removing
// and recreating each one with fullchain.pem last.
func writeCertbotLineage(t *testing.T, root, name string, version int, chain testCertificateChain) {
	t.Helper()
	archive := filepath.Join(root, "archive", name)
	writeDirectAdminFile(t, filepath.Join(archive, fmt.Sprintf("fullchain%d.pem", version)), chain.CertificatePEM)
	writeDirectAdminFile(t, filepath.Join(archive, fmt.Sprintf("privkey%d.pem", version)), chain.KeyPEM)

	live := filepath.Join(root, "live", name)
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatalf("create %s: %v", live, err)
	}
	for _, kind := range []string{"privkey", "fullchain"} {
		link := filepath.Join(live, kind+".pem")
		if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove %s: %v", link, err)
		}
		target := filepath.Join("..", "..", "archive", name, fmt.Sprintf("%s%d.pem", kind, version))
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("link %s: %v", link, err)
		}
	}
}

// writeCertbotTestRoot creates a certbot config directory with a valid and an
// expired lineage and a lineage without a private key.
func writeCertbotTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeDirectAdminFile(t, filepath.Join(root, "renewal", "example.com.conf"), []byte("version = 2.9.0\n"))
	writeDirectAdminFile(t, filepath.Join(root, "live", "README"), []byte("This directory contains your keys and certificates.\n"))

	writeCertbotLineage(t, root, "example.com", 1, createTestCertificateChain(t, "example.com", time.Now().Add(90*24*time.Hour), false))
	writeCertbotLineage(t, root, "expired.example", 1, createTestCertificateChain(t, "expired.example", time.Now().Add(-time.Hour), false))
	writeCertbotLineage(t, root, "keyless.example", 1, createTestCertificateChain(t, "keyless.example", time.Now().Add(90*24*time.Hour), false))
	if err := os.Remove(filepath.Join(root, "live", "keyless.example", "privkey.pem")); err != nil {
		t.Fatalf("remove private key: %v", err)
	}

	return root
}

func TestIsCertbotRoot(t *testing.T) {
	if !IsCertbotRoot(writeCertbotTestRoot(t)) {
		t.Fatal("expected a certbot config directory to be recognized")
	}

	dir := t.TempDir()
	writeCombinedPEM(t, filepath.Join(dir, "example.pem"), createSelfSignedRSACert(t, "example.com", time.Now().Add(24*time.Hour)))
	if IsCertbotRoot(dir) {
		t.Fatal("expected a certificate directory not to be recognized as certbot")
	}
	if IsCertbotRoot("") {
		t.Fatal("expected an empty path not to be recognized as certbot")
	}
}

func TestCertbotCertificatesListsLineagePairs(t *testing.T) {
	root := writeCertbotTestRoot(t)
	live := filepath.Join(root, "live")

	want := []Certificate{
		{CertPath: filepath.Join(live, "example.com", "fullchain.pem"), KeyPath: filepath.Join(live, "example.com", "privkey.pem")},
		{CertPath: filepath.Join(live, "expired.example", "fullchain.pem"), KeyPath: filepath.Join(live, "expired.example", "privkey.pem")},
	}
	if got := certbotCertificates(root); !reflect.DeepEqual(got, want) {
		t.Fatalf("certbotCertificates() =\n%#v\nwant\n%#v", got, want)
	}

	wantDirs := []string{
		live,
		filepath.Join(live, "example.com"),
		filepath.Join(live, "expired.example"),
		filepath.Join(live, "keyless.example"),
	}
	if got := certbotWatchDirs(root); !reflect.DeepEqual(got, wantDirs) {
		t.Fatalf("certbotWatchDirs() = %#v, want %#v", got, wantDirs)
	}
}

func TestManagerLoadsCertbotCertificates(t *testing.T) {
	root := writeCertbotTestRoot(t)
	cm := New(Config{CertPath: root})
	defer cm.Stop()

	cert := cm.GetCertificateForHostname("example.com")
	if cert == nil {
		t.Fatal("expected the lineage certificate to be served")
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("expected the certificate to include its chain, got %d certificate(s)", len(cert.Certificate))
	}
	if cm.HostnameCount() != 1 {
		t.Fatalf("expected 1 hostname, got %d", cm.HostnameCount())
	}
	for _, name := range []string{"expired.example", "keyless.example"} {
		if _, ok := cm.hostnameCache[name]; ok {
			t.Fatalf("did not expect %s to be loaded", name)
		}
	}
}

func TestProbeCertificateDirectoryAcceptsCertbotRoot(t *testing.T) {
	summary, err := ProbeCertificateDirectorySummary(writeCertbotTestRoot(t))
	if err != nil {
		t.Fatalf("ProbeCertificateDirectorySummary: %v", err)
	}
	if summary.CertificateCount != 1 || summary.HostnameCount != 1 {
		t.Fatalf("expected 1 certificate covering 1 hostname, got %d covering %d", summary.CertificateCount, summary.HostnameCount)
	}
}

// skipCertbotWatcherOutsideLinux skips tests of certbot renewals outside
// Linux, where FlowGuard runs. The kqueue watcher on macOS and BSD follows the
// relative symlinks in live/<name>/ and misses their replacement.
func skipCertbotWatcherOutsideLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("certbot symlink renewals are only detected by the inotify watcher on Linux")
	}
}

func waitForCertbotCertificate(t *testing.T, cm *Manager, hostname string, chain *testCertificateChain) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cert := cm.GetCertificateForHostname(hostname)
		if chain == nil && cert == nil {
			return
		}
		if chain != nil && cert != nil && bytes.Equal(cert.Certificate[0], chain.Certificates[0].Raw) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for the certbot certificate of %s to change", hostname)
}

func TestCertbotWatcherReloadsRenewedCertificate(t *testing.T) {
	skipCertbotWatcherOutsideLinux(t)

	root := writeCertbotTestRoot(t)
	cm := New(Config{CertPath: root})
	t.Cleanup(cm.Stop)

	renewed := createTestCertificateChain(t, "example.com", time.Now().Add(90*24*time.Hour), false)
	writeCertbotLineage(t, root, "example.com", 2, renewed)
	waitForCertbotCertificate(t, cm, "example.com", &renewed)
}

func TestCertbotWatcherFollowsRecreatedLineage(t *testing.T) {
	skipCertbotWatcherOutsideLinux(t)

	root := writeCertbotTestRoot(t)
	cm := New(Config{CertPath: root})
	t.Cleanup(cm.Stop)

	if err := os.RemoveAll(filepath.Join(root, "live", "example.com")); err != nil {
		t.Fatalf("remove lineage: %v", err)
	}
	waitForCertbotCertificate(t, cm, "example.com", nil)

	issued := createTestCertificateChain(t, "example.com", time.Now().Add(90*24*time.Hour), false)
	writeCertbotLineage(t, root, "example.com", 3, issued)
	waitForCertbotCertificate(t, cm, "example.com", &issued)

	renewed := createTestCertificateChain(t, "example.com", time.Now().Add(90*24*time.Hour), false)
	writeCertbotLineage(t, root, "example.com", 4, renewed)
	waitForCertbotCertificate(t, cm, "example.com", &renewed)
}
