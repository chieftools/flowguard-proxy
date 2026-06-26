package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resetSetupTestGlobals(t *testing.T) {
	t.Helper()

	oldConfigFile := configFile
	oldDiscover := setupDiscover
	oldInput := setupInput
	oldOutput := setupOutput
	oldIsInteractive := setupIsInteractive
	oldPsaConfPath := setupPsaConfPath
	oldNginxConfigPath := setupNginxConfigPath
	oldPleskRootFallback := setupPleskRootFallback

	configFile = filepath.Join(t.TempDir(), "config.json")
	setupDiscover = false
	setupInput = strings.NewReader("")
	setupOutput = io.Discard
	setupIsInteractive = func() bool { return true }
	setupPsaConfPath = filepath.Join(t.TempDir(), "missing-psa.conf")
	setupNginxConfigPath = filepath.Join(t.TempDir(), "missing-nginx.conf")
	setupPleskRootFallback = nil

	t.Cleanup(func() {
		configFile = oldConfigFile
		setupDiscover = oldDiscover
		setupInput = oldInput
		setupOutput = oldOutput
		setupIsInteractive = oldIsInteractive
		setupPsaConfPath = oldPsaConfPath
		setupNginxConfigPath = oldNginxConfigPath
		setupPleskRootFallback = oldPleskRootFallback
	})
}

type fakeSetupClient struct {
	initialConfig string
	updatedConfig string
	getCount      int
	patchFunc     func(certPath, nginxConfigPath string) error
}

func (c *fakeSetupClient) GetConfig(string) ([]byte, error) {
	c.getCount++
	if c.getCount == 1 || c.updatedConfig == "" {
		return []byte(c.initialConfig), nil
	}

	return []byte(c.updatedConfig), nil
}

func (c *fakeSetupClient) PatchConfigPaths(certPath, nginxConfigPath string) error {
	if c.patchFunc == nil {
		return fmt.Errorf("unexpected PATCH")
	}

	return c.patchFunc(certPath, nginxConfigPath)
}

func (c *fakeSetupClient) GetBaseURL() string {
	return "https://flowguard.test"
}

func writeSetupTestPleskCertRoot(t *testing.T) (string, string) {
	t.Helper()

	tempDir := t.TempDir()
	root := filepath.Join(tempDir, "psa")
	certDir := filepath.Join(root, "var", "certificates")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatalf("create cert dir: %v", err)
	}
	writeSetupTestCombinedPEM(t, filepath.Join(certDir, "example.pem"))

	psaConfPath := filepath.Join(tempDir, "psa.conf")
	if err := os.WriteFile(psaConfPath, []byte("PRODUCT_ROOT_D "+root+"\n"), 0o644); err != nil {
		t.Fatalf("write psa.conf: %v", err)
	}

	return root, psaConfPath
}

func writeSetupTestCombinedPEM(t *testing.T, path string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames:  []string{"example.com"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	body := append(certPEM, keyPEM...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write combined PEM: %v", err)
	}
}

func TestSetupHostSkipsDiscoveryWhenPathsAlreadyConfigured(t *testing.T) {
	resetSetupTestGlobals(t)

	client := &fakeSetupClient{
		initialConfig: `{"host":{"cert_path":"/already"}}`,
	}

	if err := setupHostWithClient(client); err != nil {
		t.Fatalf("setupHostWithClient: %v", err)
	}

	body, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if !strings.Contains(string(body), `"/already"`) {
		t.Fatalf("expected original config to be saved, got %s", string(body))
	}
}

func TestSetupHostDiscoverFlagRunsDespiteExistingPaths(t *testing.T) {
	resetSetupTestGlobals(t)

	root, psaConfPath := writeSetupTestPleskCertRoot(t)
	setupPsaConfPath = psaConfPath
	setupDiscover = true
	setupInput = strings.NewReader("\n")
	var output bytes.Buffer
	setupOutput = &output
	certPath := filepath.Join(root, "var", "certificates")
	updatedConfig := `{"host":{"cert_path":"` + certPath + `"}}`

	patchCalled := false
	client := &fakeSetupClient{
		initialConfig: `{"host":{"cert_path":"/already"}}`,
		updatedConfig: updatedConfig,
		patchFunc: func(patchedCertPath, patchedNginxConfigPath string) error {
			patchCalled = true
			if patchedCertPath != certPath {
				t.Fatalf("unexpected cert path: %s", patchedCertPath)
			}
			if patchedNginxConfigPath != "" {
				t.Fatalf("unexpected nginx path: %s", patchedNginxConfigPath)
			}
			return nil
		},
	}

	if err := setupHostWithClient(client); err != nil {
		t.Fatalf("setupHostWithClient: %v", err)
	}

	if !patchCalled {
		t.Fatal("expected PATCH to be called")
	}
	body, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if !strings.Contains(string(body), certPath) {
		t.Fatalf("expected re-fetched config to be saved, got %s", string(body))
	}

	out := output.String()
	for _, want := range []string{
		"Looking for server configuration",
		"Discovered Plesk certificate directory",
		"Found 1 usable certificate covering 1 hostname.",
		"  Use this server configuration? [Y/n]:",
		"Updated FlowGuard control plane",
		"Stored configuration at",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestSetupHostDeclinedCertificateFallsBackToNginx(t *testing.T) {
	resetSetupTestGlobals(t)

	_, psaConfPath := writeSetupTestPleskCertRoot(t)
	setupPsaConfPath = psaConfPath
	setupInput = strings.NewReader("n\n\n")

	nginxConfigPath := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(nginxConfigPath, []byte("events {}\nhttp {}\n"), 0o644); err != nil {
		t.Fatalf("write nginx config: %v", err)
	}
	setupNginxConfigPath = nginxConfigPath
	updatedConfig := `{"host":{"nginx_config_path":"` + nginxConfigPath + `"}}`

	client := &fakeSetupClient{
		initialConfig: `{"host":{}}`,
		updatedConfig: updatedConfig,
		patchFunc: func(certPath, patchedNginxConfigPath string) error {
			if certPath != "" {
				t.Fatalf("unexpected cert path: %s", certPath)
			}
			if patchedNginxConfigPath != nginxConfigPath {
				t.Fatalf("unexpected nginx path: %s", patchedNginxConfigPath)
			}
			return nil
		},
	}

	if err := setupHostWithClient(client); err != nil {
		t.Fatalf("setupHostWithClient: %v", err)
	}
}

func TestSetupHostNonInteractiveNeverPatches(t *testing.T) {
	resetSetupTestGlobals(t)

	root, psaConfPath := writeSetupTestPleskCertRoot(t)
	setupPsaConfPath = psaConfPath
	setupPleskRootFallback = []string{root}
	setupDiscover = true
	setupIsInteractive = func() bool { return false }

	client := &fakeSetupClient{
		initialConfig: `{"host":{}}`,
	}

	if err := setupHostWithClient(client); err != nil {
		t.Fatalf("setupHostWithClient: %v", err)
	}

	body, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if !bytes.Contains(body, []byte(`"host":{}`)) {
		t.Fatalf("expected original config to be saved, got %s", string(body))
	}
}

func TestSetupHostPatchFailureAborts(t *testing.T) {
	resetSetupTestGlobals(t)

	root, psaConfPath := writeSetupTestPleskCertRoot(t)
	setupPsaConfPath = psaConfPath
	setupInput = strings.NewReader("\n")
	certPath := filepath.Join(root, "var", "certificates")

	client := &fakeSetupClient{
		initialConfig: `{"host":{}}`,
		patchFunc: func(patchedCertPath, nginxConfigPath string) error {
			if patchedCertPath != certPath {
				t.Fatalf("unexpected cert path: %s", patchedCertPath)
			}
			if nginxConfigPath != "" {
				t.Fatalf("unexpected nginx path: %s", nginxConfigPath)
			}
			return fmt.Errorf("API returned status 422: invalid path")
		},
	}

	err := setupHostWithClient(client)
	if err == nil {
		t.Fatal("expected setup to fail")
	}
	if !strings.Contains(err.Error(), "invalid path") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(configFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected config not to be saved after patch failure, stat error: %v", statErr)
	}
}
