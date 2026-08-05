package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flowguard/api"
	"flowguard/config"
	"flowguard/proxy"
)

func resetSetupTestGlobals(t *testing.T) {
	t.Helper()

	oldConfigFile := configFile
	oldDiscover := setupDiscover
	oldVerbose := verbose
	oldNoTUI := noTUI
	oldInput := setupInput
	oldOutput := setupOutput
	oldIsInteractive := setupIsInteractive
	oldInspectNetwork := setupInspectNetwork
	oldLookupEnvironment := setupLookupEnvironment
	oldStreamsAreTerminal := setupStreamsAreTerminal
	oldRunForm := setupRunForm
	oldPsaConfPath := setupPsaConfPath
	oldACMEPaths := setupACMEPaths
	oldNginxConfigPath := setupNginxConfigPath
	oldPleskRootFallback := setupPleskRootFallback

	configFile = filepath.Join(t.TempDir(), "config.json")
	setupDiscover = false
	verbose = false
	noTUI = false
	setupInput = strings.NewReader("")
	setupOutput = io.Discard
	setupIsInteractive = func() bool { return true }
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return proxy.NetworkInspection{
			Mode:             "headers",
			HeaderReady:      true,
			TransparentReady: false,
			Prerequisites: []proxy.NetworkPrerequisite{{
				Name: "test prerequisite", Ready: false, Details: "not available in unit tests",
			}},
		}, nil
	}
	setupLookupEnvironment = func(string) (string, bool) { return "", false }
	setupStreamsAreTerminal = func() bool { return false }
	setupPsaConfPath = filepath.Join(t.TempDir(), "missing-psa.conf")
	setupACMEPaths = nil
	setupNginxConfigPath = filepath.Join(t.TempDir(), "missing-nginx.conf")
	setupPleskRootFallback = nil

	t.Cleanup(func() {
		configFile = oldConfigFile
		setupDiscover = oldDiscover
		verbose = oldVerbose
		noTUI = oldNoTUI
		setupInput = oldInput
		setupOutput = oldOutput
		setupIsInteractive = oldIsInteractive
		setupInspectNetwork = oldInspectNetwork
		setupLookupEnvironment = oldLookupEnvironment
		setupStreamsAreTerminal = oldStreamsAreTerminal
		setupRunForm = oldRunForm
		setupPsaConfPath = oldPsaConfPath
		setupACMEPaths = oldACMEPaths
		setupNginxConfigPath = oldNginxConfigPath
		setupPleskRootFallback = oldPleskRootFallback
	})
}

type fakeSetupClient struct {
	initialConfig string
	updatedConfig string
	getCount      int
	patchFunc     func(api.ConfigPatch) error
}

func (c *fakeSetupClient) GetConfig(string) ([]byte, error) {
	c.getCount++
	if c.getCount == 1 || c.updatedConfig == "" {
		return []byte(c.initialConfig), nil
	}

	return []byte(c.updatedConfig), nil
}

func (c *fakeSetupClient) PatchConfig(payload api.ConfigPatch) error {
	if c.patchFunc == nil {
		return fmt.Errorf("unexpected PATCH")
	}

	return c.patchFunc(payload)
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

	certPEM, keyPEM := makeSetupTestCertificatePEM(t)
	body := append(certPEM, keyPEM...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write combined PEM: %v", err)
	}
}

func makeSetupTestCertificatePEM(t *testing.T) ([]byte, []byte) {
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
	return certPEM, keyPEM
}

func writeSetupTestACMEStore(t *testing.T, path string) {
	t.Helper()

	certPEM, keyPEM := makeSetupTestCertificatePEM(t)
	store := map[string]any{
		"resolver": map[string]any{
			"Account": map[string]any{"Email": "test@example.invalid"},
			"Certificates": []map[string]any{{
				"domain":      map[string]any{"main": "example.com"},
				"certificate": certPEM,
				"key":         keyPEM,
				"Store":       "default",
			}},
		},
	}
	data, err := json.Marshal(store)
	if err != nil {
		t.Fatalf("marshal ACME store: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write ACME store: %v", err)
	}
}

func TestResolveSetupInvocationReusesConfiguredKeyAndEnablesDiscovery(t *testing.T) {
	resetSetupTestGlobals(t)

	if err := os.WriteFile(configFile, []byte(`{"host":{"key":"fgsvr_existing"}}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	hostKey, discover, err := resolveSetupInvocation(nil)
	if err != nil {
		t.Fatalf("resolveSetupInvocation: %v", err)
	}
	if hostKey != "fgsvr_existing" {
		t.Fatalf("expected configured host key, got %q", hostKey)
	}
	if !discover {
		t.Fatal("expected discovery to be enabled when reusing the configured host key")
	}
}

func TestResolveSetupInvocationExplicitKeyPreservesDiscoverFlag(t *testing.T) {
	resetSetupTestGlobals(t)

	hostKey, discover, err := resolveSetupInvocation([]string{"fgsvr_new"})
	if err != nil {
		t.Fatalf("resolveSetupInvocation: %v", err)
	}
	if hostKey != "fgsvr_new" {
		t.Fatalf("expected explicit host key, got %q", hostKey)
	}
	if discover {
		t.Fatal("expected discovery to remain disabled for an explicit host key")
	}

	setupDiscover = true
	_, discover, err = resolveSetupInvocation([]string{"fgsvr_new"})
	if err != nil {
		t.Fatalf("resolveSetupInvocation with --discover: %v", err)
	}
	if !discover {
		t.Fatal("expected explicit --discover to enable discovery")
	}
}

func TestResolveSetupInvocationWithoutConfiguredKeyFails(t *testing.T) {
	resetSetupTestGlobals(t)

	if err := os.WriteFile(configFile, []byte(`{"host":{}}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, _, err := resolveSetupInvocation(nil)
	if err == nil {
		t.Fatal("expected missing configured host key to fail")
	}
	if !strings.Contains(err.Error(), "host key is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupHostSkipsPathDiscoveryWhenPathsAlreadyConfigured(t *testing.T) {
	resetSetupTestGlobals(t)
	setupInput = strings.NewReader(strings.Repeat("\n", 5))

	client := &fakeSetupClient{
		initialConfig: `{"host":{"cert_path":"/already"}}`,
		patchFunc: func(payload api.ConfigPatch) error {
			if payload.Host != nil {
				t.Fatalf("expected configured paths not to be patched: %+v", payload.Host)
			}
			if payload.Server == nil || payload.Server.Upstream == nil || payload.Server.Upstream.ClientIPMode != config.UpstreamClientIPModeHeaders {
				t.Fatalf("expected headers server patch, got %+v", payload.Server)
			}
			if payload.Server.Protocols == nil || !payload.Server.Protocols.HTTP1 || !payload.Server.Protocols.HTTP2 || !payload.Server.Protocols.HTTP3 {
				t.Fatalf("expected all protocols enabled, got %+v", payload.Server.Protocols)
			}
			if payload.Server.AdvertiseHTTP3 == nil || *payload.Server.AdvertiseHTTP3 {
				t.Fatalf("expected HTTP/3 advertisement disabled, got %v", payload.Server.AdvertiseHTTP3)
			}
			return nil
		},
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

func TestSetupHostForcedDiscoveryRunsDespiteExistingPaths(t *testing.T) {
	resetSetupTestGlobals(t)
	verbose = true

	root, psaConfPath := writeSetupTestPleskCertRoot(t)
	setupPsaConfPath = psaConfPath
	setupInput = strings.NewReader(strings.Repeat("\n", 6))
	var output bytes.Buffer
	setupOutput = &output
	certPath := filepath.Join(root, "var", "certificates")
	updatedConfig := `{"host":{"cert_path":"` + certPath + `"}}`

	patchCalled := false
	client := &fakeSetupClient{
		initialConfig: `{"host":{"cert_path":"/already"}}`,
		updatedConfig: updatedConfig,
		patchFunc: func(payload api.ConfigPatch) error {
			patchCalled = true
			if payload.Host == nil || payload.Host.CertPath != certPath {
				t.Fatalf("unexpected host patch: %+v", payload.Host)
			}
			if payload.Host.NginxConfigPath != "" {
				t.Fatalf("unexpected nginx path: %s", payload.Host.NginxConfigPath)
			}
			return nil
		},
	}

	if err := setupHostWithClientAndDiscovery(client, true); err != nil {
		t.Fatalf("setupHostWithClientAndDiscovery: %v", err)
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
		"Verbose server configuration detection:",
		"Plesk certificates: accepted",
		"  ✓ Discovered Plesk certificate directory",
		"    Found 1 usable certificate covering 1 hostname.",
		"  Use this server configuration? [Y/n]:",
		"Updated FlowGuard control plane",
		"Stored configuration at",
		"✓ Setup complete",
		"Start FlowGuard, or restart it if already running, to apply this configuration.",
		"systemd: sudo systemctl restart flowguard",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestValidateSetupNetworkSummarizesReadyTransparentMode(t *testing.T) {
	resetSetupTestGlobals(t)
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return proxy.NetworkInspection{
			Mode:             config.UpstreamClientIPModeTransparent,
			HeaderReady:      true,
			TransparentReady: true,
			Ready:            true,
			BindAddresses:    []string{"10.20.30.10", "fd12:3456:789a::10"},
		}, nil
	}
	var output bytes.Buffer
	setupOutput = &output
	cfg := &config.Config{Server: &config.ServerConfig{Upstream: &config.UpstreamConfig{
		ClientIPMode: config.UpstreamClientIPModeTransparent,
	}}}

	if err := validateSetupNetwork(cfg); err != nil {
		t.Fatalf("validateSetupNetwork: %v", err)
	}
	if output.String() != "✓ Transparent upstream networking ready\n" {
		t.Fatalf("expected concise readiness output, got %q", output.String())
	}
}

func TestValidateSetupNetworkPrintsInspectionWhenTransparentModeIsNotReady(t *testing.T) {
	resetSetupTestGlobals(t)
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return proxy.NetworkInspection{
			Mode:             config.UpstreamClientIPModeTransparent,
			HeaderReady:      true,
			TransparentReady: false,
			Ready:            false,
			BindAddresses:    []string{"10.20.30.10"},
		}, nil
	}
	var output bytes.Buffer
	setupOutput = &output
	cfg := &config.Config{Server: &config.ServerConfig{Upstream: &config.UpstreamConfig{
		ClientIPMode: config.UpstreamClientIPModeTransparent,
	}}}

	err := validateSetupNetwork(cfg)
	if err == nil {
		t.Fatal("expected transparent readiness validation to fail")
	}
	if !strings.Contains(output.String(), "Configured upstream client IP mode: transparent") ||
		!strings.Contains(output.String(), "Ready: false") {
		t.Fatalf("expected failed inspection details, got:\n%s", output.String())
	}
}

func TestSetupHostDeclinedCertificateFallsBackToNginx(t *testing.T) {
	resetSetupTestGlobals(t)

	_, psaConfPath := writeSetupTestPleskCertRoot(t)
	setupPsaConfPath = psaConfPath
	setupInput = strings.NewReader("n\n" + strings.Repeat("\n", 6))

	nginxConfigPath := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(nginxConfigPath, []byte("events {}\nhttp {}\n"), 0o644); err != nil {
		t.Fatalf("write nginx config: %v", err)
	}
	setupNginxConfigPath = nginxConfigPath
	updatedConfig := `{"host":{"nginx_config_path":"` + nginxConfigPath + `"}}`

	client := &fakeSetupClient{
		initialConfig: `{"host":{}}`,
		updatedConfig: updatedConfig,
		patchFunc: func(payload api.ConfigPatch) error {
			if payload.Host == nil {
				t.Fatal("expected host patch")
			}
			if payload.Host.CertPath != "" {
				t.Fatalf("unexpected cert path: %s", payload.Host.CertPath)
			}
			if payload.Host.NginxConfigPath != nginxConfigPath {
				t.Fatalf("unexpected nginx path: %s", payload.Host.NginxConfigPath)
			}
			return nil
		},
	}

	if err := setupHostWithClient(client); err != nil {
		t.Fatalf("setupHostWithClient: %v", err)
	}
}

func TestSetupHostDiscoversTraefikACMEStorage(t *testing.T) {
	resetSetupTestGlobals(t)

	acmePath := filepath.Join(t.TempDir(), "acme.json")
	writeSetupTestACMEStore(t, acmePath)
	setupACMEPaths = []string{filepath.Join(t.TempDir(), "missing.json"), acmePath}
	setupInput = strings.NewReader(strings.Repeat("\n", 6))
	var output bytes.Buffer
	setupOutput = &output
	updatedConfig := `{"host":{"acme_path":"` + acmePath + `"}}`

	client := &fakeSetupClient{
		initialConfig: `{"host":{}}`,
		updatedConfig: updatedConfig,
		patchFunc: func(payload api.ConfigPatch) error {
			if payload.Host == nil || payload.Host.ACMEPath != acmePath {
				t.Fatalf("unexpected host patch: %+v", payload.Host)
			}
			if payload.Host.CertPath != "" || payload.Host.NginxConfigPath != "" {
				t.Fatalf("unexpected non-ACME paths: %+v", payload.Host)
			}
			return nil
		},
	}

	if err := setupHostWithClient(client); err != nil {
		t.Fatalf("setupHostWithClient: %v", err)
	}
	for _, want := range []string{
		"Discovered Traefik ACME storage: " + acmePath,
		"Found 1 usable certificate covering 1 hostname.",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, output.String())
		}
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
	setupInput = strings.NewReader(strings.Repeat("\n", 6))
	certPath := filepath.Join(root, "var", "certificates")

	client := &fakeSetupClient{
		initialConfig: `{"host":{}}`,
		patchFunc: func(payload api.ConfigPatch) error {
			if payload.Host == nil || payload.Host.CertPath != certPath {
				t.Fatalf("unexpected host patch: %+v", payload.Host)
			}
			if payload.Host.NginxConfigPath != "" {
				t.Fatalf("unexpected nginx path: %s", payload.Host.NginxConfigPath)
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
