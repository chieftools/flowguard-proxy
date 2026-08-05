package proxy

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"flowguard/config"
)

type fakeFirewallRunner struct {
	installed map[string]bool
	failures  map[string]error
}

type orderedFirewallRunner struct {
	fallback   *fakeFirewallRunner
	prerouting []string
}

func newFakeFirewallRunner() *fakeFirewallRunner {
	return &fakeFirewallRunner{
		installed: make(map[string]bool),
		failures:  make(map[string]error),
	}
}

func newOrderedFirewallRunner(prerouting ...string) *orderedFirewallRunner {
	return &orderedFirewallRunner{
		fallback:   newFakeFirewallRunner(),
		prerouting: append([]string(nil), prerouting...),
	}
}

func (f *fakeFirewallRunner) Run(name string, args ...string) error {
	rawKey := firewallCommandKey(name, args)
	if err, ok := f.failures[rawKey]; ok {
		return err
	}

	checkKey := normalizeFirewallCommand(name, args)
	verbIndex := firewallVerbIndex(args)
	if verbIndex == -1 {
		return nil
	}

	switch args[verbIndex] {
	case "-C":
		if f.installed[checkKey] {
			return nil
		}
		return errors.New("missing rule")
	case "-I", "-A":
		f.installed[checkKey] = true
		return nil
	case "-D":
		if !f.installed[checkKey] {
			return errors.New("missing rule")
		}
		delete(f.installed, checkKey)
		return nil
	default:
		return nil
	}
}

func (f *orderedFirewallRunner) Run(name string, args ...string) error {
	if name != "iptables" || len(args) < 4 || args[0] != "-t" || args[1] != "nat" || args[3] != "PREROUTING" {
		return f.fallback.Run(name, args...)
	}

	verb := args[2]
	rule := strings.Join(args[4:], " ")
	index := -1
	for i, installed := range f.prerouting {
		if installed == rule {
			index = i
			break
		}
	}

	switch verb {
	case "-C":
		if index >= 0 {
			return nil
		}
		return errors.New("missing rule")
	case "-I":
		f.prerouting = append([]string{rule}, f.prerouting...)
		return nil
	case "-A":
		f.prerouting = append(f.prerouting, rule)
		return nil
	case "-D":
		if index < 0 {
			return errors.New("missing rule")
		}
		f.prerouting = append(f.prerouting[:index], f.prerouting[index+1:]...)
		return nil
	default:
		return nil
	}
}

func firewallCommandKey(name string, args []string) string {
	return strings.Join(append([]string{name}, args...), " ")
}

func firewallVerbIndex(args []string) int {
	if len(args) == 0 {
		return -1
	}
	if args[0] == "-t" {
		if len(args) < 3 {
			return -1
		}
		return 2
	}
	return 0
}

func normalizeFirewallCommand(name string, args []string) string {
	normalized := append([]string(nil), args...)
	verbIndex := firewallVerbIndex(normalized)
	if verbIndex != -1 {
		normalized[verbIndex] = "-C"
	}
	return firewallCommandKey(name, normalized)
}

func newTestServer(bindAddr string, redirPort string, runner firewallRunner) *Server {
	return newTestServerWithScheme("http", bindAddr, redirPort, runner)
}

func newTestServerWithScheme(scheme string, bindAddr string, redirPort string, runner firewallRunner) *Server {
	server := NewServer(&ServerConfig{
		scheme:    scheme,
		verbose:   true,
		bindAddr:  bindAddr,
		bindPort:  "11080",
		redirPort: redirPort,
	})
	server.runner = runner
	server.interfaceLookup = func(string) (string, error) {
		return "eth0", nil
	}
	return server
}

func TestServerFirewallRulesBuildConsistently(t *testing.T) {
	tests := []struct {
		name           string
		bindAddr       string
		expectedBinary string
		expectedDNAT   string
	}{
		{
			name:           "ipv4",
			bindAddr:       "203.0.113.10",
			expectedBinary: "iptables",
			expectedDNAT:   "203.0.113.10:11080",
		},
		{
			name:           "ipv6",
			bindAddr:       "2001:db8::10",
			expectedBinary: "ip6tables",
			expectedDNAT:   "[2001:db8::10]:11080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newTestServer(tt.bindAddr, "80", newFakeFirewallRunner())

			rules, iface, err := server.firewallRules()
			if err != nil {
				t.Fatalf("firewallRules: %v", err)
			}
			if iface != "eth0" {
				t.Fatalf("unexpected iface: %s", iface)
			}
			if len(rules) != 3 {
				t.Fatalf("expected 3 rules, got %d", len(rules))
			}
			if rules[0].command != tt.expectedBinary || rules[1].command != tt.expectedBinary || rules[2].command != tt.expectedBinary {
				t.Fatalf("unexpected command binaries: %#v", rules)
			}

			dropArgs := rules[0].commandArgs(rules[0].setupVerb)
			expectedDrop := []string{
				"-I", "INPUT",
				"-d", tt.bindAddr,
				"-p", "tcp",
				"--dport", "11080",
				"-j", "DROP",
				"-m", "comment", "--comment", "FlowGuard direct-port guard",
			}
			if !reflect.DeepEqual(dropArgs, expectedDrop) {
				t.Fatalf("unexpected direct-port guard args: %#v", dropArgs)
			}

			inputArgs := rules[1].commandArgs(rules[1].setupVerb)
			expectedInput := []string{
				"-I", "INPUT",
				"-d", tt.bindAddr,
				"-p", "tcp",
				"--dport", "11080",
				"-m", "conntrack",
				"--ctstate", "DNAT",
				"--ctorigdst", tt.bindAddr,
				"--ctorigdstport", "80",
				"-j", "ACCEPT",
				"-m", "comment", "--comment", "FlowGuard",
			}
			if !reflect.DeepEqual(inputArgs, expectedInput) {
				t.Fatalf("unexpected INPUT args: %#v", inputArgs)
			}

			dnatArgs := rules[2].commandArgs(rules[2].setupVerb)
			expectedDNAT := []string{
				"-t", "nat",
				"-I", "PREROUTING",
				"-i", "eth0",
				"-d", tt.bindAddr,
				"-p", "tcp",
				"--dport", "80",
				"-j", "DNAT",
				"--to-destination", tt.expectedDNAT,
				"-m", "comment", "--comment", "FlowGuard",
			}
			if !reflect.DeepEqual(dnatArgs, expectedDNAT) {
				t.Fatalf("unexpected DNAT args: %#v", dnatArgs)
			}
		})
	}
}

func TestServerFirewallRulesIncludeUDPForHTTPS(t *testing.T) {
	server := newTestServerWithScheme("https", "203.0.113.10", "443", newFakeFirewallRunner())

	rules, iface, err := server.firewallRules()
	if err != nil {
		t.Fatalf("firewallRules: %v", err)
	}
	if iface != "eth0" {
		t.Fatalf("unexpected iface: %s", iface)
	}
	if len(rules) != 6 {
		t.Fatalf("expected 6 rules, got %d", len(rules))
	}

	expected := [][]string{
		{
			"-I", "INPUT",
			"-d", "203.0.113.10",
			"-p", "tcp",
			"--dport", "11080",
			"-j", "DROP",
			"-m", "comment", "--comment", "FlowGuard direct-port guard",
		},
		{
			"-I", "INPUT",
			"-d", "203.0.113.10",
			"-p", "tcp",
			"--dport", "11080",
			"-m", "conntrack",
			"--ctstate", "DNAT",
			"--ctorigdst", "203.0.113.10",
			"--ctorigdstport", "443",
			"-j", "ACCEPT",
			"-m", "comment", "--comment", "FlowGuard",
		},
		{
			"-t", "nat",
			"-I", "PREROUTING",
			"-i", "eth0",
			"-d", "203.0.113.10",
			"-p", "tcp",
			"--dport", "443",
			"-j", "DNAT",
			"--to-destination", "203.0.113.10:11080",
			"-m", "comment", "--comment", "FlowGuard",
		},
		{
			"-I", "INPUT",
			"-d", "203.0.113.10",
			"-p", "udp",
			"--dport", "11080",
			"-j", "DROP",
			"-m", "comment", "--comment", "FlowGuard direct-port guard",
		},
		{
			"-I", "INPUT",
			"-d", "203.0.113.10",
			"-p", "udp",
			"--dport", "11080",
			"-m", "conntrack",
			"--ctstate", "DNAT",
			"--ctorigdst", "203.0.113.10",
			"--ctorigdstport", "443",
			"-j", "ACCEPT",
			"-m", "comment", "--comment", "FlowGuard",
		},
		{
			"-t", "nat",
			"-I", "PREROUTING",
			"-i", "eth0",
			"-d", "203.0.113.10",
			"-p", "udp",
			"--dport", "443",
			"-j", "DNAT",
			"--to-destination", "203.0.113.10:11080",
			"-m", "comment", "--comment", "FlowGuard",
		},
	}

	for i, rule := range rules {
		if !reflect.DeepEqual(rule.commandArgs(rule.setupVerb), expected[i]) {
			t.Fatalf("unexpected rule %d args: %#v", i, rule.commandArgs(rule.setupVerb))
		}
	}
}

func TestServerFirewallRulesOmitUDPWhenHTTP3Disabled(t *testing.T) {
	server := newTestServerWithScheme("https", "203.0.113.10", "443", newFakeFirewallRunner())
	settings := config.ProtocolSettings{HTTP1: true, HTTP2: true, HTTP3: false}
	server.config.protocols = &settings

	rules, _, err := server.firewallRules()
	if err != nil {
		t.Fatalf("firewallRules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected only TCP rules, got %d", len(rules))
	}
	for _, rule := range rules {
		if containsArgValue(rule.args, "-p", "udp") {
			t.Fatalf("unexpected UDP rule: %#v", rule)
		}
	}
}

func containsArgValue(args []string, key string, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}

func TestServerSetupPortRedirectPrependsBeforeDocker(t *testing.T) {
	const dockerJump = "-m addrtype --dst-type LOCAL -j DOCKER"
	runner := newOrderedFirewallRunner(dockerJump)
	server := newTestServer("203.0.113.10", "80", runner)

	if err := server.SetupPortRedirect(); err != nil {
		t.Fatalf("SetupPortRedirect: %v", err)
	}
	if len(runner.prerouting) != 2 {
		t.Fatalf("expected FlowGuard and Docker rules, got %#v", runner.prerouting)
	}
	if !strings.Contains(runner.prerouting[0], "--comment FlowGuard") {
		t.Fatalf("expected FlowGuard rule first, got %#v", runner.prerouting)
	}
	if runner.prerouting[1] != dockerJump {
		t.Fatalf("expected Docker jump to remain second, got %#v", runner.prerouting)
	}

	server.CleanupPortRedirect()
	if !reflect.DeepEqual(runner.prerouting, []string{dockerJump}) {
		t.Fatalf("expected cleanup to preserve Docker jump, got %#v", runner.prerouting)
	}
}

func TestManagerEvaluateFirewallRepairsRedirectAheadOfDocker(t *testing.T) {
	const dockerJump = "-m addrtype --dst-type LOCAL -j DOCKER"
	runner := newOrderedFirewallRunner(dockerJump)
	server := newTestServer("203.0.113.10", "80", runner)
	manager := &Manager{
		config:  &Config{},
		servers: []*Server{server},
	}

	state := manager.evaluateFirewall(true)
	if state.Status != firewallStatusHealthy {
		t.Fatalf("expected healthy status, got %q", state.Status)
	}
	if len(runner.prerouting) != 2 || !strings.Contains(runner.prerouting[0], "--comment FlowGuard") {
		t.Fatalf("expected repaired FlowGuard rule ahead of Docker, got %#v", runner.prerouting)
	}
}

func TestManagerSetupPortRedirectsFailsOnError(t *testing.T) {
	runner := newFakeFirewallRunner()
	server := newTestServer("203.0.113.10", "80", runner)
	rules, _, err := server.firewallRules()
	if err != nil {
		t.Fatalf("firewallRules: %v", err)
	}

	failKey := firewallCommandKey(rules[0].command, rules[0].commandArgs(rules[0].setupVerb))
	runner.failures[failKey] = errors.New("boom")

	manager := &Manager{
		config:  &Config{},
		servers: []*Server{server},
	}

	if err := manager.setupPortRedirects(); err == nil {
		t.Fatal("expected startup redirect setup to fail")
	}
}

func TestManagerEvaluateFirewallRepairsMissingRules(t *testing.T) {
	runner := newFakeFirewallRunner()
	server := newTestServer("203.0.113.10", "80", runner)

	manager := &Manager{
		config:  &Config{},
		servers: []*Server{server},
	}

	state := manager.evaluateFirewall(true)
	if state.Status != firewallStatusHealthy {
		t.Fatalf("expected healthy status, got %q", state.Status)
	}
	if state.MissingRuleCount != 0 {
		t.Fatalf("expected zero missing rules after repair, got %d", state.MissingRuleCount)
	}
	if state.LastRepairedAt == 0 {
		t.Fatal("expected repair timestamp to be set")
	}

	missing, err := server.CheckPortRedirect()
	if err != nil {
		t.Fatalf("CheckPortRedirect: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("expected repaired rules to exist, still missing %d", len(missing))
	}
}

func TestManagerEvaluateFirewallRepairFailureMarksDegraded(t *testing.T) {
	runner := newFakeFirewallRunner()
	server := newTestServer("203.0.113.10", "80", runner)
	rules, _, err := server.firewallRules()
	if err != nil {
		t.Fatalf("firewallRules: %v", err)
	}

	for _, rule := range rules {
		failKey := firewallCommandKey(rule.command, rule.commandArgs(rule.setupVerb))
		runner.failures[failKey] = errors.New("repair failed")
	}

	manager := &Manager{
		config:  &Config{},
		servers: []*Server{server},
	}

	state := manager.evaluateFirewall(true)
	if state.Status != firewallStatusDegraded {
		t.Fatalf("expected degraded status, got %q", state.Status)
	}
	if state.MissingRuleCount != len(rules) {
		t.Fatalf("expected %d missing rules, got %d", len(rules), state.MissingRuleCount)
	}
	if !strings.Contains(state.LastError, "repair failed") {
		t.Fatalf("expected repair error to be preserved, got %q", state.LastError)
	}
}

func TestManagerEvaluateFirewallDisabledWhenNoRedirect(t *testing.T) {
	manager := &Manager{
		config: &Config{NoRedirect: true},
	}

	state := manager.evaluateFirewall(true)
	if state.Status != firewallStatusDisabled {
		t.Fatalf("expected disabled status, got %q", state.Status)
	}
}
