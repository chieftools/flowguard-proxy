package proxy

import (
	"errors"
	"strings"
	"testing"

	"flowguard/config"
)

type fakeNetworkRunner struct {
	runs         []string
	outputs      map[string]string
	outputErrors map[string]error
}

func (f *fakeNetworkRunner) Run(name string, args ...string) error {
	command := strings.Join(append([]string{name}, args...), " ")
	f.runs = append(f.runs, command)
	if strings.Contains(command, " -L "+transparentFirewallChain) ||
		strings.Contains(command, " -C ") {
		return errors.New("not installed")
	}
	return nil
}

func (f *fakeNetworkRunner) Output(name string, args ...string) ([]byte, error) {
	command := strings.Join(append([]string{name}, args...), " ")
	var output string
	if f.outputs != nil {
		output = f.outputs[command]
	}
	var err error
	if f.outputErrors != nil {
		err = f.outputErrors[command]
	}
	return []byte(output), err
}

func TestTransparentNetworkCreatesMissingRoutingTable(t *testing.T) {
	const routeCommand = "ip -4 route show table 17991"
	runner := &fakeNetworkRunner{
		outputs: map[string]string{
			routeCommand: "Error: ipv4: FIB table does not exist.\nDump terminated\n",
		},
		outputErrors: map[string]error{
			routeCommand: errors.New("exit status 2"),
		},
	}
	manager := newTransparentNetworkManager(config.TransparentUpstreamSettings{RouteTable: 17991}, nil)
	manager.runner = runner

	if err := manager.ensureLocalRoute("-4", "0.0.0.0/0"); err != nil {
		t.Fatalf("ensureLocalRoute: %v", err)
	}
	if got := strings.Join(runner.runs, "\n"); !strings.Contains(got, "ip -4 route add local 0.0.0.0/0 dev lo table 17991") {
		t.Fatalf("expected missing routing table to be created, commands:\n%s", got)
	}
}

func TestMissingRoutingTableErrorRecognition(t *testing.T) {
	for _, output := range []string{
		"Error: ipv4: FIB table does not exist.\nDump terminated",
		"Error: ipv6: FIB table does not exist.\nDump terminated",
		"routing table does not exist",
	} {
		if !isMissingRoutingTableError([]byte(output)) {
			t.Fatalf("expected missing table diagnostic to be recognized: %q", output)
		}
	}
	if isMissingRoutingTableError([]byte("RTNETLINK answers: Operation not permitted")) {
		t.Fatal("permission failure must not be treated as an available routing table")
	}
}

func TestTransparentNetworkSetupFamilyCreatesOwnedResources(t *testing.T) {
	settings := config.TransparentUpstreamSettings{
		FWMark:       17991,
		RouteTable:   17991,
		RulePriority: 17991,
	}
	runner := &fakeNetworkRunner{}
	manager := newTransparentNetworkManager(settings, []string{"192.0.2.10"})
	manager.runner = runner

	if err := manager.setupFamily(4); err != nil {
		t.Fatalf("setupFamily: %v", err)
	}
	if len(manager.cleanupActions) != 6 {
		t.Fatalf("expected six owned cleanup actions, got %d", len(manager.cleanupActions))
	}
	joined := strings.Join(runner.runs, "\n")
	for _, expected := range []string{
		"iptables -t mangle -N " + transparentFirewallChain,
		"iptables -t mangle -A " + transparentFirewallChain,
		"iptables -t mangle -I OUTPUT 1",
		"ip -4 rule add priority 17991 fwmark 17991 lookup 17991",
		"ip -4 route add local 0.0.0.0/0 dev lo table 17991",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected command %q in:\n%s", expected, joined)
		}
	}
}

func TestTransparentNetworkAdoptsCleanupWithoutDuplicates(t *testing.T) {
	settings := config.TransparentUpstreamSettings{
		FWMark:       17991,
		RouteTable:   17991,
		RulePriority: 17991,
	}
	runner := &fakeNetworkRunner{outputs: map[string]string{
		"ip -4 rule show":              "17991: from all fwmark 0x4647 lookup 17991\n",
		"ip -4 route show table 17991": "local default dev lo scope host\n",
	}}
	manager := newTransparentNetworkManager(settings, []string{"192.0.2.10"})
	manager.runner = runner

	for range 2 {
		if err := manager.ensurePolicyRule("-4"); err != nil {
			t.Fatalf("ensurePolicyRule: %v", err)
		}
		if err := manager.ensureLocalRoute("-4", "0.0.0.0/0"); err != nil {
			t.Fatalf("ensureLocalRoute: %v", err)
		}
	}
	if len(manager.cleanupActions) != 2 {
		t.Fatalf("expected adopted resources to have one cleanup each, got %d", len(manager.cleanupActions))
	}
}

func TestTransparentNetworkRejectsPolicyPriorityConflict(t *testing.T) {
	settings := config.TransparentUpstreamSettings{
		FWMark:       17991,
		RouteTable:   17991,
		RulePriority: 17991,
	}
	runner := &fakeNetworkRunner{outputs: map[string]string{
		"ip -4 rule show": "17991: from all lookup main\n",
	}}
	manager := newTransparentNetworkManager(settings, []string{"192.0.2.10"})
	manager.runner = runner

	if err := manager.ensurePolicyRule("-4"); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected priority conflict, got %v", err)
	}
}

func TestManagedTransparentChainLinesAcceptsIptablesOutput(t *testing.T) {
	for _, line := range []string{
		"-A FLOWGUARD_UPSTREAM -m mark --mark 0x4647 -j CONNMARK --save-mark",
		"-A FLOWGUARD_UPSTREAM -m connmark --mark 0x4647/0xffffffff -j CONNMARK --restore-mark",
		"-A FLOWGUARD_UPSTREAM -m mark --mark 17991 -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff",
	} {
		if !isManagedTransparentChainLine(line, 17991) {
			t.Fatalf("expected managed iptables output %q to be accepted", line)
		}
	}
}
