package proxy

import (
	"reflect"
	"strings"
	"testing"

	"go.chief.tools/flowguard-proxy/config"
)

func TestInspectUnboundAddresses(t *testing.T) {
	old := interfaceAddresses
	t.Cleanup(func() { interfaceAddresses = old })
	interfaceAddresses = func() ([]InterfaceAddress, error) {
		return []InterfaceAddress{
			{Address: "192.0.2.10", Interface: "eth0"},
			{Address: "2001:db8::30", Interface: "eth0"},
			{Address: "192.0.2.30", Interface: "eth0"},
			{Address: "fe80::1", Interface: "eth0"},
			{Address: testAnchorIP, Interface: "eth0"},
			{Address: "10.0.0.2", Interface: "eth1"},
			{Address: "fd00::2", Interface: "eth1"},
			{Address: "100.101.102.103", Interface: "tailscale0"},
			{Address: "fd7a:115c:a1e0::1", Interface: "tailscale0"},
			{Address: "172.17.0.1", Interface: "docker0"},
			{Address: "10.8.0.1", Interface: "wg0"},
			{Address: "100.70.0.1", Interface: "eth2"},
		}, nil
	}
	anchor := &ReservedIPAnchor{Provider: "DigitalOcean", ReservedIP: testReservedIP, AnchorIP: testAnchorIP}

	uncovered, nonPublic := inspectUnboundAddresses([]string{"192.0.2.10"}, anchor)

	if want := []string{"192.0.2.30", "2001:db8::30"}; !reflect.DeepEqual(uncovered, want) {
		t.Fatalf("uncovered = %q, want %q", uncovered, want)
	}
	nonPublicAddress := func(address, iface, kind, hint string) NonPublicAddress {
		return NonPublicAddress{InterfaceAddress: InterfaceAddress{Address: address, Interface: iface}, Kind: kind, Hint: hint}
	}
	want := []NonPublicAddress{
		nonPublicAddress(testAnchorIP, "eth0", "private", "receives the internet traffic for DigitalOcean reserved IP 198.51.100.20"),
		nonPublicAddress("10.0.0.2", "eth1", "private", "reachable from other machines on the same network, such as a cloud VPC"),
		nonPublicAddress("fd00::2", "eth1", "unique local", ""),
		nonPublicAddress("100.101.102.103", "tailscale0", "carrier-grade NAT", "looks like Tailscale; reachable from devices on your tailnet"),
		nonPublicAddress("fd7a:115c:a1e0::1", "tailscale0", "unique local", "looks like Tailscale; reachable from devices on your tailnet"),
		nonPublicAddress("172.17.0.1", "docker0", "private", "looks like a Docker network; reachable from containers on this machine"),
		nonPublicAddress("10.8.0.1", "wg0", "private", "looks like WireGuard; reachable from its VPN peers"),
		nonPublicAddress("100.70.0.1", "eth2", "carrier-grade NAT", "also used by Tailscale and some providers' internal networks"),
	}
	if !reflect.DeepEqual(nonPublic, want) {
		t.Fatalf("non-public addresses =\n%+v\nwant\n%+v", nonPublic, want)
	}
}

func TestFormatNetworkInspectionListsNonPublicAddresses(t *testing.T) {
	report := FormatNetworkInspection(NetworkInspection{
		Mode:          config.UpstreamClientIPModeHeaders,
		BindAddresses: []string{"192.0.2.10"},
		NonPublicAddresses: []NonPublicAddress{
			{
				InterfaceAddress: InterfaceAddress{Address: "100.101.102.103", Interface: "tailscale0"},
				Kind:             "carrier-grade NAT",
				Hint:             "looks like Tailscale; reachable from devices on your tailnet",
			},
			{InterfaceAddress: InterfaceAddress{Address: "fd00::2", Interface: "eth1"}, Kind: "unique local"},
		},
	})

	for _, expected := range []string{
		"Bind addresses: 192.0.2.10\nNon-public addresses FlowGuard does not listen on:\n",
		"  100.101.102.103 on tailscale0 (carrier-grade NAT): looks like Tailscale; reachable from devices on your tailnet\n",
		"  fd00::2 on eth1 (unique local)\n",
		"connections to them bypass FlowGuard",
	} {
		if !strings.Contains(report, expected) {
			t.Fatalf("expected report to contain %q:\n%s", expected, report)
		}
	}
}
