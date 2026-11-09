package proxy

import (
	"reflect"
	"strings"
	"testing"

	"go.chief.tools/flowguard-proxy/config"
)

const (
	testPublicIP   = "203.0.113.10"
	testReservedIP = "198.51.100.20"
	testAnchorIP   = "10.18.0.5"
	testIPv6       = "2001:db8::10"
)

func stubReservedIPAnchor(t *testing.T, anchor *ReservedIPAnchor, local []string) {
	t.Helper()
	oldDetect := detectReservedIPAnchor
	oldLocal := localInterfaceAddresses
	t.Cleanup(func() {
		detectReservedIPAnchor = oldDetect
		localInterfaceAddresses = oldLocal
	})
	detectReservedIPAnchor = func() (ReservedIPAnchor, bool) {
		if anchor == nil {
			return ReservedIPAnchor{}, false
		}
		return *anchor, true
	}
	localInterfaceAddresses = func() ([]string, error) { return local, nil }
}

func transparentTestConfig(pairs ...config.AddressPair) *config.Config {
	return &config.Config{Server: &config.ServerConfig{Upstream: &config.UpstreamConfig{
		ClientIPMode: config.UpstreamClientIPModeTransparent,
		Transparent:  &config.TransparentUpstreamConfig{AddressPairs: pairs},
	}}}
}

func TestParseDigitalOceanMetadata(t *testing.T) {
	interfaces := `"interfaces": {"public": [{"ipv4": {"ip_address": "203.0.113.10"}, "anchor_ipv4": {"ip_address": "10.18.0.5"}}]}`
	tests := []struct {
		name   string
		body   string
		want   ReservedIPAnchor
		wantOK bool
	}{
		{
			name:   "active reserved IP",
			body:   `{"reserved_ip": {"ipv4": {"active": true, "ip_address": "198.51.100.20"}}, ` + interfaces + `}`,
			want:   ReservedIPAnchor{Provider: "DigitalOcean", ReservedIP: testReservedIP, AnchorIP: testAnchorIP, PublicIP: testPublicIP},
			wantOK: true,
		},
		{
			name:   "legacy floating IP",
			body:   `{"floating_ip": {"ipv4": {"active": true, "ip_address": "198.51.100.20"}}, ` + interfaces + `}`,
			want:   ReservedIPAnchor{Provider: "DigitalOcean", ReservedIP: testReservedIP, AnchorIP: testAnchorIP, PublicIP: testPublicIP},
			wantOK: true,
		},
		{
			name: "inactive reserved IP",
			body: `{"reserved_ip": {"ipv4": {"active": false}}, ` + interfaces + `}`,
		},
		{
			name: "no anchor address",
			body: `{"reserved_ip": {"ipv4": {"active": true, "ip_address": "198.51.100.20"}}, "interfaces": {"public": [{}]}}`,
		},
		{
			name: "invalid JSON",
			body: `{`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseDigitalOceanMetadata([]byte(tt.body))
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("parseDigitalOceanMetadata() = %+v, %v; want %+v, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestInspectNetworkSuggestions(t *testing.T) {
	anchor := &ReservedIPAnchor{Provider: "DigitalOcean", ReservedIP: testReservedIP, AnchorIP: testAnchorIP, PublicIP: testPublicIP}
	local := []string{testPublicIP, testAnchorIP, testIPv6}

	tests := []struct {
		name        string
		cfg         *config.Config
		bindAddrs   []string
		anchor      *ReservedIPAnchor
		local       []string
		wantCommand []string
		wantSummary string
	}{
		{
			name:        "header mode adds the unbound anchor IP",
			cfg:         &config.Config{},
			bindAddrs:   []string{testPublicIP, testIPv6},
			anchor:      anchor,
			local:       local,
			wantCommand: []string{"flowguard setup --bind 2001:db8::10,203.0.113.10,10.18.0.5"},
			wantSummary: "reserved IP 198.51.100.20 to the anchor IP 10.18.0.5",
		},
		{
			name:      "transparent mode moves the IPv6 counterpart to the anchor IP",
			cfg:       transparentTestConfig(),
			bindAddrs: []string{testPublicIP, testIPv6},
			anchor:    anchor,
			local:     local,
			wantCommand: []string{
				"flowguard setup --bind 2001:db8::10,203.0.113.10,10.18.0.5 --address-pair 10.18.0.5=2001:db8::10 --address-pair 203.0.113.10=",
			},
		},
		{
			name:      "transparent mode pairs an already bound anchor IP",
			cfg:       transparentTestConfig(config.AddressPair{IPv4: testPublicIP, IPv6: testIPv6}),
			bindAddrs: []string{testPublicIP, testAnchorIP, testIPv6},
			anchor:    anchor,
			local:     local,
			wantCommand: []string{
				"flowguard setup --bind 10.18.0.5,2001:db8::10,203.0.113.10 --address-pair 10.18.0.5=2001:db8::10 --address-pair 203.0.113.10=",
			},
			wantSummary: "Pair the anchor IP 10.18.0.5 with 2001:db8::10",
		},
		{
			name:        "anchor IP not assigned to this machine",
			cfg:         &config.Config{},
			bindAddrs:   []string{testPublicIP, testIPv6},
			anchor:      anchor,
			local:       []string{testPublicIP, testIPv6},
			wantCommand: nil,
		},
		{
			name: "surplus IPv4 address becomes IPv4-only",
			cfg: func() *config.Config {
				cfg := transparentTestConfig(config.AddressPair{IPv4: "192.0.2.10", IPv6: testIPv6})
				cfg.Server.BindAddresses = []string{"192.0.2.10", "192.0.2.20", testIPv6}
				return cfg
			}(),
			wantCommand: []string{"flowguard setup --address-pair 192.0.2.20="},
			wantSummary: "Mark it as IPv4-only",
		},
		{
			name:        "ambiguous addresses get a template",
			cfg:         transparentTestConfig(),
			bindAddrs:   []string{"192.0.2.10", "192.0.2.20", "2001:db8::10", "2001:db8::20"},
			wantCommand: []string{"flowguard setup --bind 192.0.2.10,192.0.2.20,2001:db8::10,2001:db8::20 --address-pair IPV4=IPV6"},
		},
		{
			name:        "surplus IPv6 address is dropped from the bind addresses",
			cfg:         transparentTestConfig(config.AddressPair{IPv4: "192.0.2.10", IPv6: "2001:db8::10"}),
			bindAddrs:   []string{"192.0.2.10", "2001:db8::10", "2001:db8::20"},
			wantCommand: []string{"flowguard setup --bind 192.0.2.10,2001:db8::10"},
		},
		{
			name:        "header mode ignores incomplete pairing",
			cfg:         &config.Config{},
			bindAddrs:   []string{"192.0.2.10", "192.0.2.20", "2001:db8::10"},
			wantCommand: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubReservedIPAnchor(t, tt.anchor, tt.local)

			inspection, err := InspectNetwork(tt.cfg, tt.bindAddrs)
			if err != nil {
				t.Fatalf("InspectNetwork: %v", err)
			}
			var commands []string
			var summaries []string
			for _, suggestion := range inspection.Suggestions {
				commands = append(commands, suggestion.Command)
				summaries = append(summaries, suggestion.Summary)
			}
			if !reflect.DeepEqual(commands, tt.wantCommand) {
				t.Fatalf("suggested commands = %q, want %q", commands, tt.wantCommand)
			}
			if tt.wantSummary != "" && !strings.Contains(strings.Join(summaries, "\n"), tt.wantSummary) {
				t.Fatalf("suggestions %q do not mention %q", summaries, tt.wantSummary)
			}
		})
	}
}

func TestFormatNetworkInspectionListsSuggestions(t *testing.T) {
	report := FormatNetworkInspection(NetworkInspection{
		Mode:        config.UpstreamClientIPModeHeaders,
		HeaderReady: true,
		Ready:       true,
		Suggestions: []NetworkSuggestion{{Summary: "Listen on the anchor IP too.", Command: "flowguard setup --bind 10.18.0.5"}},
	})

	if !strings.HasSuffix(report, "\nSuggestions:\n  - Listen on the anchor IP too.\n    flowguard setup --bind 10.18.0.5\n") {
		t.Fatalf("expected suggestions at the end of the report, got:\n%s", report)
	}
}
