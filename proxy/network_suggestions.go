package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"go.chief.tools/flowguard-proxy/config"
)

// NetworkSuggestion is a configuration change that network inspection
// recommends, with the command that applies it.
type NetworkSuggestion struct {
	Summary string
	Command string
}

// ReservedIPAnchor describes a cloud reserved IP whose traffic the provider
// delivers to a private anchor address on this machine instead of to the
// reserved IP itself, so FlowGuard only sees that traffic when it listens on
// the anchor address.
type ReservedIPAnchor struct {
	Provider   string
	ReservedIP string
	AnchorIP   string
	// PublicIP is the machine's own public IPv4 address, which usually holds
	// the IPv6 counterpart in transparent mode before the anchor is added.
	PublicIP string
	// Bound reports whether the anchor address is already a bind address.
	Bound bool
}

// AddressPairs returns the transparent address pairs that move the IPv6
// counterpart of the machine's public IPv4 address to the anchor address,
// which receives the reserved IP's traffic, and keep the public address as
// IPv4-only. It returns nil when the public address has no IPv6 counterpart.
func (a ReservedIPAnchor) AddressPairs(pairing AddressPairResolution) []config.AddressPair {
	if a.PublicIP == "" {
		return nil
	}
	ipv6, ok := pairing.counterpart(a.PublicIP)
	if !ok {
		return nil
	}
	return []config.AddressPair{
		{IPv4: a.AnchorIP, IPv6: ipv6},
		{IPv4: a.PublicIP},
	}
}

var (
	digitalOceanVendorPath  = "/sys/class/dmi/id/sys_vendor"
	digitalOceanMetadataURL = "http://169.254.169.254/metadata/v1.json"

	// detectReservedIPAnchor and localInterfaceAddresses are replaced in tests.
	detectReservedIPAnchor  = detectDigitalOceanReservedIPAnchor
	localInterfaceAddresses = DetectInterfaceIPAddresses
)

type digitalOceanReservedIP struct {
	IPv4 struct {
		Active    bool   `json:"active"`
		IPAddress string `json:"ip_address"`
	} `json:"ipv4"`
}

type digitalOceanMetadata struct {
	ReservedIP *digitalOceanReservedIP `json:"reserved_ip"`
	// FloatingIP is the name DigitalOcean used before reserved IPs.
	FloatingIP *digitalOceanReservedIP `json:"floating_ip"`
	Interfaces struct {
		Public []struct {
			IPv4 struct {
				IPAddress string `json:"ip_address"`
			} `json:"ipv4"`
			AnchorIPv4 struct {
				IPAddress string `json:"ip_address"`
			} `json:"anchor_ipv4"`
		} `json:"public"`
	} `json:"interfaces"`
}

// detectDigitalOceanReservedIPAnchor asks the droplet metadata service whether
// a reserved IP is assigned. It only contacts the metadata service when the
// DMI vendor identifies a DigitalOcean droplet.
func detectDigitalOceanReservedIPAnchor() (ReservedIPAnchor, bool) {
	vendor, err := os.ReadFile(digitalOceanVendorPath)
	if err != nil || strings.TrimSpace(string(vendor)) != "DigitalOcean" {
		return ReservedIPAnchor{}, false
	}

	client := http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
	response, err := client.Get(digitalOceanMetadataURL)
	if err != nil {
		return ReservedIPAnchor{}, false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ReservedIPAnchor{}, false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return ReservedIPAnchor{}, false
	}
	return parseDigitalOceanMetadata(body)
}

func parseDigitalOceanMetadata(body []byte) (ReservedIPAnchor, bool) {
	var metadata digitalOceanMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return ReservedIPAnchor{}, false
	}
	reserved := metadata.ReservedIP
	if reserved == nil || !reserved.IPv4.Active {
		reserved = metadata.FloatingIP
	}
	if reserved == nil || !reserved.IPv4.Active || len(metadata.Interfaces.Public) == 0 {
		return ReservedIPAnchor{}, false
	}
	public := metadata.Interfaces.Public[0]
	reservedIP, reservedErr := netip.ParseAddr(reserved.IPv4.IPAddress)
	anchorIP, anchorErr := netip.ParseAddr(public.AnchorIPv4.IPAddress)
	if reservedErr != nil || anchorErr != nil || !reservedIP.Is4() || !anchorIP.Is4() {
		return ReservedIPAnchor{}, false
	}
	anchor := ReservedIPAnchor{
		Provider:   "DigitalOcean",
		ReservedIP: reservedIP.String(),
		AnchorIP:   anchorIP.String(),
	}
	if publicIP, err := netip.ParseAddr(public.IPv4.IPAddress); err == nil && publicIP.Is4() {
		anchor.PublicIP = publicIP.String()
	}
	return anchor, true
}

// inspectReservedIPAnchor reports a detected reserved IP whose anchor address
// is assigned to this machine, so FlowGuard could listen on it.
func inspectReservedIPAnchor(bindAddrs []string) *ReservedIPAnchor {
	anchor, ok := detectReservedIPAnchor()
	if !ok {
		return nil
	}
	local, err := localInterfaceAddresses()
	if err != nil || !slices.Contains(local, anchor.AnchorIP) {
		return nil
	}
	anchor.Bound = slices.Contains(bindAddrs, anchor.AnchorIP)
	if !slices.Contains(bindAddrs, anchor.PublicIP) {
		anchor.PublicIP = ""
	}
	return &anchor
}

// networkSuggestions returns the configuration changes that resolve what the
// inspection found. includeBind adds --bind to commands that otherwise keep
// the configured bind addresses, for bind addresses that are not saved yet.
func networkSuggestions(inspection NetworkInspection, includeBind bool) []NetworkSuggestion {
	var suggestions []NetworkSuggestion
	transparent := inspection.Mode == config.UpstreamClientIPModeTransparent
	hasIPv6 := slices.ContainsFunc(inspection.BindAddresses, func(raw string) bool {
		addr, err := netip.ParseAddr(raw)
		return err == nil && addr.Unmap().Is6()
	})

	anchor := inspection.ReservedIPAnchor
	if anchor != nil && !anchor.Bound {
		bindAddrs := append(append([]string(nil), inspection.BindAddresses...), anchor.AnchorIP)
		var pairs []config.AddressPair
		if transparent && hasIPv6 {
			pairs = anchor.AddressPairs(inspection.Pairing)
			if pairs == nil {
				pairs = []config.AddressPair{{IPv4: anchor.AnchorIP}}
			}
		}
		suggestions = append(suggestions, NetworkSuggestion{
			Summary: fmt.Sprintf(
				"%s delivers traffic for reserved IP %s to the anchor IP %s, which FlowGuard does not listen on, so that traffic bypasses FlowGuard. Listen on the anchor IP too; the web server must accept connections on it, for example with a wildcard listen.",
				anchor.Provider, anchor.ReservedIP, anchor.AnchorIP,
			),
			Command: formatSetupCommand(bindAddrs, pairs),
		})
	}

	if transparent && !inspection.Pairing.Complete() {
		if suggestion, ok := pairingSuggestion(inspection, includeBind); ok {
			suggestions = append(suggestions, suggestion)
		}
	}
	return suggestions
}

func pairingSuggestion(inspection NetworkInspection, includeBind bool) (NetworkSuggestion, bool) {
	var ipv4, ipv6 []string
	for _, raw := range inspection.Pairing.Unresolved {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if addr.Unmap().Is4() {
			ipv4 = append(ipv4, addr.Unmap().String())
		} else {
			ipv6 = append(ipv6, addr.String())
		}
	}
	var bindAddrs []string
	if includeBind {
		bindAddrs = inspection.BindAddresses
	}

	anchor := inspection.ReservedIPAnchor
	if anchor != nil && anchor.Bound && slices.Contains(ipv4, anchor.AnchorIP) && len(ipv4) == 1 && len(ipv6) == 0 {
		if pairs := anchor.AddressPairs(inspection.Pairing); pairs != nil {
			return NetworkSuggestion{
				Summary: fmt.Sprintf(
					"Pair the anchor IP %s with %s, because it receives the traffic for reserved IP %s, and keep %s as IPv4-only.",
					anchor.AnchorIP, pairs[0].IPv6, anchor.ReservedIP, anchor.PublicIP,
				),
				Command: formatSetupCommand(bindAddrs, pairs),
			}, true
		}
	}

	switch {
	case len(ipv4) > 0 && len(ipv6) == 0:
		pairs := make([]config.AddressPair, 0, len(ipv4))
		for _, address := range ipv4 {
			pairs = append(pairs, config.AddressPair{IPv4: address})
		}
		return NetworkSuggestion{
			Summary: fmt.Sprintf(
				"No IPv6 bind address is left to pair with %s. Mark it as IPv4-only; validated IPv6 clients that reach it use canonical header fallback.",
				strings.Join(ipv4, ", "),
			),
			Command: formatSetupCommand(bindAddrs, pairs),
		}, true
	case len(ipv4) > 0 && len(ipv6) > 0:
		return NetworkSuggestion{
			Summary: fmt.Sprintf(
				"Pair each of %s with the IPv6 address that serves the same sites (unpaired: %s), or mark it as IPv4-only with IPV4=.",
				strings.Join(ipv4, ", "), strings.Join(ipv6, ", "),
			),
			Command: formatSetupCommand(bindAddrs, nil) + " --address-pair IPV4=IPV6",
		}, true
	case len(ipv6) > 0:
		remaining := slices.DeleteFunc(slices.Clone(inspection.BindAddresses), func(address string) bool {
			return slices.Contains(ipv6, address)
		})
		return NetworkSuggestion{
			Summary: fmt.Sprintf(
				"Every IPv6 bind address needs an IPv4 counterpart, and no IPv4 bind address is left for %s. Listen on an IPv4 address that serves the same sites, or stop listening on %s.",
				strings.Join(ipv6, ", "), strings.Join(ipv6, ", "),
			),
			Command: formatSetupCommand(remaining, nil),
		}, true
	}
	return NetworkSuggestion{}, false
}

func formatSetupCommand(bindAddrs []string, pairs []config.AddressPair) string {
	command := "flowguard setup"
	if len(bindAddrs) > 0 {
		command += " --bind " + strings.Join(bindAddrs, ",")
	}
	for _, pair := range pairs {
		command += fmt.Sprintf(" --address-pair %s=%s", pair.IPv4, pair.IPv6)
	}
	return command
}
