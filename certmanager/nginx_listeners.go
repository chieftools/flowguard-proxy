package certmanager

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// NginxAddressPair describes an IPv4/IPv6 listener pair explicitly co-listed
// in an NGINX server block.
type NginxAddressPair struct {
	IPv4 string
	IPv6 string
}

// DiscoverNginxAddressPairs conservatively discovers one-to-one address pairs.
// Blocks with multiple addresses of either family and relationships that are
// not globally one-to-one are reported as ambiguous rather than guessed.
func DiscoverNginxAddressPairs(configPath string) ([]NginxAddressPair, []string, error) {
	pairs, warnings, _, err := DiscoverNginxAddressPairsWithDiagnostics(configPath)
	return pairs, warnings, err
}

// DiscoverNginxAddressPairsWithDiagnostics also reports each listener parsing
// and pairing decision for verbose setup output.
func DiscoverNginxAddressPairsWithDiagnostics(configPath string) ([]NginxAddressPair, []string, []string, error) {
	diagnostics := []string{fmt.Sprintf("nginx: inspecting configuration %s", configPath)}
	_, configFiles, err := parseNginxConfig(configPath, false)
	if err != nil {
		diagnostics = append(diagnostics, fmt.Sprintf("nginx: configuration could not be read: %v", err))
		return nil, nil, diagnostics, fmt.Errorf("read nginx configuration: %w", err)
	}
	sort.Strings(configFiles)
	diagnostics = append(diagnostics, fmt.Sprintf("nginx: inspecting %d parsed configuration file(s)", len(configFiles)))

	type candidate struct {
		ipv4 netip.Addr
		ipv6 netip.Addr
	}
	var candidates []candidate
	var warnings []string
	for _, path := range configFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("could not inspect nginx listeners in %s: %v", path, err))
			diagnostics = append(diagnostics, fmt.Sprintf("nginx: skipped %s because it could not be read: %v", path, err))
			continue
		}
		blocks, blockWarnings := nginxServerListenerBlocks(string(data))
		diagnostics = append(diagnostics, fmt.Sprintf("nginx: %s contains %d server block(s)", path, len(blocks)))
		for _, warning := range blockWarnings {
			warnings = append(warnings, fmt.Sprintf("%s: %s", path, warning))
		}
		for index, block := range blocks {
			for _, ignored := range block.ignored {
				diagnostics = append(diagnostics, fmt.Sprintf(
					"nginx: %s server block %d ignored listen %q: %s",
					path, index+1, ignored.raw, ignored.reason,
				))
			}
			diagnostics = append(diagnostics, fmt.Sprintf(
				"nginx: %s server block %d has explicit IPv4 listeners [%s] and IPv6 listeners [%s]",
				path, index+1, formatNginxListenerAddresses(block.ipv4), formatNginxListenerAddresses(block.ipv6),
			))
			if len(block.ipv4) == 0 || len(block.ipv6) == 0 {
				diagnostics = append(diagnostics, fmt.Sprintf(
					"nginx: %s server block %d was not a pair candidate because it needs one explicit listener from each address family",
					path, index+1,
				))
				continue
			}
			if len(block.ipv4) != 1 || len(block.ipv6) != 1 {
				warnings = append(warnings, fmt.Sprintf(
					"%s: server block has %d explicit IPv4 and %d explicit IPv6 listeners; pairing is ambiguous",
					path, len(block.ipv4), len(block.ipv6),
				))
				diagnostics = append(diagnostics, fmt.Sprintf(
					"nginx: %s server block %d was not a pair candidate because multiple explicit listeners make it ambiguous",
					path, index+1,
				))
				continue
			}
			pairCandidate := candidate{
				ipv4: firstAddr(block.ipv4),
				ipv6: firstAddr(block.ipv6),
			}
			candidates = append(candidates, pairCandidate)
			diagnostics = append(diagnostics, fmt.Sprintf(
				"nginx: %s server block %d proposed %s <-> %s",
				path, index+1, pairCandidate.ipv4, pairCandidate.ipv6,
			))
		}
	}

	v4ToV6 := make(map[netip.Addr]netip.Addr)
	v6ToV4 := make(map[netip.Addr]netip.Addr)
	ambiguousV4 := make(map[netip.Addr]bool)
	ambiguousV6 := make(map[netip.Addr]bool)
	for _, candidate := range candidates {
		if existing, ok := v4ToV6[candidate.ipv4]; ok && existing != candidate.ipv6 {
			ambiguousV4[candidate.ipv4] = true
			warnings = append(warnings, fmt.Sprintf(
				"nginx listener %s is paired with both %s and %s",
				candidate.ipv4, existing, candidate.ipv6,
			))
		} else {
			v4ToV6[candidate.ipv4] = candidate.ipv6
		}
		if existing, ok := v6ToV4[candidate.ipv6]; ok && existing != candidate.ipv4 {
			ambiguousV6[candidate.ipv6] = true
			warnings = append(warnings, fmt.Sprintf(
				"nginx listener %s is paired with both %s and %s",
				candidate.ipv6, existing, candidate.ipv4,
			))
		} else {
			v6ToV4[candidate.ipv6] = candidate.ipv4
		}
	}

	pairs := make([]NginxAddressPair, 0, len(v4ToV6))
	for ipv4, ipv6 := range v4ToV6 {
		if ambiguousV4[ipv4] || ambiguousV6[ipv6] || v6ToV4[ipv6] != ipv4 {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"nginx: rejected %s <-> %s because the relationship is not globally one-to-one",
				ipv4, ipv6,
			))
			continue
		}
		pairs = append(pairs, NginxAddressPair{IPv4: ipv4.String(), IPv6: ipv6.String()})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].IPv4 < pairs[j].IPv4
	})
	sort.Strings(warnings)
	for _, pair := range pairs {
		diagnostics = append(diagnostics, fmt.Sprintf("nginx: accepted %s <-> %s", pair.IPv4, pair.IPv6))
	}
	if len(pairs) == 0 {
		diagnostics = append(diagnostics, "nginx: no unique IPv4/IPv6 listener pairs were found")
	}
	return pairs, dedupeStrings(warnings), diagnostics, nil
}

type nginxListenerBlock struct {
	ipv4    map[netip.Addr]bool
	ipv6    map[netip.Addr]bool
	ignored []nginxIgnoredListener
}

type nginxIgnoredListener struct {
	raw    string
	reason string
}

type nginxParseContext struct {
	name   string
	server *nginxListenerBlock
}

func nginxServerListenerBlocks(input string) ([]nginxListenerBlock, []string) {
	tokens := tokenizeNginx(input)
	stack := []nginxParseContext{{name: "root"}}
	var directive []string
	var blocks []nginxListenerBlock
	var warnings []string

	for _, token := range tokens {
		switch token {
		case "{":
			name := ""
			if len(directive) > 0 {
				name = directive[0]
			}
			ctx := nginxParseContext{name: name, server: stack[len(stack)-1].server}
			if name == "server" {
				block := &nginxListenerBlock{
					ipv4: make(map[netip.Addr]bool),
					ipv6: make(map[netip.Addr]bool),
				}
				ctx.server = block
			}
			stack = append(stack, ctx)
			directive = directive[:0]
		case "}":
			if len(stack) <= 1 {
				warnings = append(warnings, "unmatched closing brace while parsing listeners")
				directive = directive[:0]
				continue
			}
			closing := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if closing.name == "server" && closing.server != nil {
				blocks = append(blocks, *closing.server)
			}
			directive = directive[:0]
		case ";":
			if len(directive) >= 2 && directive[0] == "listen" {
				server := stack[len(stack)-1].server
				if server != nil {
					if addr, ok, reason := parseNginxListenAddress(directive[1]); ok {
						if addr.Is4() {
							server.ipv4[addr] = true
						} else if addr.Is6() && !addr.Is4In6() {
							server.ipv6[addr] = true
						}
					} else {
						server.ignored = append(server.ignored, nginxIgnoredListener{raw: directive[1], reason: reason})
					}
				}
			}
			directive = directive[:0]
		default:
			directive = append(directive, token)
		}
	}

	return blocks, warnings
}

func tokenizeNginx(input string) []string {
	var tokens []string
	var current strings.Builder
	var quote rune
	escaped := false
	comment := false

	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}

	for _, r := range input {
		if comment {
			if r == '\n' {
				comment = false
			}
			continue
		}
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			current.WriteRune(r)
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' {
			flush()
			comment = true
			continue
		}
		if unicode.IsSpace(r) {
			flush()
			continue
		}
		if r == '{' || r == '}' || r == ';' {
			flush()
			tokens = append(tokens, string(r))
			continue
		}
		current.WriteRune(r)
	}
	flush()
	return tokens
}

func parseNginxListenAddress(raw string) (netip.Addr, bool, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, false, "the listen address is empty"
	}
	if strings.HasPrefix(raw, "unix:") {
		return netip.Addr{}, false, "Unix sockets do not identify an IP bind address"
	}
	if strings.Contains(raw, "$") {
		return netip.Addr{}, false, "variable-based listeners cannot be resolved statically"
	}
	if raw == "*" || raw == "0.0.0.0" || raw == "[::]" || raw == "::" {
		return netip.Addr{}, false, "wildcard listeners do not identify a specific bind address"
	}
	if _, err := strconv.ParseUint(raw, 10, 16); err == nil {
		return netip.Addr{}, false, "port-only listeners apply to wildcard addresses"
	}
	if _, err := netip.ParseAddr(raw); err == nil {
		addr, _ := netip.ParseAddr(raw)
		if addr.IsUnspecified() {
			return netip.Addr{}, false, "wildcard listeners do not identify a specific bind address"
		}
		return addr.Unmap(), true, ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err == nil {
			if addr.IsUnspecified() {
				return netip.Addr{}, false, "wildcard listeners do not identify a specific bind address"
			}
			return addr.Unmap(), true, ""
		}
		return netip.Addr{}, false, "the listener host is not a literal IP address"
	}
	if strings.Count(raw, ":") == 1 {
		host, _, ok := strings.Cut(raw, ":")
		if ok {
			addr, err := netip.ParseAddr(host)
			if err == nil && !addr.IsUnspecified() {
				return addr.Unmap(), true, ""
			}
		}
	}
	return netip.Addr{}, false, "the listener is not a supported literal IP address"
}

func formatNginxListenerAddresses(values map[netip.Addr]bool) string {
	addresses := make([]string, 0, len(values))
	for address := range values {
		addresses = append(addresses, address.String())
	}
	sort.Strings(addresses)
	return strings.Join(addresses, ", ")
}

func firstAddr(values map[netip.Addr]bool) netip.Addr {
	for value := range values {
		return value
	}
	return netip.Addr{}
}

func dedupeStrings(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
