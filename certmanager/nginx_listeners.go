package certmanager

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
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
	_, configFiles, err := parseNginxConfig(configPath, false)
	if err != nil {
		return nil, nil, fmt.Errorf("read nginx configuration: %w", err)
	}

	type candidate struct {
		ipv4 netip.Addr
		ipv6 netip.Addr
		file string
	}
	var candidates []candidate
	var warnings []string
	for _, path := range configFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("could not inspect nginx listeners in %s: %v", path, err))
			continue
		}
		blocks, blockWarnings := nginxServerListenerBlocks(string(data))
		for _, warning := range blockWarnings {
			warnings = append(warnings, fmt.Sprintf("%s: %s", path, warning))
		}
		for _, block := range blocks {
			if len(block.ipv4) == 0 || len(block.ipv6) == 0 {
				continue
			}
			if len(block.ipv4) != 1 || len(block.ipv6) != 1 {
				warnings = append(warnings, fmt.Sprintf(
					"%s: server block has %d explicit IPv4 and %d explicit IPv6 listeners; pairing is ambiguous",
					path, len(block.ipv4), len(block.ipv6),
				))
				continue
			}
			candidates = append(candidates, candidate{
				ipv4: firstAddr(block.ipv4),
				ipv6: firstAddr(block.ipv6),
				file: path,
			})
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
			continue
		}
		pairs = append(pairs, NginxAddressPair{IPv4: ipv4.String(), IPv6: ipv6.String()})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].IPv4 < pairs[j].IPv4
	})
	sort.Strings(warnings)
	return pairs, dedupeStrings(warnings), nil
}

type nginxListenerBlock struct {
	ipv4 map[netip.Addr]bool
	ipv6 map[netip.Addr]bool
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
					if addr, ok := parseNginxListenAddress(directive[1]); ok {
						if addr.Is4() {
							server.ipv4[addr] = true
						} else if addr.Is6() && !addr.Is4In6() {
							server.ipv6[addr] = true
						}
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

func parseNginxListenAddress(raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "unix:") || strings.Contains(raw, "$") ||
		raw == "*" || raw == "0.0.0.0" || raw == "[::]" || raw == "::" {
		return netip.Addr{}, false
	}
	if _, err := netip.ParseAddr(raw); err == nil {
		addr, _ := netip.ParseAddr(raw)
		if addr.IsUnspecified() {
			return netip.Addr{}, false
		}
		return addr.Unmap(), true
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err == nil && !addr.IsUnspecified() {
			return addr.Unmap(), true
		}
	}
	if strings.Count(raw, ":") == 1 {
		host, _, ok := strings.Cut(raw, ":")
		if ok {
			addr, err := netip.ParseAddr(host)
			if err == nil && !addr.IsUnspecified() {
				return addr.Unmap(), true
			}
		}
	}
	return netip.Addr{}, false
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
