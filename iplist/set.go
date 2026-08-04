package iplist

import (
	"bufio"
	"fmt"
	"net/netip"
	"strings"

	"github.com/gaissmai/bart"
)

// ParseIssue describes an invalid non-comment line encountered while parsing a set.
type ParseIssue struct {
	Line  int
	Value string
	Err   error
}

// Set is an immutable IPv4/IPv6 prefix set backed by a BART trie.
type Set struct {
	trie *bart.Lite
}

// ParsePrefix parses an IP address or CIDR into its canonical prefix form.
func ParsePrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %s: %w", raw, err)
		}

		addr := prefix.Addr()
		if addr.Is4In6() {
			bits := prefix.Bits() - 96
			if bits < 0 {
				return netip.Prefix{}, fmt.Errorf("invalid mapped IPv4 CIDR %s", raw)
			}
			return netip.PrefixFrom(addr.Unmap(), bits).Masked(), nil
		}
		return prefix.Masked(), nil
	}

	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP address: %s", raw)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ParseSet parses one IP address or CIDR per line. Invalid lines are returned
// as issues while valid entries are retained.
func ParseSet(data []byte) (*Set, []ParseIssue, error) {
	trie := new(bart.Lite)
	var issues []ParseIssue
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		prefix, err := ParsePrefix(line)
		if err != nil {
			issues = append(issues, ParseIssue{Line: lineNumber, Value: line, Err: err})
			continue
		}
		trie.Insert(prefix)
	}

	if err := scanner.Err(); err != nil {
		return nil, issues, fmt.Errorf("scanner error: %w", err)
	}
	return &Set{trie: trie}, issues, nil
}

// NewSet creates a set from already parsed prefixes.
func NewSet(prefixes []netip.Prefix) *Set {
	trie := new(bart.Lite)
	for _, prefix := range prefixes {
		if prefix.IsValid() {
			trie.Insert(prefix.Masked())
		}
	}
	return &Set{trie: trie}
}

// UnionSets returns a new set containing all prefixes from the supplied sets.
func UnionSets(sets ...*Set) *Set {
	trie := new(bart.Lite)
	for _, set := range sets {
		if set == nil || set.trie == nil {
			continue
		}
		trie.Union(set.trie)
	}
	return &Set{trie: trie}
}

// Contains reports whether addr belongs to the set.
func (s *Set) Contains(addr netip.Addr) bool {
	return s != nil && s.trie != nil && addr.IsValid() && s.trie.Contains(addr.Unmap())
}

// Size returns the number of unique prefixes in the set.
func (s *Set) Size() int {
	if s == nil || s.trie == nil {
		return 0
	}
	return s.trie.Size()
}

// Equal reports whether two sets contain the same prefixes.
func (s *Set) Equal(other *Set) bool {
	if s == nil || s.trie == nil {
		return other == nil || other.trie == nil || other.trie.Size() == 0
	}
	if other == nil || other.trie == nil {
		return s.trie.Size() == 0
	}
	return s.trie.Equal(other.trie)
}
