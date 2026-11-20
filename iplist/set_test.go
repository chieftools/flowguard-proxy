package iplist

import (
	"net/netip"
	"testing"
)

func TestParsePrefix(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "IPv4 address", input: "192.0.2.10", want: "192.0.2.10/32"},
		{name: "IPv6 address", input: "2001:db8::1", want: "2001:db8::1/128"},
		{name: "masked CIDR", input: "192.0.2.10/24", want: "192.0.2.0/24"},
		{name: "mapped IPv4 address", input: "::ffff:192.0.2.10", want: "192.0.2.10/32"},
		{name: "mapped IPv4 CIDR", input: "::ffff:192.0.2.0/120", want: "192.0.2.0/24"},
		{name: "invalid address", input: "not-an-ip", wantErr: true},
		{name: "invalid mapped CIDR", input: "::ffff:192.0.2.0/80", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := ParsePrefix(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePrefix: %v", err)
			}
			if got := prefix.String(); got != tt.want {
				t.Fatalf("ParsePrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseSetRetainsValidEntriesAndReportsIssues(t *testing.T) {
	set, issues, err := ParseSet([]byte(`
# comment
192.0.2.10
192.0.2.10/32
invalid
2001:db8::/32
`))
	if err != nil {
		t.Fatalf("ParseSet: %v", err)
	}
	if set.Size() != 2 {
		t.Fatalf("set size = %d, want 2", set.Size())
	}
	if len(issues) != 1 || issues[0].Line != 5 || issues[0].Value != "invalid" {
		t.Fatalf("unexpected issues: %+v", issues)
	}
	if !set.Contains(netip.MustParseAddr("192.0.2.10")) || !set.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("valid parsed entries are missing")
	}
}

func TestUnionSetsDoesNotMutateInputs(t *testing.T) {
	left := NewSet([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	right := NewSet([]netip.Prefix{netip.MustParsePrefix("2001:db8::/32")})
	combined := UnionSets(left, right)

	if combined.Size() != 2 || !combined.Contains(netip.MustParseAddr("192.0.2.1")) || !combined.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("union does not contain both inputs")
	}
	if left.Size() != 1 || left.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("union mutated its left input")
	}
	if right.Size() != 1 || right.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("union mutated its right input")
	}
	if !combined.Equal(UnionSets(right, left)) || combined.Equal(left) {
		t.Fatal("set equality returned an unexpected result")
	}
}

func TestSetWithAndWithoutPrefixLeaveReceiverUnchanged(t *testing.T) {
	original := NewSet([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	added := original.WithPrefix(netip.MustParsePrefix("198.51.100.7/32"))
	removed := added.WithoutPrefix(netip.MustParsePrefix("192.0.2.0/24"))

	for _, test := range []struct {
		name string
		set  *Set
		addr string
		want bool
	}{
		{name: "original keeps its prefix", set: original, addr: "192.0.2.10", want: true},
		{name: "original does not gain the added prefix", set: original, addr: "198.51.100.7", want: false},
		{name: "added has both prefixes", set: added, addr: "192.0.2.10", want: true},
		{name: "added has the new prefix", set: added, addr: "198.51.100.7", want: true},
		{name: "removed drops the prefix", set: removed, addr: "192.0.2.10", want: false},
		{name: "removed keeps the other prefix", set: removed, addr: "198.51.100.7", want: true},
	} {
		if got := test.set.Contains(netip.MustParseAddr(test.addr)); got != test.want {
			t.Errorf("%s: Contains(%s) = %v, want %v", test.name, test.addr, got, test.want)
		}
	}

	var empty *Set
	if !empty.WithPrefix(netip.MustParsePrefix("203.0.113.0/24")).Contains(netip.MustParseAddr("203.0.113.9")) {
		t.Error("expected WithPrefix on a nil set to return a set with the prefix")
	}
}
