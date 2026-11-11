package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The firewall monitor confirms every FlowGuard rule with "iptables -C" on each
// check interval. Every call forks a process, and on iptables-legacy every -C
// also writes a NETFILTER_CFG record to the kernel audit log, which floods
// auditd on hosts with many bind addresses. Listing a chain with -S does
// neither. A check therefore lists the chains that hold FlowGuard's rules and
// only runs the -C calls when a listing differs from the one recorded by the
// last check that found every rule, or when that check is older than
// firewallFullCheckInterval. A listing that cannot be read always falls back to
// the -C calls, so the monitor never reports rules it did not confirm.
const firewallFullCheckInterval = 10 * time.Minute

// chainLister lists iptables chains. execFirewallRunner and
// execNetworkCommandRunner both satisfy it.
type chainLister interface {
	Output(name string, args ...string) ([]byte, error)
}

type chainRef struct {
	command string
	table   string
	chain   string
}

func (c chainRef) listArgs() []string {
	args := make([]string, 0, 4)
	if c.table != "" {
		args = append(args, "-t", c.table)
	}
	return append(args, "-S", c.chain)
}

type chainListing struct {
	output []byte
	err    error
}

// chainSnapshot memoizes chain listings for one monitor pass, so servers
// that share chains list each chain once. Call invalidate after changing
// rules.
type chainSnapshot struct {
	listings map[chainRef]chainListing
}

func newChainSnapshot() *chainSnapshot {
	return &chainSnapshot{listings: make(map[chainRef]chainListing)}
}

func (s *chainSnapshot) invalidate() {
	clear(s.listings)
}

// list returns the memoized listing of ref. All servers use the same runner
// in production, so the first lister to list a chain serves the whole pass.
func (s *chainSnapshot) list(lister chainLister, ref chainRef) ([]byte, error) {
	if listing, ok := s.listings[ref]; ok {
		return listing.output, listing.err
	}
	output, err := lister.Output(ref.command, ref.listArgs()...)
	s.listings[ref] = chainListing{output: output, err: err}
	return output, err
}

// chainFingerprint digests the expected rules together with the current
// listing of every chain that holds them. It reports false when a chain cannot
// be listed, for example because it does not exist.
func chainFingerprint(expected []string, chains []chainRef, list func(chainRef) ([]byte, error)) (string, bool) {
	refs := slices.Clone(chains)
	slices.SortFunc(refs, func(a, b chainRef) int {
		return strings.Compare(a.command+"\x00"+a.table+"\x00"+a.chain, b.command+"\x00"+b.table+"\x00"+b.chain)
	})
	refs = slices.Compact(refs)

	digest := sha256.New()
	for _, rule := range expected {
		writeFingerprintField(digest, rule)
	}
	for _, ref := range refs {
		output, err := list(ref)
		if err != nil {
			return "", false
		}
		writeFingerprintField(digest, ref.command+" "+strings.Join(ref.listArgs(), " "))
		writeFingerprintField(digest, string(output))
	}
	return hex.EncodeToString(digest.Sum(nil)), true
}

func writeFingerprintField(digest interface{ Write([]byte) (int, error) }, value string) {
	_, _ = digest.Write([]byte(strconv.Itoa(len(value)) + ":" + value))
}

func ruleCheckCommand(command string, args []string) string {
	return command + " " + strings.Join(args, " ")
}

// verifiedFirewallState remembers the fingerprint of the last check that
// confirmed every rule with -C.
type verifiedFirewallState struct {
	mu          sync.Mutex
	fingerprint string
	verifiedAt  time.Time
	now         func() time.Time
}

func (v *verifiedFirewallState) clock() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

// matches reports whether fingerprint equals the recorded one and the -C
// check that recorded it is recent enough to skip another.
func (v *verifiedFirewallState) matches(fingerprint string) bool {
	if fingerprint == "" {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.fingerprint != fingerprint {
		return false
	}
	elapsed := v.clock().Sub(v.verifiedAt)
	return elapsed >= 0 && elapsed < firewallFullCheckInterval
}

func (v *verifiedFirewallState) record(fingerprint string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fingerprint = fingerprint
	v.verifiedAt = v.clock()
}

func (v *verifiedFirewallState) reset() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fingerprint = ""
	v.verifiedAt = time.Time{}
}

// checkWithSnapshot runs checkRules unless the chains are unchanged since the
// last check that confirmed every rule. Before recording a new fingerprint
// it lists the chains again, outside the snapshot, and records only when both
// listings agree, so a rule that changed during the -C calls is checked again
// on the next pass.
func checkWithSnapshot[T any](state *verifiedFirewallState, snapshot *chainSnapshot, lister chainLister, expected []string, chains []chainRef, checkRules func() []T) []T {
	before, ok := chainFingerprint(expected, chains, func(ref chainRef) ([]byte, error) {
		return snapshot.list(lister, ref)
	})
	if ok && state.matches(before) {
		return nil
	}

	missing := checkRules()
	if !ok || len(missing) > 0 {
		state.reset()
		return missing
	}

	after, ok := chainFingerprint(expected, chains, func(ref chainRef) ([]byte, error) {
		return lister.Output(ref.command, ref.listArgs()...)
	})
	if ok && after == before {
		state.record(after)
	} else {
		state.reset()
	}
	return missing
}
