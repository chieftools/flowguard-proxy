package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"flowguard/config"
)

const (
	transparentFirewallChain = "FLOWGUARD_UPSTREAM"
	transparentLockPath      = "/run/flowguard-transparent.lock"
)

type networkCommandRunner interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
}

type execNetworkCommandRunner struct{}

func (execNetworkCommandRunner) Run(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func (execNetworkCommandRunner) Output(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

type transparentNetworkManager struct {
	settings  config.TransparentUpstreamSettings
	bindAddrs []string
	runner    networkCommandRunner

	mu              sync.Mutex
	cleanupActions  []func()
	cleanupKeys     map[string]bool
	originalSrcMark *string
	lockFile        *os.File
	active          bool
}

func newTransparentNetworkManager(settings config.TransparentUpstreamSettings, bindAddrs []string) *transparentNetworkManager {
	return &transparentNetworkManager{
		settings:    settings,
		bindAddrs:   append([]string(nil), bindAddrs...),
		runner:      execNetworkCommandRunner{},
		cleanupKeys: make(map[string]bool),
	}
}

func (m *transparentNetworkManager) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active {
		return nil
	}
	if err := m.acquireLock(); err != nil {
		return err
	}

	families, err := transparentAddressFamilies(m.bindAddrs)
	if err != nil {
		m.rollbackLocked()
		return err
	}
	if families[4] {
		if err := m.ensureIPv4SourceMark(); err != nil {
			m.rollbackLocked()
			return err
		}
	}
	for _, family := range []int{4, 6} {
		if !families[family] {
			continue
		}
		if err := m.setupFamily(family); err != nil {
			m.rollbackLocked()
			return err
		}
	}
	for _, family := range []int{4, 6} {
		if !families[family] {
			continue
		}
		bindAddr := firstAddressForFamily(m.bindAddrs, family)
		if err := m.probeFamily(family, bindAddr); err != nil {
			m.rollbackLocked()
			return fmt.Errorf("transparent upstream IPv%d probe failed: %w", family, err)
		}
	}

	m.active = true
	return nil
}

func (m *transparentNetworkManager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollbackLocked()
	m.active = false
}

func (m *transparentNetworkManager) Check() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	families, err := transparentAddressFamilies(m.bindAddrs)
	if err != nil {
		return nil, err
	}
	var missing []string
	if families[4] {
		data, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/src_valid_mark")
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(string(data)) != "1" {
			missing = append(missing, "net.ipv4.conf.all.src_valid_mark")
		}
	}
	for _, family := range []int{4, 6} {
		if !families[family] {
			continue
		}
		familyMissing, err := m.checkFamily(family)
		if err != nil {
			return nil, err
		}
		missing = append(missing, familyMissing...)
	}
	return missing, nil
}

func (m *transparentNetworkManager) Repair() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active || m.lockFile == nil {
		return fmt.Errorf("transparent upstream networking is not active")
	}
	families, err := transparentAddressFamilies(m.bindAddrs)
	if err != nil {
		return err
	}
	if families[4] {
		if err := m.ensureIPv4SourceMark(); err != nil {
			return err
		}
	}
	for _, family := range []int{4, 6} {
		if !families[family] {
			continue
		}
		if err := m.setupFamily(family); err != nil {
			return err
		}
		if err := m.probeFamily(family, firstAddressForFamily(m.bindAddrs, family)); err != nil {
			return err
		}
	}
	return nil
}

func (m *transparentNetworkManager) rollbackLocked() {
	for _, cleanup := range slices.Backward(m.cleanupActions) {
		cleanup()
	}
	m.cleanupActions = nil
	m.cleanupKeys = make(map[string]bool)
	if m.originalSrcMark != nil {
		current, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/src_valid_mark")
		if err == nil && strings.TrimSpace(string(current)) == "1" {
			_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/src_valid_mark", []byte(*m.originalSrcMark+"\n"), 0o644)
		}
		m.originalSrcMark = nil
	}
	if m.lockFile != nil {
		_ = unlockTransparentNetworkFile(m.lockFile)
		_ = m.lockFile.Close()
		m.lockFile = nil
	}
}

func (m *transparentNetworkManager) addCleanup(key string, cleanup func()) {
	if m.cleanupKeys[key] {
		return
	}
	m.cleanupKeys[key] = true
	m.cleanupActions = append(m.cleanupActions, cleanup)
}

func (m *transparentNetworkManager) acquireLock() error {
	lockFile, err := os.OpenFile(transparentLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open transparent networking lock %s: %w", transparentLockPath, err)
	}
	if err := lockTransparentNetworkFile(lockFile); err != nil {
		_ = lockFile.Close()
		return fmt.Errorf("another FlowGuard process owns transparent upstream networking: %w", err)
	}
	m.lockFile = lockFile
	return nil
}

func (m *transparentNetworkManager) ensureIPv4SourceMark() error {
	const path = "/proc/sys/net/ipv4/conf/all/src_valid_mark"
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	current := strings.TrimSpace(string(data))
	if current == "1" {
		return nil
	}
	if current != "0" {
		return fmt.Errorf("%s has unsupported value %q", path, current)
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("enable mark-aware reverse path validation: %w", err)
	}
	m.originalSrcMark = &current
	return nil
}

func (m *transparentNetworkManager) setupFamily(family int) error {
	binary := "iptables"
	routePrefix := "-4"
	routeCIDR := "0.0.0.0/0"
	if family == 6 {
		binary = "ip6tables"
		routePrefix = "-6"
		routeCIDR = "::/0"
	}

	createdChain := false
	if err := m.runner.Run(binary, "-t", "mangle", "-L", transparentFirewallChain); err != nil {
		if err := m.runner.Run(binary, "-t", "mangle", "-N", transparentFirewallChain); err != nil {
			return fmt.Errorf("create %s mangle chain: %w", binary, err)
		}
		createdChain = true
		m.addCleanup(binary+" chain", func() {
			_ = m.runner.Run(binary, "-t", "mangle", "-F", transparentFirewallChain)
			_ = m.runner.Run(binary, "-t", "mangle", "-X", transparentFirewallChain)
		})
	}

	mark := strconv.FormatUint(uint64(m.settings.FWMark), 10)
	expectedRules := [][]string{
		{"-m", "mark", "--mark", mark, "-j", "CONNMARK", "--save-mark"},
		{"-m", "connmark", "--mark", mark, "-j", "CONNMARK", "--restore-mark"},
	}
	if !createdChain {
		output, err := m.runner.Output(binary, "-t", "mangle", "-S", transparentFirewallChain)
		if err != nil {
			return fmt.Errorf("inspect %s chain: %w", binary, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
			if line == "" {
				continue
			}
			if !isManagedTransparentChainLine(line, m.settings.FWMark) {
				return fmt.Errorf("%s chain %s contains an unmanaged rule: %s", binary, transparentFirewallChain, line)
			}
		}
		m.addCleanup(binary+" chain", func() {
			_ = m.runner.Run(binary, "-t", "mangle", "-F", transparentFirewallChain)
			_ = m.runner.Run(binary, "-t", "mangle", "-X", transparentFirewallChain)
		})
	}
	for _, args := range expectedRules {
		checkArgs := append([]string{"-t", "mangle", "-C", transparentFirewallChain}, args...)
		if err := m.runner.Run(binary, checkArgs...); err != nil {
			addArgs := append([]string{"-t", "mangle", "-A", transparentFirewallChain}, args...)
			if err := m.runner.Run(binary, addArgs...); err != nil {
				return fmt.Errorf("add %s transparent mark rule: %w", binary, err)
			}
		}
		deleteArgs := append([]string{"-t", "mangle", "-D", transparentFirewallChain}, args...)
		m.addCleanup(binary+" rule "+strings.Join(args, " "), func() {
			_ = m.runner.Run(binary, deleteArgs...)
		})
	}

	jumpArgs := []string{"-j", transparentFirewallChain, "-m", "comment", "--comment", "FlowGuard transparent upstream"}
	outputRules, err := m.runner.Output(binary, "-t", "mangle", "-S", "OUTPUT")
	if err != nil {
		return fmt.Errorf("inspect %s OUTPUT chain: %w", binary, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(outputRules)), "\n") {
		if strings.Contains(line, "-j "+transparentFirewallChain) && !isManagedTransparentJumpLine(line) {
			return fmt.Errorf("%s OUTPUT contains an unmanaged jump to %s: %s", binary, transparentFirewallChain, line)
		}
	}
	checkJump := append([]string{"-t", "mangle", "-C", "OUTPUT"}, jumpArgs...)
	if err := m.runner.Run(binary, checkJump...); err != nil {
		addJump := append([]string{"-t", "mangle", "-I", "OUTPUT", "1"}, jumpArgs...)
		if err := m.runner.Run(binary, addJump...); err != nil {
			return fmt.Errorf("install %s transparent OUTPUT jump: %w", binary, err)
		}
	}
	deleteJump := append([]string{"-t", "mangle", "-D", "OUTPUT"}, jumpArgs...)
	m.addCleanup(binary+" OUTPUT jump", func() {
		_ = m.runner.Run(binary, deleteJump...)
	})

	if err := m.ensurePolicyRule(routePrefix); err != nil {
		return err
	}
	if err := m.ensureLocalRoute(routePrefix, routeCIDR); err != nil {
		return err
	}
	return nil
}

func isManagedTransparentChainLine(line string, mark uint32) bool {
	if line == "-N "+transparentFirewallChain {
		return true
	}
	fields := strings.Fields(line)
	if len(fields) < 9 ||
		fields[0] != "-A" ||
		fields[1] != transparentFirewallChain ||
		fields[2] != "-m" ||
		fields[4] != "--mark" ||
		fields[6] != "-j" ||
		fields[7] != "CONNMARK" {
		return false
	}
	action := ""
	switch fields[3] {
	case "mark":
		action = "--save-mark"
	case "connmark":
		action = "--restore-mark"
	default:
		return false
	}
	if fields[8] != action || !iptablesMarkTokenMatches(fields[5], mark) {
		return false
	}
	for i := 9; i < len(fields); i += 2 {
		if i+1 >= len(fields) ||
			(fields[i] != "--nfmask" && fields[i] != "--ctmask") ||
			!iptablesMarkTokenMatches(fields[i+1], ^uint32(0)) {
			return false
		}
	}
	return true
}

func iptablesMarkTokenMatches(token string, expected uint32) bool {
	value, mask, hasMask := strings.Cut(token, "/")
	parsed, err := strconv.ParseUint(value, 0, 32)
	if err != nil || uint32(parsed) != expected {
		return false
	}
	if !hasMask {
		return true
	}
	parsedMask, err := strconv.ParseUint(mask, 0, 32)
	return err == nil && uint32(parsedMask) == ^uint32(0)
}

func isManagedTransparentJumpLine(line string) bool {
	return strings.Contains(line, "-j "+transparentFirewallChain) &&
		strings.Contains(line, "FlowGuard transparent upstream")
}

func (m *transparentNetworkManager) checkFamily(family int) ([]string, error) {
	binary := "iptables"
	routePrefix := "-4"
	routeCIDR := "0.0.0.0/0"
	if family == 6 {
		binary = "ip6tables"
		routePrefix = "-6"
		routeCIDR = "::/0"
	}
	var missing []string
	if err := m.runner.Run(binary, "-t", "mangle", "-L", transparentFirewallChain); err != nil {
		missing = append(missing, binary+" mangle chain")
	} else {
		mark := strconv.FormatUint(uint64(m.settings.FWMark), 10)
		expectedRules := [][]string{
			{"-m", "mark", "--mark", mark, "-j", "CONNMARK", "--save-mark"},
			{"-m", "connmark", "--mark", mark, "-j", "CONNMARK", "--restore-mark"},
		}
		for _, args := range expectedRules {
			checkArgs := append([]string{"-t", "mangle", "-C", transparentFirewallChain}, args...)
			if err := m.runner.Run(binary, checkArgs...); err != nil {
				missing = append(missing, binary+" mark rule")
			}
		}
		jumpArgs := []string{
			"-t", "mangle", "-C", "OUTPUT", "-j", transparentFirewallChain,
			"-m", "comment", "--comment", "FlowGuard transparent upstream",
		}
		if err := m.runner.Run(binary, jumpArgs...); err != nil {
			missing = append(missing, binary+" OUTPUT jump")
		}
	}

	priority := strconv.FormatUint(uint64(m.settings.RulePriority), 10)
	mark := strconv.FormatUint(uint64(m.settings.FWMark), 10)
	table := strconv.FormatUint(uint64(m.settings.RouteTable), 10)
	rules, err := m.runner.Output("ip", routePrefix, "rule", "show")
	if err != nil {
		return nil, err
	}
	ruleFound := false
	for _, line := range strings.Split(string(rules), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), priority+":") &&
			(strings.Contains(line, "fwmark "+mark) || strings.Contains(line, fmt.Sprintf("fwmark 0x%x", m.settings.FWMark))) &&
			strings.Contains(line, "lookup "+table) {
			ruleFound = true
			break
		}
	}
	if !ruleFound {
		missing = append(missing, "IPv"+routePrefix[1:]+" policy rule")
	}
	routes, err := m.runner.Output("ip", routePrefix, "route", "show", "table", table)
	if err != nil {
		return nil, err
	}
	routeFound := false
	for _, line := range strings.Split(string(routes), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "local" &&
			(fields[1] == "default" || fields[1] == routeCIDR) &&
			fields[2] == "dev" && fields[3] == "lo" {
			routeFound = true
			break
		}
	}
	if !routeFound {
		missing = append(missing, "IPv"+routePrefix[1:]+" local route")
	}
	return missing, nil
}

func (m *transparentNetworkManager) ensurePolicyRule(family string) error {
	priority := strconv.FormatUint(uint64(m.settings.RulePriority), 10)
	mark := strconv.FormatUint(uint64(m.settings.FWMark), 10)
	table := strconv.FormatUint(uint64(m.settings.RouteTable), 10)
	output, err := m.runner.Output("ip", family, "rule", "show")
	if err != nil {
		return fmt.Errorf("inspect IPv%s policy rules: %w: %s", family[1:], err, strings.TrimSpace(string(output)))
	}
	var priorityLine string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), priority+":") {
			priorityLine = strings.TrimSpace(line)
			break
		}
	}
	if priorityLine != "" {
		markHex := fmt.Sprintf("0x%x", m.settings.FWMark)
		if (strings.Contains(priorityLine, "fwmark "+mark) || strings.Contains(priorityLine, "fwmark "+markHex)) &&
			(strings.Contains(priorityLine, "lookup "+table) || strings.Contains(priorityLine, "lookup "+routeTableName(m.settings.RouteTable))) {
			m.addCleanup("policy rule "+family, func() {
				_ = m.runner.Run("ip", family, "rule", "del", "priority", priority, "fwmark", mark, "lookup", table)
			})
			return nil
		}
		return fmt.Errorf("policy rule priority %s is already in use: %s", priority, priorityLine)
	}
	args := []string{family, "rule", "add", "priority", priority, "fwmark", mark, "lookup", table}
	if err := m.runner.Run("ip", args...); err != nil {
		return fmt.Errorf("add IPv%s transparent policy rule: %w", family[1:], err)
	}
	m.addCleanup("policy rule "+family, func() {
		_ = m.runner.Run("ip", family, "rule", "del", "priority", priority, "fwmark", mark, "lookup", table)
	})
	return nil
}

func (m *transparentNetworkManager) ensureLocalRoute(family, cidr string) error {
	table := strconv.FormatUint(uint64(m.settings.RouteTable), 10)
	output, err := m.runner.Output("ip", family, "route", "show", "table", table)
	if err != nil {
		if !isMissingRoutingTableError(output) {
			return fmt.Errorf("inspect IPv%s route table %s: %w: %s", family[1:], table, err, strings.TrimSpace(string(output)))
		}
		output = nil
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed != "" {
		for _, line := range strings.Split(trimmed, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 && fields[0] == "local" &&
				(fields[1] == "default" || fields[1] == cidr) &&
				fields[2] == "dev" && fields[3] == "lo" {
				m.addCleanup("local route "+family, func() {
					_ = m.runner.Run("ip", family, "route", "del", "local", cidr, "dev", "lo", "table", table)
				})
				return nil
			}
		}
		return fmt.Errorf("routing table %s is already in use: %s", table, trimmed)
	}
	if err := m.runner.Run("ip", family, "route", "add", "local", cidr, "dev", "lo", "table", table); err != nil {
		return fmt.Errorf("add IPv%s transparent local route: %w", family[1:], err)
	}
	m.addCleanup("local route "+family, func() {
		_ = m.runner.Run("ip", family, "route", "del", "local", cidr, "dev", "lo", "table", table)
	})
	return nil
}

func isMissingRoutingTableError(output []byte) bool {
	details := strings.ToLower(string(output))
	return strings.Contains(details, "fib table does not exist") ||
		strings.Contains(details, "routing table does not exist")
}

func routeTableName(table uint32) string {
	switch table {
	case 253:
		return "default"
	case 254:
		return "main"
	case 255:
		return "local"
	default:
		return strconv.FormatUint(uint64(table), 10)
	}
}

func (m *transparentNetworkManager) probeFamily(family int, bindAddr string) error {
	network := "tcp4"
	source, _ := netip.ParseAddr("192.0.2.254")
	if family == 6 {
		network = "tcp6"
		source, _ = netip.ParseAddr("2001:db8::ffff")
	}
	listener, err := net.Listen(network, net.JoinHostPort(bindAddr, "0"))
	if err != nil {
		return fmt.Errorf("start local probe backend on %s: %w", bindAddr, err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		remoteHost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			serverResult <- err
			return
		}
		remoteIP, err := netip.ParseAddr(remoteHost)
		if err != nil || remoteIP.Unmap() != source {
			serverResult <- fmt.Errorf("probe backend saw source %q, expected %s", remoteHost, source)
			return
		}
		payload := make([]byte, 4)
		if _, err := io.ReadFull(conn, payload); err != nil {
			serverResult <- err
			return
		}
		if string(payload) != "ping" {
			serverResult <- fmt.Errorf("unexpected probe payload %q", payload)
			return
		}
		_, err = conn.Write([]byte("pong"))
		serverResult <- err
	}()

	dialContext, err := transparentDialContext(source, m.settings.FWMark)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialContext(ctx, network, listener.Addr().String())
	if err != nil {
		return fmt.Errorf("dial local probe backend: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return err
	}
	if string(payload) != "pong" {
		return fmt.Errorf("unexpected probe response %q", payload)
	}
	if err := <-serverResult; err != nil {
		return err
	}
	return nil
}

func transparentAddressFamilies(bindAddrs []string) (map[int]bool, error) {
	result := make(map[int]bool)
	for _, raw := range bindAddrs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid bind address %q: %w", raw, err)
		}
		if addr.Unmap().Is4() {
			result[4] = true
		} else {
			result[6] = true
		}
	}
	return result, nil
}

func firstAddressForFamily(bindAddrs []string, family int) string {
	for _, raw := range bindAddrs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if (family == 4) == addr.Unmap().Is4() {
			return addr.Unmap().String()
		}
	}
	return ""
}
