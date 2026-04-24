package proxy

import (
	"fmt"
	"log"
	"net"
	"os/exec"
)

const (
	firewallStatusDisabled = "disabled"
	firewallStatusHealthy  = "healthy"
	firewallStatusDegraded = "degraded"
)

type firewallRunner interface {
	Run(name string, args ...string) error
}

type execFirewallRunner struct{}

func (execFirewallRunner) Run(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

type firewallRuleSpec struct {
	command   string
	table     string
	setupVerb string
	chain     string
	args      []string
}

func (r firewallRuleSpec) commandArgs(verb string) []string {
	args := make([]string, 0, len(r.args)+4)
	if r.table != "" {
		args = append(args, "-t", r.table)
	}
	args = append(args, verb, r.chain)
	args = append(args, r.args...)
	return args
}

func (s *Server) firewallRules() ([]firewallRuleSpec, string, error) {
	if !s.managesRedirect() {
		return nil, "", nil
	}

	iface, err := s.interfaceLookup(s.config.bindAddr)
	if err != nil {
		return nil, "", fmt.Errorf("could not detect interface for IP %s: %w", s.config.bindAddr, err)
	}

	iptablesCmd := "iptables"
	if parsedIP := net.ParseIP(s.config.bindAddr); parsedIP != nil && parsedIP.To4() == nil {
		iptablesCmd = "ip6tables"
	}

	protocols := []string{"tcp"}
	if s.config.scheme == "https" {
		protocols = append(protocols, "udp")
	}

	rules := make([]firewallRuleSpec, 0, len(protocols)*2)
	for _, protocol := range protocols {
		rules = append(rules,
			firewallRuleSpec{
				command:   iptablesCmd,
				setupVerb: "-I",
				chain:     "INPUT",
				args: []string{
					"-d", s.config.bindAddr,
					"-p", protocol,
					"--dport", s.config.bindPort,
					"-j", "ACCEPT",
					"-m", "comment", "--comment", "FlowGuard",
				},
			},
			firewallRuleSpec{
				command:   iptablesCmd,
				table:     "nat",
				setupVerb: "-A",
				chain:     "PREROUTING",
				args: []string{
					"-i", iface,
					"-d", s.config.bindAddr,
					"-p", protocol,
					"--dport", s.config.redirPort,
					"-j", "DNAT",
					"--to-destination", fmt.Sprintf("%s:%s", maybeFormatV6Addr(s.config.bindAddr), s.config.bindPort),
					"-m", "comment", "--comment", "FlowGuard",
				},
			},
		)
	}

	return rules, iface, nil
}

func (s *Server) managesRedirect() bool {
	return s.config.redirPort != ""
}

func (s *Server) runFirewallRule(rule firewallRuleSpec, verb string) error {
	return s.runner.Run(rule.command, rule.commandArgs(verb)...)
}

func (s *Server) CheckPortRedirect() ([]firewallRuleSpec, error) {
	rules, _, err := s.firewallRules()
	if err != nil || len(rules) == 0 {
		return nil, err
	}

	missing := make([]firewallRuleSpec, 0, len(rules))
	for _, rule := range rules {
		if err := s.runFirewallRule(rule, "-C"); err != nil {
			missing = append(missing, rule)
		}
	}

	return missing, nil
}

func (s *Server) RepairPortRedirect(rules []firewallRuleSpec) error {
	for _, rule := range rules {
		if err := s.runFirewallRule(rule, rule.setupVerb); err != nil {
			return fmt.Errorf("failed to repair %s rule for %s:%s: %w", rule.command, s.config.bindAddr, s.config.bindPort, err)
		}
	}

	return nil
}

func (s *Server) SetupPortRedirect() error {
	if !s.managesRedirect() {
		return nil
	}

	s.CleanupPortRedirect()

	rules, iface, err := s.firewallRules()
	if err != nil {
		return err
	}

	for _, rule := range rules {
		if err := s.runFirewallRule(rule, rule.setupVerb); err != nil {
			s.CleanupPortRedirect()
			return fmt.Errorf("failed to setup %s rules for %s:%s: %w", rule.command, s.config.bindAddr, s.config.bindPort, err)
		}
	}

	log.Printf("[%s] redirection setup complete for %s:%s on interface %s", rules[0].command, s.config.bindAddr, s.config.bindPort, iface)
	return nil
}

func (s *Server) CleanupPortRedirect() {
	if !s.managesRedirect() {
		return
	}

	rules, _, err := s.firewallRules()
	if err != nil {
		log.Printf("Warning: %v", err)
		return
	}

	totalRemoved := 0
	for _, rule := range rules {
		removed := 0
		for {
			if err := s.runFirewallRule(rule, "-D"); err != nil {
				break
			}
			removed++
			totalRemoved++
		}
		if s.config.verbose && removed > 0 {
			log.Printf("[%s] removed %d instance(s) of rule: %v", rule.command, removed, rule.commandArgs("-D"))
		}
	}

	if totalRemoved > 0 {
		log.Printf("[%s] redirection cleanup complete for %s:%s (%d rules removed)", rules[0].command, s.config.bindAddr, s.config.bindPort, totalRemoved)
	}
}
