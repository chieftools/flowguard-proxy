package certmanager

import (
	"bufio"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// DirectAdmin keeps one certificate per domain in
// data/users/<user>/domains/<domain>.cert.combined, with its private key in
// <domain>.key next to it. The server hostname's certificate, chain and key
// default to conf/cacert.pem, conf/carootcert.pem and conf/cakey.pem, and
// directadmin.conf can move them with the cacert, carootcert and cakey keys.

// IsDirectAdminRoot reports whether path is a DirectAdmin installation, such
// as /usr/local/directadmin.
func IsDirectAdminRoot(path string) bool {
	if path == "" {
		return false
	}
	if info, err := os.Stat(filepath.Join(path, "conf", "directadmin.conf")); err != nil || info.IsDir() {
		return false
	}
	info, err := os.Stat(filepath.Join(path, "data", "users"))
	return err == nil && info.IsDir()
}

// directAdminCertificates lists the certificate pairs of a DirectAdmin
// installation, starting with the server hostname's certificate.
func directAdminCertificates(root string) []Certificate {
	var pairs []Certificate

	hostname := directAdminHostnameCertificate(root)
	if fileExists(hostname.CertPath) && fileExists(hostname.KeyPath) {
		pairs = append(pairs, hostname)
	}

	certPaths, _ := filepath.Glob(filepath.Join(root, "data", "users", "*", "domains", "*.cert.combined"))
	sort.Strings(certPaths)
	for _, certPath := range certPaths {
		keyPath := strings.TrimSuffix(certPath, ".cert.combined") + ".key"
		if fileExists(keyPath) {
			pairs = append(pairs, Certificate{CertPath: certPath, KeyPath: keyPath})
		}
	}

	return pairs
}

// directAdminWatchDirs lists the directories whose changes can add, renew or
// remove a DirectAdmin certificate. Watching data/users picks up new users.
func directAdminWatchDirs(root string) []string {
	dirs := []string{filepath.Join(root, "data", "users")}

	domainDirs, _ := filepath.Glob(filepath.Join(root, "data", "users", "*", "domains"))
	sort.Strings(domainDirs)
	dirs = append(dirs, domainDirs...)

	hostname := directAdminHostnameCertificate(root)
	for _, path := range []string{hostname.CertPath, hostname.ChainPath, hostname.KeyPath} {
		if dir := filepath.Dir(path); !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
	}

	return dirs
}

func directAdminHostnameCertificate(root string) Certificate {
	settings := readDirectAdminSettings(filepath.Join(root, "conf", "directadmin.conf"))
	setting := func(key, fallback string) string {
		if value := settings[key]; filepath.IsAbs(value) {
			return value
		}
		return filepath.Join(root, "conf", fallback)
	}

	return Certificate{
		CertPath:  setting("cacert", "cacert.pem"),
		ChainPath: setting("carootcert", "carootcert.pem"),
		KeyPath:   setting("cakey", "cakey.pem"),
	}
}

// DiscoverDirectAdminAddressPairs reads the IPv4/IPv6 links DirectAdmin keeps
// in data/admin/ips/<ip> as linked_ips, a URL-encoded list of linked
// addresses with their options. Only links that DirectAdmin applies to the web
// server (apache=yes) are used, and an address linked to more than one
// counterpart is reported as ambiguous rather than guessed.
func DiscoverDirectAdminAddressPairs(root string) ([]AddressPair, []string, []string) {
	dir := filepath.Join(root, "data", "admin", "ips")
	diagnostics := []string{fmt.Sprintf("directadmin: inspecting linked IPs in %s", dir)}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []string{fmt.Sprintf("could not read DirectAdmin IPs: %v", err)}, diagnostics
	}

	links := make(map[AddressPair]bool)
	for _, entry := range entries {
		ip, err := netip.ParseAddr(entry.Name())
		if err != nil || entry.IsDir() {
			continue
		}
		ip = ip.Unmap()

		linked, err := url.ParseQuery(readDirectAdminSettings(filepath.Join(dir, entry.Name()))["linked_ips"])
		if err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf("directadmin: skipped linked IPs of %s: %v", ip, err))
			continue
		}
		for raw, options := range linked {
			other, err := netip.ParseAddr(raw)
			if err != nil {
				continue
			}
			other = other.Unmap()
			if ip.Is4() == other.Is4() {
				continue
			}
			if values, _ := url.ParseQuery(strings.Join(options, "&")); values.Get("apache") != "yes" {
				diagnostics = append(diagnostics, fmt.Sprintf("directadmin: ignored link %s <-> %s because it does not apply to the web server", ip, other))
				continue
			}
			pair := AddressPair{IPv4: ip.String(), IPv6: other.String()}
			if ip.Is6() {
				pair = AddressPair{IPv4: other.String(), IPv6: ip.String()}
			}
			links[pair] = true
		}
	}

	counterparts := make(map[string]int)
	for pair := range links {
		counterparts[pair.IPv4]++
		counterparts[pair.IPv6]++
	}

	var pairs []AddressPair
	var warnings []string
	for pair := range links {
		if counterparts[pair.IPv4] > 1 || counterparts[pair.IPv6] > 1 {
			warnings = append(warnings, fmt.Sprintf("DirectAdmin link %s <-> %s is ambiguous because an address is linked more than once", pair.IPv4, pair.IPv6))
			continue
		}
		pairs = append(pairs, pair)
		diagnostics = append(diagnostics, fmt.Sprintf("directadmin: accepted %s <-> %s", pair.IPv4, pair.IPv6))
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].IPv4 < pairs[j].IPv4
	})
	sort.Strings(warnings)
	sort.Strings(diagnostics[1:])
	if len(pairs) == 0 {
		diagnostics = append(diagnostics, "directadmin: no linked IPv4/IPv6 pairs were found")
	}

	return pairs, warnings, diagnostics
}

// readDirectAdminSettings reads the key=value lines of a DirectAdmin settings
// file, such as directadmin.conf.
func readDirectAdminSettings(path string) map[string]string {
	settings := make(map[string]string)

	file, err := os.Open(path)
	if err != nil {
		return settings
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			settings[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}

	return settings
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
