package certmanager

import (
	"bufio"
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

// readDirectAdminSettings reads the key=value lines of directadmin.conf.
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
