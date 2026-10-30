package certmanager

import (
	"os"
	"path/filepath"
)

// Certbot keeps each certificate lineage in live/<name>/ under its config
// directory, such as /etc/letsencrypt, with the chain in fullchain.pem and the
// private key in privkey.pem. Both are symlinks into archive/<name>/, and a
// renewal replaces each symlink by removing and recreating it, with
// fullchain.pem last.

// IsCertbotRoot reports whether path is a certbot config directory, such as
// /etc/letsencrypt.
func IsCertbotRoot(path string) bool {
	if path == "" {
		return false
	}
	for _, dir := range []string{"live", "renewal"} {
		if info, err := os.Stat(filepath.Join(path, dir)); err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

// certbotCertificates lists the certificate pairs of the lineages in a certbot
// config directory.
func certbotCertificates(root string) []Certificate {
	var pairs []Certificate

	for _, dir := range certbotLineageDirs(root) {
		certPath := filepath.Join(dir, "fullchain.pem")
		keyPath := filepath.Join(dir, "privkey.pem")
		if fileExists(certPath) && fileExists(keyPath) {
			pairs = append(pairs, Certificate{CertPath: certPath, KeyPath: keyPath})
		}
	}

	return pairs
}

// certbotWatchDirs lists the directories whose changes can add, renew or
// remove a certbot certificate. Watching live picks up new lineages.
func certbotWatchDirs(root string) []string {
	return append([]string{filepath.Join(root, "live")}, certbotLineageDirs(root)...)
}

func certbotLineageDirs(root string) []string {
	var dirs []string

	entries, _ := os.ReadDir(filepath.Join(root, "live"))
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, filepath.Join(root, "live", entry.Name()))
		}
	}

	return dirs
}
