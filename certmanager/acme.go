package certmanager

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"slices"
	"time"
)

// traefikACMEStore contains only the certificate material FlowGuard needs from
// Traefik v2/v3 storage. Account data is intentionally not represented.
type traefikACMEStore map[string]traefikACMEResolver

type traefikACMEResolver struct {
	Certificates []traefikACMECertificate `json:"Certificates"`
}

type traefikACMECertificate struct {
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
}

type traefikACMEEntry struct {
	Resolver    string
	Index       int
	Certificate []byte
	Key         []byte
	DecodeError error
}

func parseTraefikACME(data []byte) ([]traefikACMEEntry, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("ACME storage file is empty")
	}

	var store traefikACMEStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("parse Traefik ACME storage: %w", err)
	}
	if store == nil {
		return nil, fmt.Errorf("Traefik ACME storage must be a resolver object")
	}

	resolverNames := make([]string, 0, len(store))
	for resolverName := range store {
		resolverNames = append(resolverNames, resolverName)
	}
	slices.Sort(resolverNames)

	var entries []traefikACMEEntry
	for _, resolverName := range resolverNames {
		resolver := store[resolverName]
		for index, certificate := range resolver.Certificates {
			certPEM, certErr := base64.StdEncoding.DecodeString(certificate.Certificate)
			keyPEM, keyErr := base64.StdEncoding.DecodeString(certificate.Key)
			var decodeErr error
			if certErr != nil {
				decodeErr = fmt.Errorf("decode certificate: %w", certErr)
			}
			if keyErr != nil {
				if decodeErr != nil {
					decodeErr = fmt.Errorf("%v; decode private key: %w", decodeErr, keyErr)
				} else {
					decodeErr = fmt.Errorf("decode private key: %w", keyErr)
				}
			}
			entries = append(entries, traefikACMEEntry{
				Resolver:    resolverName,
				Index:       index,
				Certificate: certPEM,
				Key:         keyPEM,
				DecodeError: decodeErr,
			})
		}
	}

	return entries, nil
}

func parseACMECertificateBundle(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, fmt.Errorf("missing certificate or private key")
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("certificate bundle is empty")
	}

	chain := make([]*x509.Certificate, 0, len(cert.Certificate))
	for index, der := range cert.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d in bundle: %w", index, err)
		}
		chain = append(chain, parsed)
	}
	if chain[0].IsCA {
		return nil, fmt.Errorf("certificate bundle must start with a leaf certificate")
	}
	for index := 0; index+1 < len(chain); index++ {
		if err := chain[index].CheckSignatureFrom(chain[index+1]); err != nil {
			return nil, fmt.Errorf("certificate %d is not signed by certificate %d: %w", index, index+1, err)
		}
	}

	cert.Leaf = chain[0]
	return &cert, nil
}

func traefikACMESourceID(path string, entry traefikACMEEntry) string {
	return fmt.Sprintf("%s#resolver=%q,certificate=%d", path, entry.Resolver, entry.Index)
}

func (cm *Manager) loadTraefikACMECertificates(path string, verbose bool) ([]*certificateWithMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Traefik ACME storage: %w", err)
	}

	entries, err := parseTraefikACME(data)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	certificates := make([]*certificateWithMetadata, 0, len(entries))
	for _, entry := range entries {
		sourceID := traefikACMESourceID(path, entry)
		if entry.DecodeError != nil {
			if verbose {
				log.Printf("[cert_manager] Skipping invalid Traefik ACME certificate %s: %v", sourceID, entry.DecodeError)
			}
			continue
		}
		cert, err := parseACMECertificateBundle(entry.Certificate, entry.Key)
		if err != nil {
			if verbose {
				log.Printf("[cert_manager] Skipping invalid Traefik ACME certificate %s: %v", sourceID, err)
			}
			continue
		}
		if now.After(cert.Leaf.NotAfter) {
			if verbose {
				log.Printf("[cert_manager] Skipping expired Traefik ACME certificate %s (expired %s)", sourceID, cert.Leaf.NotAfter.Format("2006-01-02"))
			}
			continue
		}

		hostnames := cm.getCertificateHostnames(cert.Leaf)
		if len(hostnames) == 0 {
			if verbose {
				log.Printf("[cert_manager] Skipping Traefik ACME certificate %s without valid hostnames", sourceID)
			}
			continue
		}

		metadata := cm.extractCertificateMetadata(cert, sourceID, hostnames)
		if metadata != nil {
			certificates = append(certificates, metadata)
		}
	}

	return certificates, nil
}

func (cm *Manager) loadTraefikACMECertificatesWithRetry(path string, verbose bool) ([]*certificateWithMetadata, error) {
	const (
		attempts   = 3
		retryDelay = 100 * time.Millisecond
	)

	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		var certificates []*certificateWithMetadata
		certificates, err = cm.loadTraefikACMECertificates(path, verbose)
		if err == nil {
			return certificates, nil
		}
		if attempt+1 < attempts {
			time.Sleep(retryDelay)
		}
	}

	return nil, err
}
