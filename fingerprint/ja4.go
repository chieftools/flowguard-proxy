package fingerprint

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
)

const zeroHash = "000000000000"

// JA4FromClientHello computes a JA4 client fingerprint from Go's parsed
// ClientHello metadata. transport must be "t" for TCP TLS or "q" for QUIC.
func JA4FromClientHello(hello *tls.ClientHelloInfo, transport string) string {
	if hello == nil || (transport != "t" && transport != "q") {
		return ""
	}

	ciphers := normalizedNonGREASE(hello.CipherSuites)
	extensions := normalizedNonGREASE(hello.Extensions)

	cipherCount := min(len(ciphers), 99)
	extensionCount := min(len(extensions), 99)

	sni := "i"
	if hello.ServerName != "" {
		sni = "d"
	}

	a := fmt.Sprintf(
		"%s%s%s%02d%02d%s",
		transport,
		tlsVersion(hello.SupportedVersions),
		sni,
		cipherCount,
		extensionCount,
		alpn(hello.SupportedProtos),
	)

	return fmt.Sprintf("%s_%s_%s", a, hashValues(ciphers), hashExtensions(extensions, hello.SignatureSchemes))
}

func tlsVersion(versions []uint16) string {
	values := make([]uint16, 0, len(versions))
	for _, version := range versions {
		if !isGREASE(version) {
			values = append(values, version)
		}
	}
	if len(values) == 0 {
		return "00"
	}

	sort.Slice(values, func(i, j int) bool {
		return values[i] < values[j]
	})

	switch values[len(values)-1] {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case tls.VersionSSL30:
		return "s3"
	default:
		return "00"
	}
}

func alpn(protocols []string) string {
	if len(protocols) == 0 || protocols[0] == "" {
		return "00"
	}

	proto := []byte(protocols[0])
	if proto[0] > 127 {
		return "99"
	}
	if len(proto) > 2 {
		return string([]byte{proto[0], proto[len(proto)-1]})
	}
	return string(proto)
}

func normalizedNonGREASE(values []uint16) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		if !isGREASE(value) {
			normalized = append(normalized, hex4(value))
		}
	}
	return normalized
}

func hashValues(values []string) string {
	if len(values) == 0 {
		return zeroHash
	}

	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return hashString(strings.Join(sorted, ","))
}

func hashExtensions(extensions []string, signatures []tls.SignatureScheme) string {
	sorted := make([]string, 0, len(extensions))
	hasSignatureAlgorithms := false
	for _, extension := range extensions {
		switch extension {
		case "0000", "0010":
			continue
		case "000d":
			hasSignatureAlgorithms = true
		}
		sorted = append(sorted, extension)
	}
	sort.Strings(sorted)

	value := strings.Join(sorted, ",")
	if hasSignatureAlgorithms && len(signatures) > 0 {
		sigValues := make([]string, 0, len(signatures))
		for _, signature := range signatures {
			if !isGREASE(uint16(signature)) {
				sigValues = append(sigValues, hex4(uint16(signature)))
			}
		}
		if len(sigValues) > 0 {
			value += "_" + strings.Join(sigValues, ",")
		}
	}

	if value == "" {
		return zeroHash
	}
	return hashString(value)
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:])[:12]
}

func hex4(value uint16) string {
	return fmt.Sprintf("%04x", value)
}

func isGREASE(value uint16) bool {
	return value&0x0f0f == 0x0a0a && byte(value>>8) == byte(value)
}
