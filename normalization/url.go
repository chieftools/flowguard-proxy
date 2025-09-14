package normalization

import (
	"strings"
)

// NormalizeURL performs URL normalization similar to Cloudflare's approach
// This includes RFC 3986 normalization and Cloudflare-specific normalizations
func NormalizeURL(rawURL string) string {
	// Step 1: Convert backslashes to forward slashes (Cloudflare-specific)
	normalizedURL := strings.ReplaceAll(rawURL, "\\", "/")

	// Step 2: Merge successive slashes (Cloudflare-specific)
	normalizedURL = mergeSuccessiveSlashes(normalizedURL)

	// Step 3: Apply RFC 3986 normalization
	normalizedURL = applyRFC3986Normalization(normalizedURL)

	return normalizedURL
}

// NormalizePath performs path-only normalization
func NormalizePath(path string) string {
	// Step 1: Convert backslashes to forward slashes
	normalizedPath := strings.ReplaceAll(path, "\\", "/")

	// Step 2: Merge successive slashes
	normalizedPath = mergeSuccessiveSlashes(normalizedPath)

	// Step 3: Percent decode unreserved characters
	normalizedPath = percentDecodeUnreserved(normalizedPath)

	// Step 4: Remove dot segments (RFC 3986 Section 5.2.4)
	normalizedPath = removeDotSegments(normalizedPath)

	// Step 5: Uppercase percent-encoded representations
	normalizedPath = uppercasePercentEncoding(normalizedPath)

	return normalizedPath
}

// mergeSuccessiveSlashes merges multiple consecutive slashes into a single slash
// but preserves the double slash after scheme (e.g., http://)
func mergeSuccessiveSlashes(s string) string {
	var result strings.Builder
	prevSlash := false

	// Check if we have a scheme (http://, https://, etc.)
	if idx := strings.Index(s, "://"); idx != -1 {
		// Copy everything up to and including ://
		result.WriteString(s[:idx+3])
		s = s[idx+3:]
	}

	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			if !prevSlash {
				result.WriteByte('/')
				prevSlash = true
			}
		} else {
			result.WriteByte(s[i])
			prevSlash = false
		}
	}

	return result.String()
}

// applyRFC3986Normalization applies RFC 3986 normalization to the URL
func applyRFC3986Normalization(rawURL string) string {
	// Find where the path starts (after scheme and host)
	pathStart := 0
	if idx := strings.Index(rawURL, "://"); idx != -1 {
		// Find the start of the path after the host
		hostStart := idx + 3
		pathStart = strings.IndexAny(rawURL[hostStart:], "/?#")
		if pathStart == -1 {
			// No path component
			return rawURL
		}
		pathStart += hostStart
	}

	// Split URL into parts
	prefix := rawURL[:pathStart]
	pathAndSuffix := rawURL[pathStart:]

	// Find query and fragment
	queryStart := strings.IndexAny(pathAndSuffix, "?#")
	path := pathAndSuffix
	suffix := ""
	if queryStart != -1 {
		path = pathAndSuffix[:queryStart]
		suffix = pathAndSuffix[queryStart:]
	}

	// Normalize just the path component
	normalizedPath := percentDecodeUnreserved(path)
	normalizedPath = removeDotSegments(normalizedPath)
	normalizedPath = uppercasePercentEncoding(normalizedPath)

	// Reconstruct the URL
	return prefix + normalizedPath + suffix
}

// percentDecodeUnreserved decodes percent-encoded unreserved characters
// Unreserved characters: a-z, A-Z, 0-9, -, ., _, ~
func percentDecodeUnreserved(s string) string {
	var result strings.Builder

	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			// Check if we have a valid percent-encoded sequence
			hex1, hex2 := s[i+1], s[i+2]
			if isHexDigit(hex1) && isHexDigit(hex2) {
				// Decode the hex value
				decoded := hexToByte(hex1, hex2)

				// Check if it's an unreserved character
				if isUnreserved(decoded) {
					// Decode it
					result.WriteByte(decoded)
					i += 2 // Skip the next two characters
				} else {
					// Keep it encoded but uppercase
					result.WriteByte('%')
					result.WriteByte(toUpperHex(hex1))
					result.WriteByte(toUpperHex(hex2))
					i += 2
				}
			} else {
				// Invalid percent encoding, keep as is
				result.WriteByte(s[i])
			}
		} else {
			result.WriteByte(s[i])
		}
	}

	return result.String()
}

// removeDotSegments implements RFC 3986 Section 5.2.4
func removeDotSegments(path string) string {
	if path == "" {
		return ""
	}

	// Track if path started/ended with slash
	startsWithSlash := strings.HasPrefix(path, "/")
	endsWithSlash := strings.HasSuffix(path, "/")

	// Split path into segments
	segments := strings.Split(path, "/")
	var stack []string

	for _, segment := range segments {
		if segment == ".." {
			// Pop from stack if possible
			if len(stack) > 0 && stack[len(stack)-1] != ".." {
				stack = stack[:len(stack)-1]
			} else if !startsWithSlash && len(stack) == 0 {
				// For relative paths, keep the ".."
				stack = append(stack, segment)
			}
		} else if segment != "." && segment != "" {
			// Add normal segments (ignore "." and empty segments)
			stack = append(stack, segment)
		}
	}

	// Reconstruct the path
	result := strings.Join(stack, "/")

	// Preserve leading slash
	if startsWithSlash {
		if result == "" {
			if endsWithSlash {
				return "/"
			}
			return "/"
		}
		result = "/" + result
	}

	// Preserve trailing slash
	if endsWithSlash && result != "" && result != "/" {
		result = result + "/"
	}

	return result
}

// uppercasePercentEncoding converts percent-encoded hex digits to uppercase
func uppercasePercentEncoding(s string) string {
	var result strings.Builder

	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hex1, hex2 := s[i+1], s[i+2]
			if isHexDigit(hex1) && isHexDigit(hex2) {
				result.WriteByte('%')
				result.WriteByte(toUpperHex(hex1))
				result.WriteByte(toUpperHex(hex2))
				i += 2
			} else {
				result.WriteByte(s[i])
			}
		} else {
			result.WriteByte(s[i])
		}
	}

	return result.String()
}

// isUnreserved checks if a byte is an unreserved character according to RFC 3986
// Note: tilde (~) is unreserved and should be decoded
func isUnreserved(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '.' || b == '_' || b == '~'
}

// isHexDigit checks if a byte is a valid hex digit
func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'f') ||
		(b >= 'A' && b <= 'F')
}

// hexToByte converts two hex digits to a byte
func hexToByte(h1, h2 byte) byte {
	return hexValue(h1)<<4 | hexValue(h2)
}

// hexValue converts a hex digit to its numeric value
func hexValue(h byte) byte {
	if h >= '0' && h <= '9' {
		return h - '0'
	}
	if h >= 'a' && h <= 'f' {
		return h - 'a' + 10
	}
	if h >= 'A' && h <= 'F' {
		return h - 'A' + 10
	}
	return 0
}

// toUpperHex converts a lowercase hex digit to uppercase
func toUpperHex(h byte) byte {
	if h >= 'a' && h <= 'f' {
		return h - 'a' + 'A'
	}
	return h
}
