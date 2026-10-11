package normalization

import "strings"

// CookieValues returns every value of the named cookie in the given Cookie
// header lines for rule matching. Unlike net/http it never drops a cookie for
// containing bytes such as "\", a stray '"' or non-ASCII text, which backends
// such as PHP accept. Each value is returned as sent, without surrounding
// quotes and percent-decoded (as PHP and common Node parsers decode it), so a
// value cannot be hidden from rules by encoding it.
func CookieValues(headers []string, name string) []string {
	var values []string
	for _, header := range headers {
		for _, pair := range strings.Split(header, ";") {
			key, value, _ := strings.Cut(strings.TrimSpace(pair), "=")
			if strings.TrimSpace(key) != name {
				continue
			}
			values = appendUnique(values, value)
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
				values = appendUnique(values, value)
			}
			values = appendUnique(values, unescapeQueryComponent(value))
		}
	}
	return values
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
