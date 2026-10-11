package normalization

import (
	"net/url"
	"strings"
)

// ParseQuery parses a raw query string for rule matching. Unlike
// url.ParseQuery it never drops a pair: pairs are split on "&" only, so a ";"
// stays part of the key or value, and invalid percent escapes are kept as
// literal text. This matches how common backends such as PHP read the query,
// so a value cannot be hidden from rules by adding a ";" or a "%zz" while the
// raw query is still forwarded upstream unchanged.
func ParseQuery(rawQuery string) url.Values {
	values := make(url.Values)
	for rawQuery != "" {
		var pair string
		pair, rawQuery, _ = strings.Cut(rawQuery, "&")
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		key = unescapeQueryComponent(key)
		values[key] = append(values[key], unescapeQueryComponent(value))
	}
	return values
}

// unescapeQueryComponent decodes "+" as a space and valid percent escapes,
// leaving invalid escapes as literal text.
func unescapeQueryComponent(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}

	var result strings.Builder
	result.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '+':
			result.WriteByte(' ')
		case s[i] == '%' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]):
			result.WriteByte(hexToByte(s[i+1], s[i+2]))
			i += 2
		default:
			result.WriteByte(s[i])
		}
	}
	return result.String()
}
