package logger

import "fmt"

// flattenJSON rewrites the JSON object in src with nested objects flattened
// into keys joined by separator, in one pass over the encoded bytes. For
// example, with separator ".":
//
//	{"client":{"ip":"1.2.3.4","as":{"num":123}}}
//
// becomes:
//
//	{"client.ip":"1.2.3.4","client.as.num":123}
//
// Values other than objects, including arrays, are copied as they are, so
// numbers keep their exact encoding. Keys keep their JSON escapes, and empty
// objects leave no key. When captureKey is set, the raw value of that
// top-level key is returned as well.
func flattenJSON(src []byte, separator, captureKey string) (flattened, captured []byte, err error) {
	f := &jsonFlattener{
		src:        src,
		out:        make([]byte, 0, len(src)+len(src)/4),
		separator:  separator,
		captureKey: captureKey,
		first:      true,
	}

	f.out = append(f.out, '{')
	f.skipSpace()
	if string(src[f.pos:]) == "null" {
		// An entry without data
		return append(f.out, '}'), nil, nil
	}
	if err := f.object(nil); err != nil {
		return nil, nil, err
	}
	f.skipSpace()
	if f.pos != len(src) {
		return nil, nil, f.errorf("unexpected data after the object")
	}
	f.out = append(f.out, '}')

	return f.out, f.captured, nil
}

type jsonFlattener struct {
	src        []byte
	pos        int
	out        []byte
	separator  string
	captureKey string
	captured   []byte
	first      bool
}

// object reads the object at pos, whose keys are prefixed with prefix, the
// flattened key of the object (nil at the top level).
func (f *jsonFlattener) object(prefix []byte) error {
	if err := f.expect('{'); err != nil {
		return err
	}
	f.skipSpace()
	if f.peek() == '}' {
		f.pos++
		return nil
	}

	for {
		f.skipSpace()
		key, err := f.stringContent()
		if err != nil {
			return err
		}
		f.skipSpace()
		if err := f.expect(':'); err != nil {
			return err
		}
		f.skipSpace()

		fullKey := key
		if prefix != nil {
			fullKey = make([]byte, 0, len(prefix)+len(f.separator)+len(key))
			fullKey = append(append(append(fullKey, prefix...), f.separator...), key...)
		}

		if f.peek() == '{' {
			if err := f.object(fullKey); err != nil {
				return err
			}
		} else {
			start := f.pos
			if err := f.skipValue(); err != nil {
				return err
			}
			value := f.src[start:f.pos]

			if !f.first {
				f.out = append(f.out, ',')
			}
			f.first = false
			f.out = append(f.out, '"')
			f.out = append(f.out, fullKey...)
			f.out = append(f.out, '"', ':')
			f.out = append(f.out, value...)

			if prefix == nil && f.captureKey != "" && string(key) == f.captureKey {
				f.captured = value
			}
		}

		f.skipSpace()
		switch f.peek() {
		case ',':
			f.pos++
		case '}':
			f.pos++
			return nil
		default:
			return f.errorf("expected , or }")
		}
	}
}

// stringContent reads the string at pos and returns its raw content between
// the quotes, escapes included.
func (f *jsonFlattener) stringContent() ([]byte, error) {
	if err := f.expect('"'); err != nil {
		return nil, err
	}
	start := f.pos
	for f.pos < len(f.src) {
		switch f.src[f.pos] {
		case '\\':
			f.pos += 2
		case '"':
			content := f.src[start:f.pos]
			f.pos++
			return content, nil
		default:
			f.pos++
		}
	}
	return nil, f.errorf("unterminated string")
}

// skipValue moves past the value at pos.
func (f *jsonFlattener) skipValue() error {
	switch f.peek() {
	case '"':
		_, err := f.stringContent()
		return err
	case '{', '[':
		depth := 0
		for f.pos < len(f.src) {
			switch f.src[f.pos] {
			case '"':
				if _, err := f.stringContent(); err != nil {
					return err
				}
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					f.pos++
					return nil
				}
			}
			f.pos++
		}
		return f.errorf("unterminated container")
	case 0:
		return f.errorf("missing value")
	default:
		start := f.pos
		for f.pos < len(f.src) {
			switch f.src[f.pos] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				if f.pos == start {
					return f.errorf("missing value")
				}
				return nil
			}
			f.pos++
		}
		return nil
	}
}

func (f *jsonFlattener) peek() byte {
	if f.pos < len(f.src) {
		return f.src[f.pos]
	}
	return 0
}

func (f *jsonFlattener) expect(c byte) error {
	if f.peek() != c {
		return f.errorf("expected %q", c)
	}
	f.pos++
	return nil
}

func (f *jsonFlattener) skipSpace() {
	for f.pos < len(f.src) {
		switch f.src[f.pos] {
		case ' ', '\t', '\n', '\r':
			f.pos++
		default:
			return
		}
	}
}

func (f *jsonFlattener) errorf(format string, args ...any) error {
	return fmt.Errorf("invalid log entry JSON at byte %d: %s", f.pos, fmt.Sprintf(format, args...))
}
