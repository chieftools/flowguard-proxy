package middleware

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestIPLookupReloadsADatabaseReplacedAtTheSamePath(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ip.mmdb")
	writeTestASNDatabase(t, dbPath, "AS64500")

	m := &IPLookupMiddleware{}
	t.Cleanup(func() {
		if m.asnDB != nil {
			m.asnDB.Close()
		}
	})
	if err := m.openASNDatabase(dbPath); err != nil {
		t.Fatalf("open database: %v", err)
	}
	if asn := m.lookupASN("192.0.2.1"); asn == nil || asn.ASN != "AS64500" {
		t.Fatalf("lookup = %+v, want AS64500", asn)
	}

	opened := m.asnDB
	if err := m.openASNDatabase(dbPath); err != nil || m.asnDB != opened {
		t.Fatalf("expected the unchanged database to stay open (err %v)", err)
	}

	// The cache replaces a refreshed download by renaming a new file over it.
	replacement := filepath.Join(dir, "ip.mmdb.tmp")
	writeTestASNDatabase(t, replacement, "AS64501")
	if err := os.Rename(replacement, dbPath); err != nil {
		t.Fatalf("replace database: %v", err)
	}
	if err := m.openASNDatabase(dbPath); err != nil {
		t.Fatalf("reload database: %v", err)
	}
	if asn := m.lookupASN("192.0.2.1"); asn == nil || asn.ASN != "AS64501" {
		t.Fatalf("lookup after refresh = %+v, want AS64501", asn)
	}
}

func TestIPLookupCachesRecordsWithAndWithoutAnASN(t *testing.T) {
	for _, test := range []struct {
		asn  string
		want string
	}{{asn: "AS64500", want: "AS64500"}, {asn: "", want: ""}} {
		dbPath := filepath.Join(t.TempDir(), "ip.mmdb")
		writeTestASNDatabase(t, dbPath, test.asn)
		m := &IPLookupMiddleware{}
		if err := m.openASNDatabase(dbPath); err != nil {
			t.Fatalf("open database: %v", err)
		}

		first, second := m.lookupASN("192.0.2.1"), m.lookupASN("198.51.100.1")
		m.asnDB.Close()
		if test.want == "" {
			if first != nil || second != nil {
				t.Fatalf("lookups = %+v, %+v; want nil for a record without an ASN", first, second)
			}
			continue
		}
		if first == nil || first.ASN != test.want || second != first {
			t.Fatalf("lookups = %+v, %+v; want the same cached %s record", first, second, test.want)
		}
	}
}

// writeTestASNDatabase writes a minimal IPv4 MaxMind DB in which every
// address maps to one record with the given ASN.
func writeTestASNDatabase(t *testing.T, path, asn string) {
	t.Helper()

	var db bytes.Buffer
	// One search tree node with 24-bit records that both point to the first
	// data record: node count (1) + separator (16) + data offset (0).
	db.Write([]byte{0, 0, 17, 0, 0, 17})
	db.Write(make([]byte, 16))
	writeMMDBMap(&db, map[string]func(*bytes.Buffer){
		"asn":          func(b *bytes.Buffer) { writeMMDBString(b, asn) },
		"country_code": func(b *bytes.Buffer) { writeMMDBString(b, "XZ") },
	})
	db.WriteString("\xab\xcd\xefMaxMind.com")
	writeMMDBMap(&db, map[string]func(*bytes.Buffer){
		"node_count":  func(b *bytes.Buffer) { writeMMDBUint(b, 6, 4, 1) },
		"record_size": func(b *bytes.Buffer) { writeMMDBUint(b, 5, 2, 24) },
		"ip_version":  func(b *bytes.Buffer) { writeMMDBUint(b, 5, 2, 4) },
	})

	if err := os.WriteFile(path, db.Bytes(), 0o644); err != nil {
		t.Fatalf("write database: %v", err)
	}
}

func writeMMDBMap(b *bytes.Buffer, fields map[string]func(*bytes.Buffer)) {
	b.WriteByte(7<<5 | byte(len(fields)))
	for key, writeValue := range fields {
		writeMMDBString(b, key)
		writeValue(b)
	}
}

func writeMMDBString(b *bytes.Buffer, value string) {
	b.WriteByte(2<<5 | byte(len(value)))
	b.WriteString(value)
}

// writeMMDBUint writes an unsigned integer of the given MaxMind DB type
// (5 for uint16, 6 for uint32) in size bytes.
func writeMMDBUint(b *bytes.Buffer, dataType byte, size int, value uint32) {
	b.WriteByte(dataType<<5 | byte(size))
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	b.Write(encoded[4-size:])
}
