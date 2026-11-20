package fingerprint

import (
	"crypto/tls"
	"fmt"
	"testing"
	"time"
)

func TestJA4FromClientHello(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x0a0a, tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Extensions:        []uint16{0x0a0a, 0x0000, 0x0010, 0x000d, 0x002b},
		SupportedVersions: []uint16{0x0a0a, tls.VersionTLS12, tls.VersionTLS13},
		ServerName:        "example.com",
		SupportedProtos:   []string{"h2"},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
	}

	got := JA4FromClientHello(hello, "t")
	want := "t13d0304h2_40b44b994229_ef5f37ab036a"
	if got != want {
		t.Fatalf("unexpected JA4: got %q, want %q", got, want)
	}
}

func TestJA4FromClientHelloQUICNoSNI(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		Extensions:        []uint16{0x002b},
		SupportedVersions: []uint16{tls.VersionTLS13},
		SupportedProtos:   []string{"h3"},
	}

	got := JA4FromClientHello(hello, "q")
	want := "q13i0101h3_0f2cb44170f4_b9a491fefe05"
	if got != want {
		t.Fatalf("unexpected JA4: got %q, want %q", got, want)
	}
}

func TestJA4FromClientHelloEmptyLists(t *testing.T) {
	hello := &tls.ClientHelloInfo{}

	got := JA4FromClientHello(hello, "t")
	want := "t00i000000_000000000000_000000000000"
	if got != want {
		t.Fatalf("unexpected JA4: got %q, want %q", got, want)
	}
}

func TestStoreTakeReturnsTheFingerprintOnce(t *testing.T) {
	store := NewStore()
	store.Set("127.0.0.1:443", "192.0.2.1:51515", "ja4")

	if got := store.Take("127.0.0.1:443", "192.0.2.1:51515"); got != "ja4" {
		t.Fatalf("unexpected stored value: %q", got)
	}
	if got := store.Take("127.0.0.1:443", "192.0.2.1:51515"); got != "" {
		t.Fatalf("expected the value to be taken, got %q", got)
	}
}

func TestStoreReplacesAnEntryWhenFull(t *testing.T) {
	store := NewStore()
	for i := range storeMaxEntries {
		store.Set("127.0.0.1:443", fmt.Sprintf("192.0.2.1:%d", i), "flood")
	}

	store.Set("127.0.0.1:443", "198.51.100.1:443", "ja4")
	if len(store.entries) != storeMaxEntries {
		t.Fatalf("store holds %d entries, want %d", len(store.entries), storeMaxEntries)
	}
	if got := store.Take("127.0.0.1:443", "198.51.100.1:443"); got != "ja4" {
		t.Fatal("expected a new fingerprint to replace an entry while the store is full")
	}

	// Expired entries are cleaned up first.
	for k, entry := range store.entries {
		entry.expiresAt = time.Now().Add(-time.Second)
		store.entries[k] = entry
	}
	store.lastCleanup = time.Time{}
	store.Set("127.0.0.1:443", "198.51.100.2:443", "ja4")
	if len(store.entries) != 1 {
		t.Fatalf("store holds %d entries, want only the new one after expired entries were cleaned up", len(store.entries))
	}
}
