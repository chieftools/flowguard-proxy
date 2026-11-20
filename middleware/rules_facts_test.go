package middleware

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestRequestFactsDeriveEachValueOnce(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://Shop.Example.co.uk/a//b/../c?page=2&page=3", nil)
	req.Header.Set("Cookie", "session=abc; theme=dark")
	facts := newRequestFacts(req)

	if got := facts.host(); got != "shop.example.co.uk" {
		t.Fatalf("host = %q", got)
	}
	if got := facts.registerableDomain(); got != "example.co.uk" {
		t.Fatalf("registerable domain = %q", got)
	}
	if got := facts.normalizedPath(); got != "/a/c" {
		t.Fatalf("normalized path = %q", got)
	}
	if got := facts.query()["page"]; !slices.Equal(got, []string{"2", "3"}) {
		t.Fatalf("query page = %v", got)
	}
	if got := facts.cookieValues("session"); !slices.Equal(got, []string{"abc"}) {
		t.Fatalf("session cookie = %v", got)
	}

	// Later reads use the values derived the first time.
	req.Host = "other.test"
	req.URL.Path = "/other"
	req.URL.RawQuery = "page=9"
	req.Header.Set("Cookie", "session=changed")
	if facts.host() != "shop.example.co.uk" || facts.registerableDomain() != "example.co.uk" || facts.normalizedPath() != "/a/c" ||
		!slices.Equal(facts.query()["page"], []string{"2", "3"}) || !slices.Equal(facts.cookieValues("session"), []string{"abc"}) {
		t.Fatal("expected the request facts to be derived only once")
	}
}
