package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClassifyResponseResource(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		contentType   string
		fetchDest     string
		wantType      string
		wantStatic    bool
		wantSource    string
		wantMIME      string
		wantExtension string
	}{
		{
			name:          "stylesheet from content type",
			path:          "/static/app.CSS",
			contentType:   "text/css; charset=utf-8",
			wantType:      "stylesheet",
			wantStatic:    true,
			wantSource:    "content-type",
			wantMIME:      "text/css",
			wantExtension: "css",
		},
		{
			name:          "script from content type",
			path:          "/assets/app.js",
			contentType:   "text/javascript",
			wantType:      "script",
			wantStatic:    true,
			wantSource:    "content-type",
			wantMIME:      "text/javascript",
			wantExtension: "js",
		},
		{
			name:          "svg remains image despite xml suffix",
			path:          "/icons/logo.svg",
			contentType:   "image/svg+xml",
			wantType:      "image",
			wantStatic:    true,
			wantSource:    "content-type",
			wantMIME:      "image/svg+xml",
			wantExtension: "svg",
		},
		{
			name:          "font from content type",
			path:          "/fonts/inter.woff2",
			contentType:   "font/woff2",
			wantType:      "font",
			wantStatic:    true,
			wantSource:    "content-type",
			wantMIME:      "font/woff2",
			wantExtension: "woff2",
		},
		{
			name:          "media from content type",
			path:          "/video/intro.mp4",
			contentType:   "video/mp4",
			wantType:      "media",
			wantStatic:    true,
			wantSource:    "content-type",
			wantMIME:      "video/mp4",
			wantExtension: "mp4",
		},
		{
			name:          "html is not static candidate",
			path:          "/",
			contentType:   "text/html; charset=utf-8",
			wantType:      "html",
			wantStatic:    false,
			wantSource:    "content-type",
			wantMIME:      "text/html",
			wantExtension: "",
		},
		{
			name:          "problem json uses json bucket",
			path:          "/api/error",
			contentType:   "application/problem+json",
			wantType:      "json",
			wantStatic:    false,
			wantSource:    "content-type",
			wantMIME:      "application/problem+json",
			wantExtension: "",
		},
		{
			name:          "fetch destination fallback",
			path:          "/asset?id=style",
			fetchDest:     "style",
			wantType:      "stylesheet",
			wantStatic:    true,
			wantSource:    "sec-fetch-dest",
			wantMIME:      "",
			wantExtension: "",
		},
		{
			name:          "generic binary falls back to extension",
			path:          "/assets/app.mjs",
			contentType:   "application/octet-stream",
			wantType:      "script",
			wantStatic:    true,
			wantSource:    "path-extension",
			wantMIME:      "application/octet-stream",
			wantExtension: "mjs",
		},
		{
			name:          "extension fallback",
			path:          "/fonts/inter.woff2",
			wantType:      "font",
			wantStatic:    true,
			wantSource:    "path-extension",
			wantMIME:      "",
			wantExtension: "woff2",
		},
		{
			name:          "unknown extension",
			path:          "/download/file.custom",
			wantType:      "other",
			wantStatic:    false,
			wantSource:    "path-extension",
			wantMIME:      "",
			wantExtension: "custom",
		},
		{
			name:          "no metadata",
			path:          "/download",
			wantType:      "unknown",
			wantStatic:    false,
			wantSource:    "none",
			wantMIME:      "",
			wantExtension: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.fetchDest != "" {
				req.Header.Set("Sec-Fetch-Dest", tt.fetchDest)
			}

			headers := http.Header{}
			if tt.contentType != "" {
				headers.Set("Content-Type", tt.contentType)
			}

			got := classifyResponseResource(req, headers)
			if got.Type != tt.wantType {
				t.Fatalf("type = %q, want %q", got.Type, tt.wantType)
			}
			if got.StaticCandidate != tt.wantStatic {
				t.Fatalf("static candidate = %t, want %t", got.StaticCandidate, tt.wantStatic)
			}
			if got.Source != tt.wantSource {
				t.Fatalf("source = %q, want %q", got.Source, tt.wantSource)
			}
			if got.MIME != tt.wantMIME {
				t.Fatalf("mime = %q, want %q", got.MIME, tt.wantMIME)
			}
			if got.Extension != tt.wantExtension {
				t.Fatalf("extension = %q, want %q", got.Extension, tt.wantExtension)
			}
		})
	}
}

func TestGetResponseInfoIncludesResource(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
	wrapper := &ResponseWriterWrapper{
		Headers: http.Header{
			"Content-Type": []string{"text/css; charset=utf-8"},
		},
		StatusCode: http.StatusOK,
		BodySize:   12,
	}

	info := getResponseInfo(req, wrapper, nil)
	if info.Resource.Type != "stylesheet" {
		t.Fatalf("resource type = %q, want stylesheet", info.Resource.Type)
	}
	if !info.Resource.StaticCandidate {
		t.Fatal("resource should be marked as a static candidate")
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal response info: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal response info: %v", err)
	}
	if _, ok := decoded["resource"]; !ok {
		t.Fatal("expected response info JSON to include resource")
	}
}
