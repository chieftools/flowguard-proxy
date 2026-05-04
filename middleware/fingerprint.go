package middleware

import (
	"context"
	"net/http"
)

const ContextKeyFingerprintJA4 contextKey = "fingerprint-ja4"

func ContextWithJA4Fingerprint(ctx context.Context, ja4 string) context.Context {
	if ja4 == "" {
		return ctx
	}
	return context.WithValue(ctx, ContextKeyFingerprintJA4, ja4)
}

func WithJA4Fingerprint(r *http.Request, ja4 string) *http.Request {
	if ja4 == "" {
		return r
	}
	return r.WithContext(ContextWithJA4Fingerprint(r.Context(), ja4))
}

func GetJA4Fingerprint(r *http.Request) string {
	if r == nil {
		return ""
	}
	if ja4, ok := r.Context().Value(ContextKeyFingerprintJA4).(string); ok {
		return ja4
	}
	return ""
}
