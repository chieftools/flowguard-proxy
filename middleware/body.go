package middleware

import (
	"context"
	"io"
	"net/http"
	"strings"
)

// maxBodyInspectionBytes is how much of a request body the body matchers see.
// Cloudflare inspects 128 KB on Enterprise plans; twice that still covers
// every form or API body short of a file upload, while bounding the memory a
// flood of large uploads can pin to 256 KiB per in-flight request. Larger
// bodies are marked truncated, so rules can still act on what was not seen.
const maxBodyInspectionBytes = 256 << 10

const contextKeyBodyInspection contextKey = "bodyInspection"

// bodyInspection is the start of a request body, read once per request when a
// rule first needs it.
type bodyInspection struct {
	body      string
	truncated bool
}

// inspectBody reads up to maxBodyInspectionBytes of the request body and puts
// the bytes it read back in front of the rest, so the upstream receives the
// body unchanged. Requests that did not reach a body matcher are never read.
func inspectBody(r *http.Request) *bodyInspection {
	if inspection, ok := r.Context().Value(contextKeyBodyInspection).(*bodyInspection); ok {
		return inspection
	}

	inspection := &bodyInspection{}
	// A CONNECT body is a tunnel that may only send data after a response,
	// so reading it before forwarding would stall the request.
	if r.Body != nil && r.Body != http.NoBody && r.Method != http.MethodConnect {
		inspection.body, inspection.truncated = replayBodyPrefix(r)
	}

	ctx := context.WithValue(r.Context(), contextKeyBodyInspection, inspection)
	*r = *r.WithContext(ctx)
	return inspection
}

func replayBodyPrefix(r *http.Request) (string, bool) {
	original := r.Body
	read, err := readBodyPrefix(original, r.ContentLength, maxBodyInspectionBytes+1)

	// One copy serves both matching and the replay
	prefix := string(read)

	var rest io.Reader = original
	if err != nil {
		// Hand the read error to the upstream after the bytes that did arrive,
		// as it would have seen it without the inspection.
		rest = errorReader{err: err}
	}
	r.Body = replayedBody{
		Reader: io.MultiReader(strings.NewReader(prefix), rest),
		Closer: original,
	}

	if len(prefix) > maxBodyInspectionBytes {
		return prefix[:maxBodyInspectionBytes], true
	}
	return prefix, false
}

// readBodyPrefix reads at most limit bytes, like io.ReadAll on an
// io.LimitReader, but sized up front from the Content-Length when known and
// never grown past the limit.
func readBodyPrefix(body io.Reader, contentLength int64, limit int64) ([]byte, error) {
	capacity := int64(512)
	if contentLength >= 0 {
		// One spare byte lets the read that returns io.EOF finish without
		// growing the buffer
		capacity = contentLength + 1
	}

	buf := make([]byte, 0, min(capacity, limit))
	for int64(len(buf)) < limit {
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), min(2*int64(cap(buf)), limit))
			copy(grown, buf)
			buf = grown
		}
		n, err := body.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return buf, err
		}
	}
	return buf, nil
}

type replayedBody struct {
	io.Reader
	io.Closer
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
