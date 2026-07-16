package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	upstreamRetryDelay      = 100 * time.Millisecond
	upstreamRetryJitter     = 50 * time.Millisecond
	upstreamRecoveryWait    = 5 * time.Second
	upstreamBreakerPoll     = 25 * time.Millisecond
	upstreamDialTimeout     = 30 * time.Second
	upstreamKeepAlive       = 30 * time.Second
	upstreamIdleConnTimeout = 90 * time.Second
	upstreamForceAttemptH2  = false
)

var errUpstreamCircuitOpen = errors.New("upstream temporarily unavailable")

type upstreamRetryTransport struct {
	next         http.RoundTripper
	breaker      *upstreamCircuitBreaker
	retryDelay   func() time.Duration
	recoveryWait time.Duration
	sleep        func(context.Context, time.Duration) error
	onRecovered  func(*http.Request, int, error)
}

func (t *upstreamRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.next == nil {
		t.next = http.DefaultTransport
	}

	deadline := time.Time{}
	if t.recoveryWait > 0 {
		deadline = t.now().Add(t.recoveryWait)
	}

	attempts := 0
	var lastErr error
	for {
		if err := t.waitForBreaker(req.Context(), deadline); err != nil {
			return nil, err
		}

		resp, err := t.next.RoundTrip(req)
		attempts++
		if err == nil {
			if t.breaker != nil {
				t.breaker.recordSuccess()
			}
			if lastErr != nil && t.onRecovered != nil {
				t.onRecovered(req, attempts-1, lastErr)
			}
			return resp, nil
		}

		lastErr = err
		retryable := isRetryableUpstreamError(err)
		if retryable && t.breaker != nil {
			t.breaker.recordFailure()
		}
		if !retryable {
			if t.breaker != nil {
				t.breaker.recordSuccess()
			}
			return nil, err
		}
		if !t.canRetryAfterFailure(req, err, deadline, attempts) {
			return nil, err
		}
		if err := prepareRequestForRetry(req); err != nil {
			return nil, err
		}

		delay := t.retryDelayForAttempt(attempts)
		if !deadline.IsZero() {
			remaining := deadline.Sub(t.now())
			if remaining <= 0 {
				return nil, lastErr
			}
			if delay > remaining {
				delay = remaining
			}
		}
		if err := t.sleepFor(req.Context(), delay); err != nil {
			return nil, err
		}
	}
}

func (t *upstreamRetryTransport) waitForBreaker(ctx context.Context, deadline time.Time) error {
	if t.breaker == nil {
		return nil
	}

	err := t.breaker.beforeRequest()
	if err == nil || !errors.Is(err, errUpstreamCircuitOpen) || deadline.IsZero() {
		return err
	}

	for errors.Is(err, errUpstreamCircuitOpen) {
		remaining := deadline.Sub(t.now())
		if remaining <= 0 {
			return err
		}

		delay := t.breaker.retryAfter()
		if delay <= 0 {
			delay = upstreamBreakerPoll
		}
		if delay > remaining {
			delay = remaining
		}

		if sleepErr := t.sleepFor(ctx, delay); sleepErr != nil {
			return sleepErr
		}

		err = t.breaker.beforeRequest()
	}

	return err
}

func (t *upstreamRetryTransport) canRetryAfterFailure(req *http.Request, err error, deadline time.Time, attempts int) bool {
	if !canRetryUpstreamRequest(req) && !canRetryUnsentRequestAfterDialFailure(req, err) {
		return false
	}
	if deadline.IsZero() {
		return attempts == 1
	}
	return t.now().Before(deadline)
}

func canRetryUnsentRequestAfterDialFailure(req *http.Request, err error) bool {
	return isDefiniteUpstreamDialFailure(err) && hasReplayableRequestBody(req)
}

func hasReplayableRequestBody(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

func prepareRequestForRetry(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if req.GetBody == nil {
		return nil
	}

	body, err := req.GetBody()
	if err != nil {
		return err
	}
	req.Body = body
	return nil
}

func (t *upstreamRetryTransport) retryDelayForAttempt(attempts int) time.Duration {
	if t.retryDelay != nil {
		return t.retryDelay()
	}

	delay := upstreamRetryDelay
	for i := 1; i < attempts && delay < time.Second; i++ {
		delay *= 2
	}
	if delay > time.Second {
		delay = time.Second
	}
	return delay + upstreamRetryJitterDuration()
}

func (t *upstreamRetryTransport) sleepFor(ctx context.Context, delay time.Duration) error {
	if t.sleep != nil {
		return t.sleep(ctx, delay)
	}
	return sleepContext(ctx, delay)
}

func (t *upstreamRetryTransport) now() time.Time {
	if t.breaker != nil {
		return t.breaker.now()
	}
	return time.Now()
}

type upstreamCircuitBreaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	now       func() time.Time

	failures  int
	openUntil time.Time
	probing   bool
}

func newUpstreamCircuitBreaker(threshold int, cooldown time.Duration) *upstreamCircuitBreaker {
	return &upstreamCircuitBreaker{
		threshold: threshold,
		cooldown:  cooldown,
		now:       time.Now,
	}
}

func (b *upstreamCircuitBreaker) beforeRequest() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if now.Before(b.openUntil) {
		return errUpstreamCircuitOpen
	}
	if !b.openUntil.IsZero() {
		if b.probing {
			return errUpstreamCircuitOpen
		}
		b.probing = true
	}
	return nil
}

func (b *upstreamCircuitBreaker) retryAfter() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if now.Before(b.openUntil) {
		return b.openUntil.Sub(now)
	}
	if b.probing {
		return upstreamBreakerPoll
	}
	return 0
}

func (b *upstreamCircuitBreaker) recordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures = 0
	b.openUntil = time.Time{}
	b.probing = false
}

func (b *upstreamCircuitBreaker) recordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures++
	if b.probing || b.failures >= b.threshold {
		b.failures = b.threshold
		b.openUntil = b.now().Add(b.cooldown)
		b.probing = false
	}
}

type proxyErrorLogLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	entries map[string]*proxyErrorLogEntry
}

type proxyErrorLogEntry struct {
	suppressed int
}

func newProxyErrorLogLimiter(window time.Duration) *proxyErrorLogLimiter {
	return &proxyErrorLogLimiter{
		window:  window,
		entries: make(map[string]*proxyErrorLogEntry),
	}
}

func (l *proxyErrorLogLimiter) log(bindAddr, bindPort, host string, err error) {
	if l == nil || l.window <= 0 || !isTransientProxyError(err) {
		logProxyErrorNow(bindAddr, bindPort, host, err)
		return
	}

	key := bindAddr + "|" + bindPort + "|" + host + "|" + transientProxyErrorKey(err)

	l.mu.Lock()
	if entry, ok := l.entries[key]; ok {
		entry.suppressed++
		l.mu.Unlock()
		return
	}
	l.entries[key] = &proxyErrorLogEntry{}
	l.mu.Unlock()

	logProxyErrorNow(bindAddr, bindPort, host, err)

	time.AfterFunc(l.window, func() {
		l.flush(key, bindAddr, bindPort, host, err)
	})
}

func (l *proxyErrorLogLimiter) logRecovery(bindAddr, bindPort, host string, failures int, err error) {
	if l == nil || l.window <= 0 {
		logUpstreamRecoveryNow(bindAddr, bindPort, host, failures, err)
		return
	}

	key := bindAddr + "|" + bindPort + "|" + host + "|recovered|" + transientProxyErrorKey(err)

	l.mu.Lock()
	if entry, ok := l.entries[key]; ok {
		entry.suppressed++
		l.mu.Unlock()
		return
	}
	l.entries[key] = &proxyErrorLogEntry{}
	l.mu.Unlock()

	logUpstreamRecoveryNow(bindAddr, bindPort, host, failures, err)

	time.AfterFunc(l.window, func() {
		l.flushRecovery(key, bindAddr, bindPort, host, err)
	})
}

func (l *proxyErrorLogLimiter) flush(key, bindAddr, bindPort, host string, err error) {
	l.mu.Lock()
	entry, ok := l.entries[key]
	if ok {
		delete(l.entries, key)
	}
	l.mu.Unlock()

	if !ok || entry.suppressed == 0 {
		return
	}

	log.Printf("[%s:%s] proxy error for %s: suppressed %d similar transient errors: %v",
		bindAddr, bindPort, host, entry.suppressed, err)
}

func (l *proxyErrorLogLimiter) flushRecovery(key, bindAddr, bindPort, host string, err error) {
	l.mu.Lock()
	entry, ok := l.entries[key]
	if ok {
		delete(l.entries, key)
	}
	l.mu.Unlock()

	if !ok || entry.suppressed == 0 {
		return
	}

	log.Printf("[%s:%s] upstream recovered for %s: suppressed %d similar transient recovery logs: %v",
		bindAddr, bindPort, host, entry.suppressed, err)
}

func (s *Server) ensureUpstreamTransport() http.RoundTripper {
	if s.upstreamTransport == nil {
		if s.upstreamBreaker == nil {
			s.upstreamBreaker = newUpstreamCircuitBreaker(3, time.Second)
		}
		s.upstreamTransport = s.newUpstreamTransport()
	}
	return s.upstreamTransport
}

func (s *Server) newUpstreamTransport() http.RoundTripper {
	dialer := &net.Dialer{
		Timeout:   upstreamDialTimeout,
		KeepAlive: upstreamKeepAlive,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, s.upstreamAddress())
		},
		ForceAttemptHTTP2:     upstreamForceAttemptH2,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       upstreamIdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}

	if s.config.scheme == "https" {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	return &upstreamRetryTransport{
		next:         transport,
		breaker:      s.upstreamBreaker,
		recoveryWait: upstreamRecoveryWait,
		onRecovered:  s.logUpstreamRecovery,
	}
}

func (s *Server) upstreamAddress() string {
	host := s.config.bindAddr
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	return net.JoinHostPort(host, s.upstreamPort())
}

func (s *Server) upstreamPort() string {
	if s.config.scheme == "https" {
		return "443"
	}
	return "80"
}

func (s *Server) closeUpstreamIdleConnections() {
	if transport, ok := s.upstreamTransport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
	if retryTransport, ok := s.upstreamTransport.(*upstreamRetryTransport); ok {
		if transport, ok := retryTransport.next.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	}
}

func (s *Server) logProxyError(host string, err error) {
	if s.proxyErrorLogLimiter == nil {
		logProxyErrorNow(s.config.bindAddr, s.config.bindPort, host, err)
		return
	}
	s.proxyErrorLogLimiter.log(s.config.bindAddr, s.config.bindPort, host, err)
}

func (s *Server) logUpstreamRecovery(req *http.Request, failures int, err error) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		host = "unknown"
	}

	if s.config.verbose || s.proxyErrorLogLimiter == nil {
		logUpstreamRecoveryNow(s.config.bindAddr, s.config.bindPort, host, failures, err)
		return
	}
	s.proxyErrorLogLimiter.logRecovery(s.config.bindAddr, s.config.bindPort, host, failures, err)
}

func logProxyErrorNow(bindAddr, bindPort, host string, err error) {
	log.Printf("[%s:%s] proxy error for %s: %v", bindAddr, bindPort, host, err)
}

func logUpstreamRecoveryNow(bindAddr, bindPort, host string, failures int, err error) {
	log.Printf("[%s:%s] upstream recovered for %s after %d transient failure(s): %v",
		bindAddr, bindPort, host, failures, err)
}

func canRetryUpstreamRequest(req *http.Request) bool {
	if req.Body != nil && req.Body != http.NoBody {
		return false
	}

	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func isTransientProxyError(err error) bool {
	return errors.Is(err, errUpstreamCircuitOpen) || isRetryableUpstreamError(err)
}

func isClientAbortedProxyError(req *http.Request, err error) bool {
	if err == nil {
		return false
	}
	if req != nil && errors.Is(req.Context().Err(), context.Canceled) {
		return true
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "h3_request_cancelled") ||
		strings.Contains(msg, "client disconnected")
}

func isDefiniteUpstreamDialFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connect: connection refused") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "no route to host")
}

func isRetryableUpstreamError(err error) bool {
	if err == nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, errUpstreamCircuitOpen) {
		return false
	}

	if errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "server sent goaway") ||
		strings.Contains(msg, "received goaway")
}

func transientProxyErrorKey(err error) string {
	switch {
	case errors.Is(err, errUpstreamCircuitOpen):
		return "circuit-open"
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "connection refused"):
		return "connection-refused"
	case errors.Is(err, syscall.ECONNRESET) || strings.Contains(strings.ToLower(err.Error()), "connection reset by peer"):
		return "connection-reset"
	case errors.Is(err, syscall.EPIPE) || strings.Contains(strings.ToLower(err.Error()), "broken pipe"):
		return "broken-pipe"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case strings.Contains(strings.ToLower(err.Error()), "goaway"):
		return "goaway"
	default:
		return "transient"
	}
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func upstreamRetryJitterDuration() time.Duration {
	jitter := time.Duration(time.Now().UnixNano() % int64(upstreamRetryJitter))
	return jitter
}
