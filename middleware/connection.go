package middleware

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"
)

type connectionInfoContextKey struct{}

type ConnectionInfo struct {
	ID       string
	OpenedAt time.Time
	requests atomic.Uint64
	inFlight atomic.Int64
	peak     atomic.Int64
}

type ConnectionSnapshot struct {
	ID           string `json:"id"`
	AgeMS        int64  `json:"age_ms"`
	Requests     uint64 `json:"requests"`
	InFlight     int64  `json:"in_flight"`
	PeakInFlight int64  `json:"peak_in_flight"`
}

func ContextWithConnectionInfo(ctx context.Context) context.Context {
	info := &ConnectionInfo{
		ID:       "connection_" + strings.ToLower(ulid.Make().String()),
		OpenedAt: time.Now(),
	}

	return context.WithValue(ctx, connectionInfoContextKey{}, info)
}

func BeginConnectionRequest(r *http.Request) func() {
	info := connectionInfoForRequest(r)
	if info == nil {
		return func() {}
	}

	info.requests.Add(1)
	current := info.inFlight.Add(1)
	for {
		peak := info.peak.Load()
		if current <= peak || info.peak.CompareAndSwap(peak, current) {
			break
		}
	}

	return func() {
		info.inFlight.Add(-1)
	}
}

func GetConnectionID(r *http.Request) string {
	info := connectionInfoForRequest(r)
	if info == nil {
		return ""
	}

	return info.ID
}

func GetConnectionSnapshot(r *http.Request) *ConnectionSnapshot {
	info := connectionInfoForRequest(r)
	if info == nil {
		return nil
	}

	return &ConnectionSnapshot{
		ID:           info.ID,
		AgeMS:        time.Since(info.OpenedAt).Milliseconds(),
		Requests:     info.requests.Load(),
		InFlight:     info.inFlight.Load(),
		PeakInFlight: info.peak.Load(),
	}
}

func connectionInfoForRequest(r *http.Request) *ConnectionInfo {
	if r == nil {
		return nil
	}

	info, _ := r.Context().Value(connectionInfoContextKey{}).(*ConnectionInfo)

	return info
}
