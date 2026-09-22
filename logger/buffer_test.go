package logger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundedLogBufferKeepsNewestEntries(t *testing.T) {
	diagnostics := newSinkDiagnostics()
	buffer := newBoundedLogBuffer(3, 1<<20, diagnostics)
	entries := []*LogEntry{
		testLogEntry("first"),
		testLogEntry("second"),
		testLogEntry("third"),
		testLogEntry("fourth"),
	}

	for _, entry := range entries {
		if err := buffer.enqueue(entry); err != nil {
			t.Fatalf("enqueue failed: %v", err)
		}
	}

	var retained []bufferedLogEntry
	for range 3 {
		entry, ok, batchFull := buffer.dequeue(1<<20, true)
		if !ok || batchFull {
			t.Fatal("expected retained entry")
		}
		retained = append(retained, entry)
	}
	for index, expected := range entries[1:] {
		if retained[index].entry != expected {
			t.Fatalf("entry %d was not retained in order", index)
		}
	}
	buffer.release(retained)

	queued, total, bytes, _ := buffer.stats()
	if queued != 0 || total != 0 || bytes != 0 {
		t.Fatalf("buffer was not fully released: queued=%d total=%d bytes=%d", queued, total, bytes)
	}
	snapshot := diagnostics.snapshotAndReset()
	if snapshot.evicted != 1 {
		t.Fatalf("expected one eviction, got %d", snapshot.evicted)
	}
}

func TestBoundedLogBufferEnforcesByteLimit(t *testing.T) {
	first := testLogEntry("alpha")
	second := testLogEntry("bravo")
	firstSize, err := first.prepare()
	if err != nil {
		t.Fatal(err)
	}
	secondSize, err := second.prepare()
	if err != nil {
		t.Fatal(err)
	}
	budget := max(firstSize, secondSize)
	diagnostics := newSinkDiagnostics()
	buffer := newBoundedLogBuffer(10, budget, diagnostics)

	if err := buffer.enqueue(first); err != nil {
		t.Fatal(err)
	}
	if err := buffer.enqueue(second); err != nil {
		t.Fatal(err)
	}

	entry, ok, _ := buffer.dequeue(budget, true)
	if !ok || entry.entry != second {
		t.Fatal("expected the newest entry to replace the oldest entry")
	}
	buffer.release([]bufferedLogEntry{entry})
	if snapshot := diagnostics.snapshotAndReset(); snapshot.evicted != 1 {
		t.Fatalf("expected one byte-budget eviction, got %d", snapshot.evicted)
	}
}

func TestBoundedLogBufferCountsInFlightEntries(t *testing.T) {
	diagnostics := newSinkDiagnostics()
	buffer := newBoundedLogBuffer(1, 1<<20, diagnostics)
	first := testLogEntry("active")
	second := testLogEntry("waiting")

	if err := buffer.enqueue(first); err != nil {
		t.Fatal(err)
	}
	inFlight, ok, _ := buffer.dequeue(1<<20, true)
	if !ok {
		t.Fatal("expected an in-flight entry")
	}
	if err := buffer.enqueue(second); err != nil {
		t.Fatal(err)
	}

	queued, retained, _, _ := buffer.stats()
	if queued != 0 || retained != 1 {
		t.Fatalf("unexpected buffer state: queued=%d retained=%d", queued, retained)
	}
	if snapshot := diagnostics.snapshotAndReset(); snapshot.inFlightLimited != 1 {
		t.Fatalf("expected one in-flight-limit drop, got %d", snapshot.inFlightLimited)
	}
	buffer.release([]bufferedLogEntry{inFlight})
}

func TestBoundedLogBufferDropsEntryLargerThanBudget(t *testing.T) {
	entry := testLogEntry("payload-that-does-not-fit")
	size, err := entry.prepare()
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := newSinkDiagnostics()
	buffer := newBoundedLogBuffer(10, size-1, diagnostics)

	if err := buffer.enqueue(entry); err != nil {
		t.Fatal(err)
	}
	queued, retained, _, _ := buffer.stats()
	if queued != 0 || retained != 0 {
		t.Fatalf("oversized entry was retained: queued=%d retained=%d", queued, retained)
	}
	if snapshot := diagnostics.snapshotAndReset(); snapshot.oversized != 1 {
		t.Fatalf("expected one oversized drop, got %d", snapshot.oversized)
	}
}

func TestAsyncBatchWriterDoesNotBlockWhenDeliveryStalls(t *testing.T) {
	started := make(chan struct{})
	var startOnce sync.Once
	sender := func(ctx context.Context, _ []*LogEntry) error {
		startOnce.Do(func() { close(started) })
		<-ctx.Done()
		return ctx.Err()
	}
	options := defaultAsyncBatchWriterOptions()
	options.maxEntries = 8
	options.maxBytes = 1 << 20
	options.maxBatchEntries = 1
	options.batchTimeout = time.Millisecond
	options.initialRetryDelay = time.Millisecond
	options.maxRetryDelay = time.Millisecond
	options.shutdownTimeout = 10 * time.Millisecond
	writer := newAsyncBatchWriterWithOptions("synthetic", "blocked", sender, options)
	writer.diagnostics.logf = func(string, ...interface{}) {}

	if err := writer.Write(testLogEntry("initial")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sender did not start")
	}

	done := make(chan error, 1)
	go func() {
		for index := range 100_000 {
			if err := writer.Write(testLogEntry(fmt.Sprintf("event-%d", index))); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writes blocked behind the stalled sender")
	}

	writer.Close()
	queued, retained, bytes, closed := writer.buffer.stats()
	if !closed || queued != 0 || retained != 0 || bytes != 0 {
		t.Fatalf("writer did not release its buffer: closed=%v queued=%d retained=%d bytes=%d", closed, queued, retained, bytes)
	}
}

func TestAsyncBatchWriterBoundsLargeEntries(t *testing.T) {
	started := make(chan struct{})
	var startOnce sync.Once
	sender := func(ctx context.Context, _ []*LogEntry) error {
		startOnce.Do(func() { close(started) })
		<-ctx.Done()
		return ctx.Err()
	}
	options := defaultAsyncBatchWriterOptions()
	options.maxEntries = 10_000
	options.maxBytes = 256 << 10
	options.maxBatchEntries = 1
	options.batchTimeout = time.Millisecond
	options.initialRetryDelay = time.Millisecond
	options.maxRetryDelay = time.Millisecond
	options.shutdownTimeout = 10 * time.Millisecond
	writer := newAsyncBatchWriterWithOptions("synthetic", "large", sender, options)
	writer.diagnostics.logf = func(string, ...interface{}) {}

	payload := strings.Repeat("x", 64<<10)
	if err := writer.Write(testLogEntry(payload)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sender did not start")
	}
	for range 1_000 {
		if err := writer.Write(testLogEntry(payload)); err != nil {
			t.Fatal(err)
		}
	}

	_, retained, retainedBytes, _ := writer.buffer.stats()
	if retained > options.maxEntries {
		t.Fatalf("entry bound exceeded: %d", retained)
	}
	if retainedBytes > options.maxBytes {
		t.Fatalf("byte bound exceeded: %d", retainedBytes)
	}
	writer.Close()
}

func TestSinkDiagnosticsCoalesceEvents(t *testing.T) {
	diagnostics := newSinkDiagnostics()
	var reports atomic.Int64
	diagnostics.logf = func(string, ...interface{}) {
		reports.Add(1)
	}
	for range 1_000 {
		diagnostics.recordEviction()
		diagnostics.recordError(errors.New("synthetic delivery failure"))
	}

	diagnostics.report("synthetic", "buffer")
	diagnostics.report("synthetic", "buffer")
	if reports.Load() != 1 {
		t.Fatalf("expected one aggregated report, got %d", reports.Load())
	}
}

func TestManagerAggregatesSinkErrorsOffRequestPath(t *testing.T) {
	manager := NewManager("FlowGuard/test")
	manager.diagnostics.logf = func(string, ...interface{}) {}
	manager.sinks["failing"] = errorSink{name: "failing"}
	manager.sinkConfigs["failing"] = "synthetic"

	for index := range 1_000 {
		manager.Write(testLogEntry(fmt.Sprintf("request-%d", index)))
	}

	snapshot := manager.diagnostics.snapshotAndReset()
	if snapshot.errors != 1_000 {
		t.Fatalf("expected 1,000 aggregated errors, got %d", snapshot.errors)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileSinkCloseDrainsAcceptedEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.log")
	sink, err := NewFileSink("local", map[string]interface{}{
		"type": "file",
		"path": path,
	}, "FlowGuard/test")
	if err != nil {
		t.Fatal(err)
	}

	for index := range 100 {
		if err := sink.Write(testLogEntry(fmt.Sprintf("file-event-%d", index))); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if len(lines) != 100 {
		t.Fatalf("expected 100 drained entries, got %d", len(lines))
	}
}

func TestLogEntryPreparationReleasesStructuredData(t *testing.T) {
	entry := testLogEntry("prepared")
	size, err := entry.prepare()
	if err != nil {
		t.Fatal(err)
	}
	if size == 0 {
		t.Fatal("expected encoded data")
	}
	if entry.Data != nil {
		t.Fatal("expected structured data to be released")
	}
	encoded, err := entry.jsonBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"message":"prepared"}` {
		t.Fatalf("unexpected encoded entry: %s", encoded)
	}
}

func testLogEntry(message string) *LogEntry {
	return &LogEntry{Data: map[string]interface{}{"message": message}}
}

type errorSink struct {
	name string
}

func (s errorSink) Write(*LogEntry) error {
	return errors.New("synthetic sink failure")
}

func (s errorSink) Close() error {
	return nil
}

func (s errorSink) Name() string {
	return s.name
}

func (errorSink) ConfigHash() string {
	return "synthetic"
}
