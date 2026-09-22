package logger

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	defaultSinkMaxEntries          = 10_000
	defaultSinkMaxBytes      int64 = 128 << 20
	defaultBatchMaxEntries         = 100
	defaultBatchMaxBytes     int64 = 8 << 20
	defaultBatchTimeout            = 5 * time.Second
	defaultReportInterval          = 30 * time.Second
	defaultShutdownTimeout         = 10 * time.Second
	defaultInitialRetryDelay       = time.Second
	defaultMaxRetryDelay           = 5 * time.Minute
)

var errSinkClosed = errors.New("log sink is closed")

type bufferedLogEntry struct {
	entry *LogEntry
	size  int64
}

type sinkDiagnosticSnapshot struct {
	evicted         uint64
	oversized       uint64
	inFlightLimited uint64
	deliveryDropped uint64
	shutdownDropped uint64
	errors          uint64
	recoveries      uint64
	lastError       string
}

func (s sinkDiagnosticSnapshot) empty() bool {
	return s.evicted == 0 && s.oversized == 0 && s.inFlightLimited == 0 &&
		s.deliveryDropped == 0 && s.shutdownDropped == 0 && s.errors == 0 && s.recoveries == 0
}

type sinkDiagnostics struct {
	mu              sync.Mutex
	evicted         uint64
	oversized       uint64
	inFlightLimited uint64
	deliveryDropped uint64
	shutdownDropped uint64
	errors          uint64
	recoveries      uint64
	lastError       string
	logf            func(string, ...interface{})
}

func newSinkDiagnostics() *sinkDiagnostics {
	return &sinkDiagnostics{logf: log.Printf}
}

func (d *sinkDiagnostics) recordEviction() {
	d.mu.Lock()
	d.evicted++
	d.mu.Unlock()
}

func (d *sinkDiagnostics) recordOversized() {
	d.mu.Lock()
	d.oversized++
	d.mu.Unlock()
}

func (d *sinkDiagnostics) recordInFlightLimit() {
	d.mu.Lock()
	d.inFlightLimited++
	d.mu.Unlock()
}

func (d *sinkDiagnostics) recordShutdownDrop(count uint64) {
	if count == 0 {
		return
	}
	d.mu.Lock()
	d.shutdownDropped += count
	d.mu.Unlock()
}

func (d *sinkDiagnostics) recordDeliveryDrop(count uint64) {
	if count == 0 {
		return
	}
	d.mu.Lock()
	d.deliveryDropped += count
	d.mu.Unlock()
}

func (d *sinkDiagnostics) recordError(err error) {
	if err == nil {
		return
	}
	d.mu.Lock()
	d.errors++
	d.lastError = err.Error()
	d.mu.Unlock()
}

func (d *sinkDiagnostics) recordRecovery() {
	d.mu.Lock()
	d.recoveries++
	d.mu.Unlock()
}

func (d *sinkDiagnostics) snapshotAndReset() sinkDiagnosticSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()

	snapshot := sinkDiagnosticSnapshot{
		evicted:         d.evicted,
		oversized:       d.oversized,
		inFlightLimited: d.inFlightLimited,
		deliveryDropped: d.deliveryDropped,
		shutdownDropped: d.shutdownDropped,
		errors:          d.errors,
		recoveries:      d.recoveries,
		lastError:       d.lastError,
	}
	d.evicted = 0
	d.oversized = 0
	d.inFlightLimited = 0
	d.deliveryDropped = 0
	d.shutdownDropped = 0
	d.errors = 0
	d.recoveries = 0
	d.lastError = ""

	return snapshot
}

func (d *sinkDiagnostics) report(kind, name string) {
	snapshot := d.snapshotAndReset()
	if snapshot.empty() {
		return
	}

	d.logf("[logger:%s] Sink %s activity: evicted=%d oversized=%d in_flight_limited=%d delivery_dropped=%d shutdown_dropped=%d errors=%d recoveries=%d last_error=%q",
		kind,
		name,
		snapshot.evicted,
		snapshot.oversized,
		snapshot.inFlightLimited,
		snapshot.deliveryDropped,
		snapshot.shutdownDropped,
		snapshot.errors,
		snapshot.recoveries,
		snapshot.lastError,
	)
}

type boundedLogBuffer struct {
	mu              sync.Mutex
	entries         []bufferedLogEntry
	head            int
	length          int
	retainedEntries int
	retainedBytes   int64
	maxEntries      int
	maxBytes        int64
	ready           chan struct{}
	closed          bool
	diagnostics     *sinkDiagnostics
}

func newBoundedLogBuffer(maxEntries int, maxBytes int64, diagnostics *sinkDiagnostics) *boundedLogBuffer {
	if maxEntries <= 0 {
		maxEntries = defaultSinkMaxEntries
	}
	if maxBytes <= 0 {
		maxBytes = defaultSinkMaxBytes
	}
	if diagnostics == nil {
		diagnostics = newSinkDiagnostics()
	}

	return &boundedLogBuffer{
		entries:     make([]bufferedLogEntry, maxEntries),
		maxEntries:  maxEntries,
		maxBytes:    maxBytes,
		ready:       make(chan struct{}, 1),
		diagnostics: diagnostics,
	}
}

func (b *boundedLogBuffer) enqueue(entry *LogEntry) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errSinkClosed
	}
	b.mu.Unlock()

	size, err := entry.prepare()
	if err != nil {
		return err
	}
	if size > b.maxBytes {
		b.diagnostics.recordOversized()
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errSinkClosed
	}

	for b.retainedEntries+1 > b.maxEntries || b.retainedBytes+size > b.maxBytes {
		if b.length == 0 {
			b.diagnostics.recordInFlightLimit()
			return nil
		}
		b.evictOldestLocked()
		b.diagnostics.recordEviction()
	}

	tail := (b.head + b.length) % len(b.entries)
	b.entries[tail] = bufferedLogEntry{entry: entry, size: size}
	b.length++
	b.retainedEntries++
	b.retainedBytes += size
	b.signalLocked()

	return nil
}

func (b *boundedLogBuffer) evictOldestLocked() {
	entry := b.entries[b.head]
	b.entries[b.head] = bufferedLogEntry{}
	b.head = (b.head + 1) % len(b.entries)
	b.length--
	b.retainedEntries--
	b.retainedBytes -= entry.size
}

func (b *boundedLogBuffer) dequeue(maxBytes int64, allowOversized bool) (bufferedLogEntry, bool, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.length == 0 {
		return bufferedLogEntry{}, false, false
	}

	entry := b.entries[b.head]
	if !allowOversized && entry.size > maxBytes {
		return bufferedLogEntry{}, false, true
	}

	b.entries[b.head] = bufferedLogEntry{}
	b.head = (b.head + 1) % len(b.entries)
	b.length--
	if b.length > 0 {
		b.signalLocked()
	}

	return entry, true, false
}

func (b *boundedLogBuffer) release(entries []bufferedLogEntry) {
	if len(entries) == 0 {
		return
	}

	var releasedBytes int64
	for _, entry := range entries {
		releasedBytes += entry.size
	}

	b.mu.Lock()
	b.retainedEntries -= len(entries)
	b.retainedBytes -= releasedBytes
	b.mu.Unlock()
}

func (b *boundedLogBuffer) discardQueued() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	count := b.length
	for b.length > 0 {
		b.evictOldestLocked()
	}
	b.diagnostics.recordShutdownDrop(uint64(count))

	return count
}

func (b *boundedLogBuffer) close() {
	b.mu.Lock()
	b.closed = true
	b.signalLocked()
	b.mu.Unlock()
}

func (b *boundedLogBuffer) signalLocked() {
	select {
	case b.ready <- struct{}{}:
	default:
	}
}

func (b *boundedLogBuffer) stats() (queued, retained int, retainedBytes int64, closed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.length, b.retainedEntries, b.retainedBytes, b.closed
}

type asyncBatchWriterOptions struct {
	maxEntries        int
	maxBytes          int64
	maxBatchEntries   int
	maxBatchBytes     int64
	batchTimeout      time.Duration
	reportInterval    time.Duration
	shutdownTimeout   time.Duration
	initialRetryDelay time.Duration
	maxRetryDelay     time.Duration
}

func defaultAsyncBatchWriterOptions() asyncBatchWriterOptions {
	return asyncBatchWriterOptions{
		maxEntries:        defaultSinkMaxEntries,
		maxBytes:          defaultSinkMaxBytes,
		maxBatchEntries:   defaultBatchMaxEntries,
		maxBatchBytes:     defaultBatchMaxBytes,
		batchTimeout:      defaultBatchTimeout,
		reportInterval:    defaultReportInterval,
		shutdownTimeout:   defaultShutdownTimeout,
		initialRetryDelay: defaultInitialRetryDelay,
		maxRetryDelay:     defaultMaxRetryDelay,
	}
}

type asyncBatchWriter struct {
	kind        string
	name        string
	buffer      *boundedLogBuffer
	diagnostics *sinkDiagnostics
	send        func(context.Context, []*LogEntry) error
	options     asyncBatchWriterOptions
	ctx         context.Context
	cancel      context.CancelFunc
	closeOnce   sync.Once
	wg          sync.WaitGroup
}

func newAsyncBatchWriter(kind, name string, send func(context.Context, []*LogEntry) error) *asyncBatchWriter {
	return newAsyncBatchWriterWithOptions(kind, name, send, defaultAsyncBatchWriterOptions())
}

func newAsyncBatchWriterWithOptions(kind, name string, send func(context.Context, []*LogEntry) error, options asyncBatchWriterOptions) *asyncBatchWriter {
	defaults := defaultAsyncBatchWriterOptions()
	if options.maxEntries <= 0 {
		options.maxEntries = defaults.maxEntries
	}
	if options.maxBytes <= 0 {
		options.maxBytes = defaults.maxBytes
	}
	if options.maxBatchEntries <= 0 {
		options.maxBatchEntries = defaults.maxBatchEntries
	}
	if options.maxBatchBytes <= 0 {
		options.maxBatchBytes = defaults.maxBatchBytes
	}
	if options.batchTimeout <= 0 {
		options.batchTimeout = defaults.batchTimeout
	}
	if options.reportInterval <= 0 {
		options.reportInterval = defaults.reportInterval
	}
	if options.shutdownTimeout <= 0 {
		options.shutdownTimeout = defaults.shutdownTimeout
	}
	if options.initialRetryDelay <= 0 {
		options.initialRetryDelay = defaults.initialRetryDelay
	}
	if options.maxRetryDelay <= 0 {
		options.maxRetryDelay = defaults.maxRetryDelay
	}

	diagnostics := newSinkDiagnostics()
	ctx, cancel := context.WithCancel(context.Background())
	writer := &asyncBatchWriter{
		kind:        kind,
		name:        name,
		buffer:      newBoundedLogBuffer(options.maxEntries, options.maxBytes, diagnostics),
		diagnostics: diagnostics,
		send:        send,
		options:     options,
		ctx:         ctx,
		cancel:      cancel,
	}
	writer.wg.Add(2)
	go writer.run()
	go writer.runDiagnostics()

	return writer
}

func (w *asyncBatchWriter) Write(entry *LogEntry) error {
	if entry == nil {
		return fmt.Errorf("nil log entry")
	}
	return w.buffer.enqueue(entry)
}

func (w *asyncBatchWriter) Close() {
	w.closeOnce.Do(func() {
		w.buffer.close()
		w.cancel()
		w.wg.Wait()
		w.diagnostics.report(w.kind, w.name)
	})
}

func (w *asyncBatchWriter) runDiagnostics() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.options.reportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.diagnostics.report(w.kind, w.name)
		case <-w.ctx.Done():
			return
		}
	}
}

func (w *asyncBatchWriter) run() {
	defer w.wg.Done()

	retryDelay := w.options.initialRetryDelay
	consecutiveFailures := 0
	batch := make([]bufferedLogEntry, 0, w.options.maxBatchEntries)
	var batchBytes int64
	batchTimer := time.NewTimer(w.options.batchTimeout)
	if !batchTimer.Stop() {
		<-batchTimer.C
	}
	var batchTimerC <-chan time.Time

	startBatchTimer := func() {
		if batchTimerC != nil {
			return
		}
		batchTimer.Reset(w.options.batchTimeout)
		batchTimerC = batchTimer.C
	}
	stopBatchTimer := func() {
		if batchTimerC == nil {
			return
		}
		if !batchTimer.Stop() {
			select {
			case <-batchTimer.C:
			default:
			}
		}
		batchTimerC = nil
	}

	fillBatch := func() bool {
		for len(batch) < w.options.maxBatchEntries {
			remainingBytes := w.options.maxBatchBytes - batchBytes
			entry, ok, batchFull := w.buffer.dequeue(remainingBytes, len(batch) == 0)
			if batchFull {
				return true
			}
			if !ok {
				return false
			}
			batch = append(batch, entry)
			batchBytes += entry.size
			if batchBytes >= w.options.maxBatchBytes {
				return true
			}
		}
		return true
	}

	flushBatch := func(ctx context.Context, allowRetry bool) bool {
		if len(batch) == 0 {
			return true
		}

		entries := make([]*LogEntry, len(batch))
		for index, entry := range batch {
			entries[index] = entry.entry
		}

		err := w.send(ctx, entries)
		if err == nil {
			if consecutiveFailures > 0 {
				w.diagnostics.recordRecovery()
			}
			consecutiveFailures = 0
			retryDelay = w.options.initialRetryDelay
			w.buffer.release(batch)
			batch = batch[:0]
			batchBytes = 0
			return true
		}

		consecutiveFailures++
		w.diagnostics.recordError(err)
		if !allowRetry {
			w.diagnostics.recordDeliveryDrop(uint64(len(batch)))
			w.buffer.release(batch)
			batch = batch[:0]
			batchBytes = 0
			return true
		}

		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return false
		case <-timer.C:
		}

		err = w.send(ctx, entries)
		if err != nil {
			w.diagnostics.recordError(err)
			w.diagnostics.recordDeliveryDrop(uint64(len(batch)))
			retryDelay *= 2
			if retryDelay > w.options.maxRetryDelay {
				retryDelay = w.options.maxRetryDelay
			}
		} else {
			w.diagnostics.recordRecovery()
			consecutiveFailures = 0
			retryDelay = w.options.initialRetryDelay
		}

		w.buffer.release(batch)
		batch = batch[:0]
		batchBytes = 0
		return true
	}

	for {
		select {
		case <-w.ctx.Done():
			stopBatchTimer()
			w.finishShutdown(batch)
			return
		case <-w.buffer.ready:
			if fillBatch() {
				stopBatchTimer()
				if !flushBatch(w.ctx, true) {
					w.finishShutdown(batch)
					return
				}
				continue
			}
			if len(batch) > 0 {
				startBatchTimer()
			}
		case <-batchTimerC:
			batchTimerC = nil
			if !flushBatch(w.ctx, true) {
				w.finishShutdown(batch)
				return
			}
		}
	}
}

func (w *asyncBatchWriter) finishShutdown(initial []bufferedLogEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), w.options.shutdownTimeout)
	defer cancel()

	batch := initial
	for {
		if len(batch) == 0 {
			var batchBytes int64
			for len(batch) < w.options.maxBatchEntries {
				remainingBytes := w.options.maxBatchBytes - batchBytes
				entry, ok, batchFull := w.buffer.dequeue(remainingBytes, len(batch) == 0)
				if batchFull || !ok {
					break
				}
				batch = append(batch, entry)
				batchBytes += entry.size
			}
		}
		if len(batch) == 0 {
			return
		}

		entries := make([]*LogEntry, len(batch))
		for index, entry := range batch {
			entries[index] = entry.entry
		}
		if err := w.send(ctx, entries); err != nil {
			w.diagnostics.recordError(err)
			w.diagnostics.recordShutdownDrop(uint64(len(batch)))
		}
		w.buffer.release(batch)
		batch = nil

		if ctx.Err() != nil {
			w.buffer.discardQueued()
			return
		}
	}
}
