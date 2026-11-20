package logger

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"
)

const (
	ingestMaxEvents       = 100
	ingestMaxBodyBytes    = 8 << 20
	ingestMaxPayloadBytes = 256 << 10
	ingestReceiptMaxBytes = 8 << 10
)

type ingestEnvelope struct {
	ProtocolVersion    int               `json:"protocol_version"`
	IdentityGeneration string            `json:"identity_generation"`
	BatchID            string            `json:"batch_id"`
	Events             []json.RawMessage `json:"events"`
}

type ingestEvent struct {
	ID         string          `json:"event_id"`
	CapturedAt string          `json:"captured_at_us"`
	Payload    json.RawMessage `json:"payload"`
}

type ingestRequest struct {
	id       string
	digest   string
	body     []byte
	events   int
	rawBytes int
	// preparedAt is set on the first send attempt and repeated on every retry so the gateway
	// stores identical rows and ClickHouse can drop a retried request by its content.
	preparedAt int64
}

func prepareIngestRequests(entries []*LogEntry, generation string) ([]ingestRequest, error) {
	envelope := ingestEnvelope{
		ProtocolVersion:    1,
		IdentityGeneration: generation,
		BatchID:            newIngestID(),
		Events:             []json.RawMessage{},
	}

	header, err := encodeIngestJSON(envelope)
	if err != nil {
		return nil, err
	}

	var requests []ingestRequest
	var day int64
	bodyBytes := len(header)
	rawBytes := 0

	flush := func() error {
		request, err := envelope.request(rawBytes)
		if err != nil {
			return err
		}

		requests = append(requests, request)
		envelope.BatchID = newIngestID()
		envelope.Events = []json.RawMessage{}
		bodyBytes = len(header)
		rawBytes = 0

		return nil
	}

	for _, entry := range entries {
		event, captureDay, err := prepareIngestEvent(entry)
		if err != nil {
			return nil, err
		}

		encoded, err := encodeIngestJSON(event)
		if err != nil {
			return nil, err
		}

		separatorBytes := 0
		if len(envelope.Events) > 0 {
			separatorBytes = 1
		}

		if len(envelope.Events) > 0 && (captureDay != day || len(envelope.Events) == ingestMaxEvents ||
			bodyBytes+separatorBytes+len(encoded) > ingestMaxBodyBytes) {
			if err := flush(); err != nil {
				return nil, err
			}

			separatorBytes = 0
		}

		envelope.Events = append(envelope.Events, encoded)
		bodyBytes += separatorBytes + len(encoded)
		rawBytes += len(event.Payload)
		day = captureDay
	}

	if len(envelope.Events) > 0 {
		if err := flush(); err != nil {
			return nil, err
		}
	}

	return requests, nil
}

func prepareIngestEvent(entry *LogEntry) (ingestEvent, int64, error) {
	payload, err := entry.jsonBytes()
	if err != nil {
		return ingestEvent{}, 0, fmt.Errorf("failed to encode flowguard ingest event")
	}

	if len(payload) == 0 || payload[0] != '{' {
		return ingestEvent{}, 0, fmt.Errorf("flowguard ingest event must be an object")
	}

	micros, ok := ingestTimestampMicros(entry.timestampValue())
	if !ok || micros <= 0 || time.UnixMicro(micros).UTC().Year() > 2105 {
		return ingestEvent{}, 0, fmt.Errorf("flowguard ingest event requires a valid _timestamp in microseconds")
	}

	if len(payload) > ingestMaxPayloadBytes {
		return ingestEvent{}, 0, fmt.Errorf("flowguard ingest event exceeds payload limit")
	}

	event := ingestEvent{
		ID:         newIngestID(),
		CapturedAt: strconv.FormatInt(micros, 10),
		Payload:    payload,
	}

	return event, micros / int64(24*time.Hour/time.Microsecond), nil
}

// ingestTimestampMicros returns a _timestamp value as whole microseconds.
func ingestTimestampMicros(value any) (int64, bool) {
	switch timestamp := value.(type) {
	case int64:
		return timestamp, true
	case int:
		return int64(timestamp), true
	case float64:
		if timestamp != math.Trunc(timestamp) || math.Abs(timestamp) >= math.MaxInt64 {
			return 0, false
		}
		return int64(timestamp), true
	case json.Number:
		micros, err := timestamp.Int64()
		return micros, err == nil
	default:
		return 0, false
	}
}

// ingestGzipWriters reuses compressors, which allocate about 1 MiB each.
var ingestGzipWriters = sync.Pool{
	New: func() any { return gzip.NewWriter(nil) },
}

func (e ingestEnvelope) request(rawBytes int) (ingestRequest, error) {
	body, err := encodeIngestJSON(e)
	if err != nil {
		return ingestRequest{}, err
	}

	if len(body) > ingestMaxBodyBytes {
		return ingestRequest{}, fmt.Errorf("flowguard ingest request exceeds body limit")
	}

	digest := sha256.Sum256(body)
	var compressed bytes.Buffer
	writer := ingestGzipWriters.Get().(*gzip.Writer)
	defer ingestGzipWriters.Put(writer)
	writer.Reset(&compressed)
	if _, err := writer.Write(body); err != nil {
		return ingestRequest{}, fmt.Errorf("failed to compress flowguard ingest request")
	}

	if err := writer.Close(); err != nil {
		return ingestRequest{}, fmt.Errorf("failed to finish flowguard ingest compression")
	}

	return ingestRequest{
		id:       e.BatchID,
		digest:   hex.EncodeToString(digest[:]),
		body:     compressed.Bytes(),
		events:   len(e.Events),
		rawBytes: rawBytes,
	}, nil
}

func encodeIngestJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("failed to encode flowguard ingest JSON")
	}

	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func newIngestID() string {
	var value [16]byte
	rand.Read(value[:])
	return hex.EncodeToString(value[:])
}

func ingestHexID(value string) bool {
	if len(value) != 32 {
		return false
	}

	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}

	return true
}
