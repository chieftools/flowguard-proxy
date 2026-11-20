package logger

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestFlowGuardIngestSplitsCompleteEnvelopeAtByteLimit(t *testing.T) {
	entries := make([]*LogEntry, 100)
	for index := range entries {
		entry := ingestTestEntry(2031, 6, 8)
		entry.Data["message"] = strings.Repeat("x", ingestMaxBodyBytes/100-80)
		entries[index] = entry
	}

	requests, err := prepareIngestRequests(entries, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 {
		t.Fatalf("expected two requests after envelope overhead, got %d", len(requests))
	}

	var total int
	seen := map[string]bool{}
	for _, request := range requests {
		reader, err := gzip.NewReader(bytes.NewReader(request.body))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(body) > ingestMaxBodyBytes {
			t.Fatal("complete envelope exceeded limit")
		}

		var envelope ingestEnvelope
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatal(err)
		}
		for _, encoded := range envelope.Events {
			var event ingestEvent
			if err := json.Unmarshal(encoded, &event); err != nil {
				t.Fatal(err)
			}
			if !ingestHexID(event.ID) || seen[event.ID] {
				t.Fatal("invalid or repeated event identity")
			}
			seen[event.ID] = true
		}
		total += len(envelope.Events)
	}

	if total != len(entries) || requests[0].id == requests[1].id {
		t.Fatal("splitting lost events or reused a batch ID")
	}
}

func TestFlowGuardIngestRejectsInvalidBatchBeforeFirstSend(t *testing.T) {
	cases := []struct {
		name  string
		entry *LogEntry
	}{
		{name: "missing timestamp", entry: testLogEntry("synthetic")},
		{name: "fractional timestamp", entry: &LogEntry{Data: map[string]interface{}{"_timestamp": 1.5}}},
		{name: "oversized payload", entry: ingestTestEntry(2031, 6, 8)},
	}
	cases[2].entry.Data["message"] = strings.Repeat("x", ingestMaxPayloadBytes)

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			requests, err := prepareIngestRequests([]*LogEntry{
				ingestTestEntry(2031, 6, 7),
				testCase.entry,
			}, strings.Repeat("a", 32))

			if err == nil || requests != nil {
				t.Fatal("returned a partial batch after validation failed")
			}
		})
	}
}

func TestFlowGuardIngestPayloadIsTheEntryEncodingWithoutHTMLEscapes(t *testing.T) {
	entry := ingestTestEntry(2031, 6, 7)
	entry.Data["url"] = "https://shop.example.test/?a=1&b=<2>"
	encoded, err := entry.jsonBytes()
	if err != nil {
		t.Fatalf("encode entry: %v", err)
	}

	event, _, err := prepareIngestEvent(entry)
	if err != nil {
		t.Fatalf("prepare event: %v", err)
	}
	if !strings.Contains(string(event.Payload), `"url":"https://shop.example.test/?a=1&b=<2>"`) {
		t.Fatalf("payload %s, want the URL without HTML escapes", event.Payload)
	}
	if string(event.Payload) != string(encoded) {
		t.Fatalf("payload %s differs from the entry encoding %s", event.Payload, encoded)
	}

	whole := &LogEntry{Data: map[string]interface{}{"_timestamp": float64(time.Date(2031, 6, 7, 0, 0, 0, 0, time.UTC).UnixMicro())}}
	if _, _, err := prepareIngestEvent(whole); err != nil {
		t.Fatalf("expected a whole-number float timestamp to be accepted: %v", err)
	}
}
