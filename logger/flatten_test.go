package logger

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFlattenJSON(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{name: "nested objects", src: `{"client":{"ip":"1.2.3.4","as":{"num":123}},"status":200}`, want: `{"client.ip":"1.2.3.4","client.as.num":123,"status":200}`},
		{name: "arrays are copied", src: `{"a":[{"b":1},[],null],"c":{"d":["x","}"]}}`, want: `{"a":[{"b":1},[],null],"c.d":["x","}"]}`},
		{name: "escaped keys and values", src: `{"q\"k":{"in\\ner":"<& >"}}`, want: `{"q\"k.in\\ner":"<& >"}`},
		{name: "empty objects leave no key", src: `{"empty":{},"a":{"b":{}},"c":true}`, want: `{"c":true}`},
		{name: "numbers keep their encoding", src: `{"big":9007199254740993,"f":1.5e300}`, want: `{"big":9007199254740993,"f":1.5e300}`},
		{name: "entry without data", src: `null`, want: `{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _, err := flattenJSON([]byte(test.src), ".", "")
			if err != nil {
				t.Fatalf("flattenJSON: %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("flattenJSON(%s) = %s, want %s", test.src, got, test.want)
			}
		})
	}

	if _, captured, _ := flattenJSON([]byte(`{"a":{"timestamp":"inner"},"timestamp":"2031-06-07T12:00:00Z"}`), ".", "timestamp"); string(captured) != `"2031-06-07T12:00:00Z"` {
		t.Fatalf("captured %s, want the top-level timestamp", captured)
	}
	for _, src := range []string{`{"a":`, `{"a":"x`, `{"a":1,}`, `[1]`, `{"a":1}x`} {
		if _, _, err := flattenJSON([]byte(src), ".", ""); err == nil {
			t.Errorf("flattenJSON(%s) succeeded, want an error", src)
		}
	}
}

func TestLokiAndOpenObserveSendFlattenedEntries(t *testing.T) {
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	newEntry := func() *LogEntry {
		return &LogEntry{Data: map[string]interface{}{
			"timestamp": "2031-06-07T12:00:00Z",
			"client":    map[string]interface{}{"ip": "203.0.113.7", "asn": map[string]interface{}{"number": 64500}},
		}}
	}

	t.Run("loki", func(t *testing.T) {
		sink, err := NewLokiSink("loki", map[string]interface{}{"url": server.URL}, "FlowGuard/test")
		if err != nil {
			t.Fatalf("new sink: %v", err)
		}
		defer sink.Close()
		if err := sink.(*LokiSink).sendBatch(context.Background(), []*LogEntry{newEntry()}); err != nil {
			t.Fatalf("send batch: %v", err)
		}

		var push LokiPushRequest
		if err := json.Unmarshal(body, &push); err != nil || len(push.Streams) != 1 || len(push.Streams[0].Values) != 1 {
			t.Fatalf("push request %s: %v", body, err)
		}
		value := push.Streams[0].Values[0]
		if want := time.Date(2031, 6, 7, 12, 0, 0, 0, time.UTC).UnixNano(); value[0] != strconv.FormatInt(want, 10) {
			t.Fatalf("timestamp %s, want %d", value[0], want)
		}
		if value[1] != `{"client.asn.number":64500,"client.ip":"203.0.113.7","timestamp":"2031-06-07T12:00:00Z"}` {
			t.Fatalf("log line %s", value[1])
		}
	})

	t.Run("openobserve", func(t *testing.T) {
		sink, err := NewOpenObserveSink("openobserve", map[string]interface{}{"url": server.URL, "organization": "org", "stream": "flowguard"}, "FlowGuard/test")
		if err != nil {
			t.Fatalf("new sink: %v", err)
		}
		defer sink.Close()
		if err := sink.(*OpenObserveSink).sendBatch(context.Background(), []*LogEntry{newEntry(), newEntry()}); err != nil {
			t.Fatalf("send batch: %v", err)
		}

		var entries []map[string]interface{}
		if err := json.Unmarshal(body, &entries); err != nil || len(entries) != 2 {
			t.Fatalf("request body %s: %v", body, err)
		}
		if entries[1]["client__asn__number"] != float64(64500) || entries[1]["client__ip"] != "203.0.113.7" || strings.Contains(string(body), `"client":`) {
			t.Fatalf("request body %s, want flattened entries", body)
		}
	})
}
