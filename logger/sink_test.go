package logger

import (
	"testing"
)

func TestLogEntry_Flatten(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name: "simple nested object",
			input: map[string]interface{}{
				"client": map[string]interface{}{
					"ip": "203.0.113.42",
				},
			},
			expected: map[string]interface{}{
				"client.ip": "203.0.113.42",
			},
		},
		{
			name: "deeply nested object",
			input: map[string]interface{}{
				"client": map[string]interface{}{
					"ip": "203.0.113.42",
					"as": map[string]interface{}{
						"num":    15169,
						"name":   "Google LLC",
						"domain": "google.com",
					},
				},
			},
			expected: map[string]interface{}{
				"client.ip":        "203.0.113.42",
				"client.as.num":    float64(15169), // JSON unmarshal converts to float64
				"client.as.name":   "Google LLC",
				"client.as.domain": "google.com",
			},
		},
		{
			name: "mixed flat and nested",
			input: map[string]interface{}{
				"timestamp": "2025-11-18T10:00:00Z",
				"client": map[string]interface{}{
					"ip":      "203.0.113.42",
					"country": "US",
				},
				"status": 200,
			},
			expected: map[string]interface{}{
				"timestamp":      "2025-11-18T10:00:00Z",
				"client.ip":      "203.0.113.42",
				"client.country": "US",
				"status":         float64(200), // JSON unmarshal converts to float64
			},
		},
		{
			name: "with arrays (should preserve arrays)",
			input: map[string]interface{}{
				"request": map[string]interface{}{
					"header_names": []interface{}{"user-agent", "cf-ray"},
					"method":       "GET",
				},
			},
			expected: map[string]interface{}{
				"request.header_names": []interface{}{"user-agent", "cf-ray"},
				"request.method":       "GET",
			},
		},
		{
			name: "complex real-world example",
			input: map[string]interface{}{
				"stream_id": "abc123",
				"host": map[string]interface{}{
					"name": "server.example.com",
					"team": "prod",
				},
				"client": map[string]interface{}{
					"ip": "203.0.113.42",
					"as": map[string]interface{}{
						"num":  15169,
						"name": "Google LLC",
					},
				},
				"request": map[string]interface{}{
					"method": "GET",
					"url": map[string]interface{}{
						"path":   "/api/users",
						"domain": "example.com",
					},
				},
			},
			expected: map[string]interface{}{
				"stream_id":           "abc123",
				"host.name":           "server.example.com",
				"host.team":           "prod",
				"client.ip":           "203.0.113.42",
				"client.as.num":       float64(15169), // JSON unmarshal converts to float64
				"client.as.name":      "Google LLC",
				"request.method":      "GET",
				"request.url.path":    "/api/users",
				"request.url.domain":  "example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &LogEntry{Data: tt.input}
			result, err := entry.Flatten()
			if err != nil {
				t.Fatalf("Flatten() error: %v", err)
			}

			// Compare keys and values
			if len(result) != len(tt.expected) {
				t.Errorf("Flatten() result length mismatch\nGot %d keys: %+v\nExpected %d keys: %+v",
					len(result), result, len(tt.expected), tt.expected)
			}

			for k, expectedVal := range tt.expected {
				if gotVal, ok := result[k]; !ok {
					t.Errorf("Flatten() missing key %q", k)
				} else {
					// Special handling for slices (arrays in JSON)
					gotSlice, gotIsSlice := gotVal.([]interface{})
					expSlice, expIsSlice := expectedVal.([]interface{})

					if gotIsSlice && expIsSlice {
						if len(gotSlice) != len(expSlice) {
							t.Errorf("Flatten() key %q slice length mismatch\nGot: %d\nExpected: %d",
								k, len(gotSlice), len(expSlice))
						} else {
							for i := range gotSlice {
								if gotSlice[i] != expSlice[i] {
									t.Errorf("Flatten() key %q slice[%d] mismatch\nGot: %v\nExpected: %v",
										k, i, gotSlice[i], expSlice[i])
								}
							}
						}
					} else if gotVal != expectedVal {
						t.Errorf("Flatten() key %q mismatch\nGot:      %v (%T)\nExpected: %v (%T)",
							k, gotVal, gotVal, expectedVal, expectedVal)
					}
				}
			}
		})
	}
}
