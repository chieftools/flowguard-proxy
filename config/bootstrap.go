package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"go.chief.tools/flowguard-proxy/api"
)

// Bootstrap makes sure path holds the configuration for hostKey. A readable
// file for the same host key is kept as is, because the Manager's API refresh
// brings it up to date. Otherwise, for example on first start or after the key
// was rotated, the configuration is fetched from the API and written to path.
func Bootstrap(path, hostKey, userAgent string) error {
	if hostKey == "" {
		return fmt.Errorf("host key is required")
	}

	if data, err := os.ReadFile(path); err == nil {
		var existing Config
		if json.Unmarshal(data, &existing) == nil && existing.Host != nil && existing.Host.Key == hostKey {
			return nil
		}
	}

	body, err := api.NewClient(hostKey, userAgent).GetConfig("")
	if err != nil {
		return err
	}

	var fetched Config
	if err := json.Unmarshal(body, &fetched); err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}

	return WriteFile(path, body)
}

// WriteFile atomically replaces the configuration at path with body, creating
// the directory when needed.
func WriteFile(path string, body []byte) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write to temporary file first for atomic update
	tmpFile := path + ".tmp"
	if err := os.WriteFile(tmpFile, body, 0644); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	// Atomically rename to final location
	if err := os.Rename(tmpFile, path); err != nil {
		// Clean up temp file if rename fails (ignore cleanup errors)
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	return nil
}
