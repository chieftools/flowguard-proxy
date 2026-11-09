package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCommandPrintsUsageOnlyForInvocationMistakes(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantUsage bool
	}{
		{name: "command error", args: []string{"usage-test"}, wantUsage: false},
		{name: "unexpected argument", args: []string{"usage-test", "extra"}, wantUsage: true},
		{name: "unknown flag", args: []string{"usage-test", "--unknown"}, wantUsage: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testCmd := &cobra.Command{
				Use:  "usage-test",
				Args: cobra.NoArgs,
				RunE: func(*cobra.Command, []string) error {
					return errors.New("configured mode is not ready")
				},
			}
			rootCmd.AddCommand(testCmd)
			var output bytes.Buffer
			rootCmd.SetOut(&output)
			rootCmd.SetErr(&output)
			rootCmd.SetArgs(tt.args)
			t.Cleanup(func() {
				rootCmd.RemoveCommand(testCmd)
				rootCmd.SetOut(nil)
				rootCmd.SetErr(nil)
				rootCmd.SetArgs(nil)
			})

			if _, err := rootCmd.ExecuteC(); err == nil {
				t.Fatal("expected an error")
			}
			if got := strings.Contains(output.String(), "Usage:"); got != tt.wantUsage {
				t.Fatalf("usage printed = %v, want %v; output:\n%s", got, tt.wantUsage, output.String())
			}
		})
	}
}
