package cmd

import (
	"testing"

	"flowguard/fail2ban"
)

func TestFail2BanEventCommandTreatsDashPrefixedJailAsPayload(t *testing.T) {
	oldSender := sendFail2BanEvent
	oldVerbose := verbose
	t.Cleanup(func() {
		sendFail2BanEvent = oldSender
		verbose = oldVerbose
		rootCmd.SetArgs(nil)
	})

	var received fail2ban.Event
	sendFail2BanEvent = func(_ string, event fail2ban.Event) error {
		received = event
		return nil
	}
	verbose = false
	rootCmd.SetArgs([]string{"fail2ban-event", "ban", "-v", "198.51.100.181"})
	if _, err := rootCmd.ExecuteC(); err != nil {
		t.Fatalf("execute fail2ban event command: %v", err)
	}
	if received.Operation != "ban" || received.Jail != "-v" || received.Address != "198.51.100.181" {
		t.Fatalf("received event = %#v", received)
	}
	if verbose {
		t.Fatal("dash-prefixed jail was consumed as the global verbose flag")
	}
}
