package cmd

import (
	"flowguard/fail2ban"

	"github.com/spf13/cobra"
)

var sendFail2BanEvent = fail2ban.SendEvent

var fail2banEventCmd = &cobra.Command{
	Use:                "fail2ban-event",
	Short:              "Deliver an internal Fail2Ban runtime event",
	Hidden:             true,
	DisableFlagParsing: true,
	Args:               cobra.ArbitraryArgs,
	Run: func(_ *cobra.Command, args []string) {
		// This command is invoked from a Fail2Ban action. It must never make
		// Fail2Ban's own ban or unban operation fail, including while FlowGuard
		// is restarting or when an event is malformed.
		if len(args) != 3 {
			return
		}
		_ = sendFail2BanEvent(fail2ban.DefaultEventSocketPath, fail2ban.Event{
			Operation: args[0],
			Jail:      args[1],
			Address:   args[2],
		})
	},
}

func init() {
	rootCmd.AddCommand(fail2banEventCmd)
}
