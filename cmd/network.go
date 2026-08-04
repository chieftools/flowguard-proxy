package cmd

import (
	"fmt"

	"flowguard/proxy"

	"github.com/spf13/cobra"
)

var networkBindAddrs string

var networkCmd = &cobra.Command{
	Use:   "network",
	Short: "Inspect FlowGuard networking",
}

var networkInspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Show header and transparent upstream networking readiness",
	RunE: func(cmd *cobra.Command, args []string) error {
		configMgr, err := TryGetConfigManager()
		if err != nil {
			return err
		}
		defer configMgr.Stop()

		inspection, err := proxy.InspectNetwork(configMgr.GetConfig(), parseBindAddrsList(networkBindAddrs))
		if err != nil {
			return err
		}
		fmt.Fprint(cmd.OutOrStdout(), proxy.FormatNetworkInspection(inspection))
		if !inspection.Ready {
			return fmt.Errorf("configured upstream client IP mode %q is not ready", inspection.Mode)
		}
		return nil
	},
}

func init() {
	networkInspectCmd.Flags().StringVar(&networkBindAddrs, "bind", "", "Comma-separated bind addresses (default: auto-detect public IPs)")
	networkCmd.AddCommand(networkInspectCmd)
	rootCmd.AddCommand(networkCmd)
}
