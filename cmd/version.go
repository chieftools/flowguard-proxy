package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Display the current version of FlowGuard.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("FlowGuard version %s\n", GetVersion())
		fmt.Printf("%s\n", changelogURL(GetVersion()))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func changelogURL(version string) string {
	path := "https://github.com/chieftools/flowguard-proxy"
	r := regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[\w.]+)?$`)
	if !r.MatchString(version) {
		return fmt.Sprintf("%s/releases/latest", path)
	}

	url := fmt.Sprintf("%s/releases/tag/v%s", path, strings.TrimPrefix(version, "v"))
	return url
}
