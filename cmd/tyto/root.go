package main

import (
	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/pkg/version"
)

// newRootCmd builds the tyto command tree.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "tyto",
		Short: "AI-orchestrated authorized penetration testing",
		Long: "tyto — an offline, scope-enforced, AI-orchestrated authorized\n" +
			"penetration-testing platform with a deterministic Scope Guard and a\n" +
			"tamper-evident audit log.",
		Version:       version.Version,
		SilenceUsage:  true, // don't dump usage on a runtime error
		SilenceErrors: false,
	}
	root.SetVersionTemplate("tyto {{.Version}}\n")
	root.AddCommand(
		newRunCmd(),
		newHuntCmd(),
		newBlueCmd(),
		newEngagementCmd(),
		newAuthorizeCmd(),
		newToolsCmd(),
		newMethodologyCmd(),
		newFeedsCmd(),
		newServeCmd(),
		newMcpCmd(),
		newWatchCmd(),
		newVersionCmd(),
	)
	return root
}
