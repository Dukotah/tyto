package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newToolsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tools",
		Short: "List registered tool adapters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "Registered tools:")
			for _, t := range defaultRegistry().All() {
				fmt.Fprintf(out, "  %-14s category=%-8s max_risk=%s\n", t.Name(), t.Category(), t.MaxRisk())
			}
			return nil
		},
	}
}
