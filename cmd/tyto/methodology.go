package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/methodology"
)

func newMethodologyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "methodology",
		Short: "List the technique catalog the planner is grounded in",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "Methodology catalog — the techniques the planner selects from, pruned to your assets at run time:")
			for _, t := range methodology.All() {
				tool := t.Tool
				if tool == "" {
					tool = "—"
				}
				fmt.Fprintf(out, "  %-26s phase=%-13s tool=%-10s applies=%s\n",
					t.Name, t.Phase, tool, appliesStr(t.AppliesTo))
			}
			return nil
		},
	}
}

func appliesStr(a methodology.AppliesTo) string {
	switch {
	case a.AssetType != "":
		return "asset:" + a.AssetType
	case a.Service != "":
		return "service:" + a.Service
	default:
		return "any"
	}
}
