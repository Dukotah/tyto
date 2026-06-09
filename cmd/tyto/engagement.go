package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/engagement"
)

func newEngagementCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engagement",
		Short: "Work with engagement files",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "validate <file>",
		Short: "Validate an engagement file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, err := engagement.Load(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "OK: %s for %s — %d objective(s), %d in-scope, %d out-of-scope, max_risk=%s\n",
				eng.ID, eng.Client, len(eng.Objectives),
				len(eng.Scope.InScope), len(eng.Scope.OutOfScope), eng.RoE.MaxRisk)
			return nil
		},
	})
	return cmd
}
