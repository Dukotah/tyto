package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/pkg/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "tyto %s\n", version.Version)
			return nil
		},
	}
}
