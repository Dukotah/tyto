package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/cveindex"
)

// homeTyto returns the ~/.tyto base dir (falls back to "." if home is unknown).
func homeTyto() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".tyto"
	}
	return filepath.Join(home, ".tyto")
}

// newFeedsCmd manages local offline vulnerability data (the NVD CVE index).
func newFeedsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feeds",
		Short: "Manage offline vuln data (build the NVD CVE index)",
	}

	var nvdDir, out string
	index := &cobra.Command{
		Use:   "index",
		Short: "Build the CVE index from local NVD feeds (one-time; makes cvematch instant)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			nvd, db := nvdDir, out
			if nvd == "" {
				nvd = filepath.Join(homeTyto(), "feeds", "nvd")
			}
			if db == "" {
				db = filepath.Join(homeTyto(), "feeds", "cve-index.db")
			}
			o := cmd.OutOrStdout()
			fmt.Fprintf(o, "indexing NVD feeds from %s → %s (this scans the full CVE corpus once)...\n", nvd, db)
			start := time.Now()
			rows, err := cveindex.Build(cmd.Context(), nvd, db)
			if err != nil {
				return fmt.Errorf("build index: %w", err)
			}
			fmt.Fprintf(o, "indexed %d CPE rows in %s → %s\n", rows, time.Since(start).Round(time.Second), db)
			fmt.Fprintln(o, "cvematch will now use this index automatically.")
			return nil
		},
	}
	index.Flags().StringVar(&nvdDir, "nvd", "", "NVD feed dir (default: ~/.tyto/feeds/nvd)")
	index.Flags().StringVar(&out, "out", "", "index DB output path (default: ~/.tyto/feeds/cve-index.db)")

	cmd.AddCommand(index)
	return cmd
}
