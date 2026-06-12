package main

import (
	"github.com/spf13/cobra"
)

// newHuntCmd is the overnight bug-bounty sweep: it runs the SAME engagement
// machinery as `tyto run`, but with the engine's deterministic, NO-LLM
// breadth-first payable-class sweep (HuntMode) instead of the model planner.
// Across a wildcard scope it enumerates subdomains, probes liveness, then runs
// only the high-precision payable-class probes (subdomain takeover, exposed
// .git/secrets/config, known-CVE templates) on every live host — no per-cycle
// model tax, so it covers hundreds of hosts on CPU overnight. Output defaults to
// the bounty submission gate. The Scope Guard still gates every action.
func newHuntCmd() *cobra.Command {
	o := &runOptions{hunt: true}
	cmd := &cobra.Command{
		Use:   "hunt",
		Short: "Overnight deterministic payable-class sweep of an authorized scope (no LLM)",
		Long: "Run the deterministic, no-LLM breadth-first sweep over an authorized\n" +
			"wildcard scope: enumerate -> liveness -> the payable-class battery\n" +
			"(takeover / .git / secrets / config / CVE) on every live host, then emit\n" +
			"the bounty submission gate. The Scope Guard bounds every action.",
		Args: cobra.NoArgs,
		RunE: o.run,
	}
	f := cmd.Flags()
	f.StringVar(&o.engPath, "engagement", "", "path to engagement YAML (required; defines the authorized wildcard scope)")
	f.BoolVar(&o.dryRun, "dry-run", false, "plan and scope-guard the sweep without executing any tool (preview the deterministic action sequence)")
	f.IntVar(&o.huntMaxHosts, "max-hosts", 0, "cap the host fan-out (0 = default 500; a loud note is emitted if the cap bites)")
	f.IntVar(&o.cycles, "cycles", 200, "max sweep cycles (the sweep self-terminates when the scope is exhausted)")
	f.StringVar(&o.auditPath, "audit", "", "audit log path (default: <engagement-id>.audit.jsonl)")
	f.StringVar(&o.reportFormat, "report-format", "md", "report format: bounty|submission|md|json|sarif|html (default: bounty)")
	f.StringVar(&o.reportOut, "report-out", "", "write the report to this file (default: stdout)")
	f.StringVar(&o.db, "db", "", "persist/resume via a SQLite engagement DB at this path")
	f.BoolVar(&o.resume, "resume", false, "resume the sweep from a saved state snapshot")
	f.StringVar(&o.statePath, "state", "", "state snapshot path (default: <engagement-id>.state.json)")
	return cmd
}
