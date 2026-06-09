package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/engine"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/planner"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/report"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/sysinfo"
	"github.com/dukotah/tyto/pkg/version"
)

// runOptions holds the bound flags for the run command.
type runOptions struct {
	engPath     string
	dryRun      bool
	plannerKind string
	model       string
	ollamaURL   string
	cycles      int
	auditPath   string
	noReport    bool
}

func newRunCmd() *cobra.Command {
	o := &runOptions{}
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run an engagement (plan -> guard -> execute loop)",
		Args:  cobra.NoArgs,
		RunE:  o.run,
	}
	f := cmd.Flags()
	f.StringVar(&o.engPath, "engagement", "", "path to engagement YAML (required)")
	f.BoolVar(&o.dryRun, "dry-run", false, "plan and guard only; never execute tools")
	f.StringVar(&o.plannerKind, "planner", "", "planner backend: ollama|mock (default: ollama, or mock with --dry-run)")
	f.StringVar(&o.model, "model", "", "ollama model name (default: auto-detected from RAM)")
	f.StringVar(&o.ollamaURL, "ollama-url", "http://localhost:11434", "ollama base URL")
	f.IntVar(&o.cycles, "cycles", 3, "max plan/act cycles (loop halts early on no progress)")
	f.StringVar(&o.auditPath, "audit", "", "audit log path (default: <engagement-id>.audit.jsonl)")
	f.BoolVar(&o.noReport, "no-report", false, "skip printing the report at the end")
	return cmd
}

func (o *runOptions) run(cmd *cobra.Command, _ []string) error {
	if o.engPath == "" {
		return fmt.Errorf("--engagement is required")
	}
	out := cmd.OutOrStdout()

	eng, err := engagement.Load(o.engPath)
	if err != nil {
		return err
	}

	kind := o.plannerKind
	if kind == "" {
		if o.dryRun {
			kind = "mock"
		} else {
			kind = "ollama"
		}
	}
	var client llm.Client
	switch kind {
	case "mock":
		client = llm.NewDemoMock()
	case "ollama":
		m := o.model
		if m == "" {
			ram, derr := sysinfo.TotalRAMBytes()
			choice := llm.DefaultModel(ram, derr == nil)
			m = choice.Model
			fmt.Fprintf(out, "model: %s\n", choice)
		}
		client = llm.NewOllama(o.ollamaURL, m)
	default:
		return fmt.Errorf("unknown planner backend %q (want ollama|mock)", kind)
	}

	ap := o.auditPath
	if ap == "" {
		ap = eng.ID + ".audit.jsonl"
	}
	alog, closeAudit, err := audit.Open(ap)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer func() { _ = closeAudit() }()

	// Verify any client authorization grants up front and fail closed on a bad one
	// (a forged/tampered grant must abort, not silently fall back to no-auth).
	grants, err := eng.VerifiedGrants()
	if err != nil {
		return fmt.Errorf("authorization: %w", err)
	}

	st := state.New()
	reg := defaultRegistry()

	// Bind the signed scope hash + verified-grant count into the audit chain so any
	// post-hoc scope widening is detectable against the trail.
	if err := alog.Record("authorization", map[string]any{
		"scope_hash": eng.ScopeHash(), "verified_grants": len(grants),
		"client_key": eng.Authorization.ClientPublicKeyB64,
	}); err != nil {
		return fmt.Errorf("write audit head: %w", err)
	}

	eg := engine.New(
		eng,
		guard.New(eng, toolSnapshot(reg), grants),
		planner.New(client),
		reg,
		st,
		alog,
		out,
		engine.Options{DryRun: o.dryRun, MaxCycles: o.cycles},
	)

	baseCtx := cmd.Context()
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, stop := signal.NotifyContext(baseCtx, os.Interrupt)
	defer stop()

	// Hard-stop the run when the permitted operating window closes (in addition to
	// SIGINT). No windows configured ⇒ no time-based deadline.
	if deadline, ok := eng.RoE.Deadline(time.Now().UTC()); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
		fmt.Fprintf(out, "operating window closes at %s — run will stop then\n", deadline.Format("15:04 MST"))
	}

	fmt.Fprintf(out, "tyto %s — engagement %s (%s)\n", version.Version, eng.ID, eng.Client)
	fmt.Fprintf(out, "planner=%s  dry-run=%v  audit=%s\n", client.Name(), o.dryRun, ap)

	if err := eg.Run(ctx); err != nil {
		return err
	}

	if !o.noReport {
		fmt.Fprintln(out)
		fmt.Fprintln(out, report.Render(eng, st))
	}
	return nil
}
