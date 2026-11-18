package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/engine"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/planner"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/report"
	"github.com/dukotah/tyto/internal/sqlstore"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/store"
	"github.com/dukotah/tyto/internal/sysinfo"
	"github.com/dukotah/tyto/internal/tool/adapter"
	"github.com/dukotah/tyto/internal/validate"
	"github.com/dukotah/tyto/pkg/version"
)

// runOptions holds the bound flags for the run command.
type runOptions struct {
	engPath      string
	dryRun       bool
	plannerKind  string
	model        string
	ollamaURL    string
	llmBaseURL   string
	cycles       int
	auditPath    string
	noReport     bool
	reportFormat string
	reportOut    string
	resume       bool
	statePath    string
	db           string
	// hunt runs the deterministic NO-LLM breadth-first payable-class sweep
	// (engine HuntMode) instead of the model planner — the overnight bounty engine.
	hunt         bool
	huntMaxHosts int
	// exec selects where shell-out tools run: ""=host (auto-detects Kali WSL on
	// Windows), "wsl:<distro>"=a WSL distro. Mirrors `tyto serve --exec`.
	exec string
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
	f.StringVar(&o.plannerKind, "planner", "", "planner backend: ollama|openai|scripted|mock (default: ollama, or mock with --dry-run)")
	f.StringVar(&o.model, "model", "", "model name (ollama: auto-detected from RAM; openai: required, e.g. gpt-4o-mini)")
	f.StringVar(&o.ollamaURL, "ollama-url", "http://localhost:11434", "ollama base URL")
	f.StringVar(&o.llmBaseURL, "llm-base-url", "", "OpenAI-compatible API base URL for --planner openai (default https://api.openai.com/v1; e.g. http://localhost:1234/v1 for LM Studio/vLLM). API key read from TYTO_LLM_API_KEY or OPENAI_API_KEY.")
	f.IntVar(&o.cycles, "cycles", 3, "max plan/act cycles (loop halts early on no progress)")
	f.StringVar(&o.auditPath, "audit", "", "audit log path (default: <engagement-id>.audit.jsonl)")
	f.BoolVar(&o.noReport, "no-report", false, "skip printing the report at the end")
	f.StringVar(&o.reportFormat, "report-format", "md", "report format: md|submission|json|sarif|html")
	f.StringVar(&o.reportOut, "report-out", "", "write the report to this file (default: stdout)")
	f.BoolVar(&o.resume, "resume", false, "resume from a saved state snapshot (skips completed actions)")
	f.StringVar(&o.statePath, "state", "", "state snapshot path (default: <engagement-id>.state.json)")
	f.StringVar(&o.db, "db", "", "persist/resume via a SQLite engagement DB at this path (instead of the JSON snapshot)")
	f.StringVar(&o.exec, "exec", "", `where shell-out tools run: ""=host (auto-detects Kali WSL on Windows), "wsl:<distro>"`)
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

	// Route shell-out tools (subfinder/nmap/nuclei/…) to an execution backend so
	// the sweep can actually enumerate. Explicit --exec/$TYTO_EXEC wins; otherwise
	// auto-detect a Kali WSL distro on Windows — same behavior as `tyto serve`, so
	// `tyto hunt`/`run` aren't silently host-only (where subfinder doesn't exist).
	spec := strings.TrimSpace(o.exec)
	if spec == "" {
		spec = strings.TrimSpace(os.Getenv("TYTO_EXEC"))
	}
	if spec == "" && runtime.GOOS == "windows" {
		if d := detectKaliWSL(); d != "" {
			spec = "wsl:" + d
		}
	}
	if err := adapter.Configure(spec); err != nil {
		return fmt.Errorf("exec backend: %w", err)
	}
	if spec != "" {
		fmt.Fprintf(out, "tool execution backend: %s\n", spec)
	}

	// Hunt mode is deterministic and never calls the model, so default the report
	// to the bounty gate and avoid requiring a live Ollama planner.
	if o.hunt && o.reportFormat == "md" {
		o.reportFormat = "bounty"
	}
	kind := o.plannerKind
	if kind == "" {
		if o.dryRun || o.hunt {
			kind = "mock"
		} else {
			kind = "ollama"
		}
	}
	var client llm.Client
	switch kind {
	case "mock":
		client = llm.NewDemoMock()
	case "scripted":
		var targets []string
		for _, tgt := range eng.Scope.InScope {
			targets = append(targets, tgt.Value)
		}
		client = llm.NewScriptedMock(targets)
	case "ollama":
		m := o.model
		if m == "" {
			ram, derr := sysinfo.TotalRAMBytes()
			choice := llm.DefaultModel(ram, derr == nil)
			m = choice.Model
			fmt.Fprintf(out, "model: %s\n", choice)
		}
		client = llm.NewOllama(o.ollamaURL, m)
	case "openai":
		if o.model == "" {
			return fmt.Errorf("--planner openai requires --model (e.g. gpt-4o-mini, or the model name your server exposes)")
		}
		apiKey := os.Getenv("TYTO_LLM_API_KEY")
		if apiKey == "" {
			apiKey = os.Getenv("OPENAI_API_KEY")
		}
		client = llm.NewOpenAI(o.llmBaseURL, o.model, apiKey)
		fmt.Fprintf(out, "model: %s (OpenAI-compatible)\n", o.model)
	default:
		return fmt.Errorf("unknown planner backend %q (want ollama|openai|scripted|mock)", kind)
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

	// Resume: replay a prior snapshot so the run continues where it left off.
	statePath := o.statePath
	if statePath == "" {
		statePath = eng.ID + ".state.json"
	}
	var priorActions []string
	if o.resume {
		if o.db != "" {
			dbs, err := sqlstore.Open(o.db)
			if err != nil {
				return fmt.Errorf("resume: open db: %w", err)
			}
			priorActions, err = dbs.Into(eng.ID, st)
			_ = dbs.Close()
			if err != nil {
				return fmt.Errorf("resume: load db: %w", err)
			}
			fmt.Fprintf(out, "resumed from %s: %d asset(s), %d finding(s), %d completed action(s)\n",
				o.db, len(st.Assets()), len(st.Findings()), len(priorActions))
		} else {
			snap, err := store.Load(statePath)
			if err != nil {
				return fmt.Errorf("resume: %w", err)
			}
			snap.Into(st)
			priorActions = snap.CompletedActions
			fmt.Fprintf(out, "resumed from %s: %d asset(s), %d finding(s), %d completed action(s)\n",
				statePath, len(snap.Assets), len(snap.Findings), len(priorActions))
		}
	}

	// Bind the signed scope hash + verified-grant count into the audit chain so any
	// post-hoc scope widening is detectable against the trail.
	if err := alog.Record("authorization", map[string]any{
		"scope_hash": eng.ScopeHash(), "verified_grants": len(grants),
		"client_key": eng.Authorization.ClientPublicKeyB64,
		"mode":       authMode(eng), "authorized_by": eng.Authorization.AuthorizedBy,
		"agreement_ref": eng.Authorization.AgreementRef,
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
		engine.Options{DryRun: o.dryRun, MaxCycles: o.cycles, PriorActionKeys: priorActions,
			HuntMode: o.hunt, HuntMaxHosts: o.huntMaxHosts},
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

	// Persist progress so the engagement can be resumed later (SQLite if --db,
	// else a JSON snapshot).
	if o.db != "" {
		if dbs, err := sqlstore.Open(o.db); err != nil {
			fmt.Fprintf(out, "warning: could not open db %s: %v\n", o.db, err)
		} else {
			if err := dbs.SaveState(eng.ID, st, eg.CompletedActionKeys()); err != nil {
				fmt.Fprintf(out, "warning: could not save to db: %v\n", err)
			} else {
				fmt.Fprintf(out, "state saved to %s\n", o.db)
			}
			_ = dbs.Close()
		}
	} else if err := store.Save(statePath, store.Capture(st, eg.CompletedActionKeys())); err != nil {
		fmt.Fprintf(out, "warning: could not save state snapshot: %v\n", err)
	}

	if o.noReport {
		return nil
	}
	return emitReport(o, eng, st, eg.Sessions(), out)
}

// emitReport renders the chosen format and writes it to stdout or a file. The
// sessions map (host→cookie, from the just-finished run) is threaded into the
// submission report's adversarial re-proof so it re-fetches authenticated.
func emitReport(o *runOptions, eng *engagement.Engagement, st *state.State, sessions map[string]string, out io.Writer) error {
	var data []byte
	switch o.reportFormat {
	case "md", "markdown":
		data = []byte(report.Render(eng, st))
	case "submission":
		// Adversarially re-prove findings before they enter the submission body
		// (refute-by-default); set-aside findings are retained as flagged noise.
		vctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		fetch := validate.NewHTTPFetcher()
		fetch.Cookies = sessions // re-prove authenticated, per host, with the run's sessions
		data = []byte(report.RenderSubmissionValidated(vctx, eng, st, fetch))
	case "bounty":
		// Payability-tiered bounty gate: payable classes (takeover/.git/secret/CVE)
		// surface as actionable candidates; validation promotes any it can re-prove.
		vctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		fetch := validate.NewHTTPFetcher()
		fetch.Cookies = sessions
		data = []byte(report.RenderBountyValidated(vctx, eng, st, fetch))
	case "json":
		b, err := report.RenderJSON(eng, st)
		if err != nil {
			return err
		}
		data = b
	case "sarif":
		b, err := report.RenderSARIF(eng, st)
		if err != nil {
			return err
		}
		data = b
	case "html":
		b, err := report.RenderHTML(eng, st)
		if err != nil {
			return err
		}
		data = b
	default:
		return fmt.Errorf("unknown report format %q (want md|submission|json|sarif|html)", o.reportFormat)
	}

	if o.reportOut == "" {
		fmt.Fprintln(out)
		_, err := out.Write(append(data, '\n'))
		return err
	}
	if err := os.WriteFile(o.reportOut, data, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	fmt.Fprintf(out, "report written to %s\n", o.reportOut)
	return nil
}
