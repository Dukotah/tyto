// Package engine runs the orchestration loop that ties tyto together:
// plan -> guard -> execute -> record -> repeat. It owns dry-run behaviour and is
// the only place actions flow from the planner, through the guard, to tools.
package engine

import (
	"context"
	"fmt"
	"io"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/planner"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool"
)

// Options tune one engine run.
type Options struct {
	// DryRun plans and guards but never executes tools.
	DryRun bool
	// MaxCycles caps plan/act iterations. <= 0 means a single cycle.
	MaxCycles int
}

// Engine coordinates one engagement.
type Engine struct {
	eng     *engagement.Engagement
	guard   *guard.Guard
	planner *planner.Planner
	tools   *tool.Registry
	state   *state.State
	audit   *audit.Log
	out     io.Writer
	opts    Options
}

// New wires an engine. The caller owns the state and audit log (so it can render
// a report and close the log afterwards).
func New(
	eng *engagement.Engagement,
	g *guard.Guard,
	p *planner.Planner,
	tools *tool.Registry,
	st *state.State,
	a *audit.Log,
	out io.Writer,
	opts Options,
) *Engine {
	return &Engine{eng: eng, guard: g, planner: p, tools: tools, state: st, audit: a, out: out, opts: opts}
}

// Run executes the plan/act loop until cycles are exhausted, the planner
// proposes nothing, or the context is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	e.audit.Record("info", map[string]any{
		"event": "engagement_start", "id": e.eng.ID, "client": e.eng.Client, "dry_run": e.opts.DryRun,
	})

	cycles := e.opts.MaxCycles
	if cycles <= 0 {
		cycles = 1
	}

	for c := 1; c <= cycles; c++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "\n── cycle %d/%d ──\n", c, cycles)

		actions, err := e.planner.Plan(ctx, e.eng, e.state, e.tools.Names())
		if err != nil {
			return fmt.Errorf("cycle %d: %w", c, err)
		}
		if len(actions) == 0 {
			fmt.Fprintln(e.out, "planner proposed no further actions; stopping.")
			break
		}
		for _, a := range actions {
			e.handle(ctx, a)
		}
	}

	e.audit.Record("info", map[string]any{"event": "engagement_end", "id": e.eng.ID})
	return nil
}

// handle runs one action through the guard and (if allowed and not dry-run) the
// tool, recording every step to the audit log.
func (e *Engine) handle(ctx context.Context, a action.Action) {
	dec := e.guard.Evaluate(a)
	// a.Category / a.Risk are the model's SELF-DECLARED values, recorded for
	// audit only; the guard gates on authoritative tool metadata.
	e.audit.Record("decision", map[string]any{
		"action": a.ID, "tool": a.Tool, "declared_category": a.Category,
		"target": a.Target, "declared_risk": a.Risk.String(),
		"verdict": dec.Verdict.String(), "allowed": dec.IsAllowed(), "reason": dec.Reason,
	})

	switch dec.Verdict {
	case guard.VerdictDeny:
		fmt.Fprintf(e.out, "  DENY  %-12s %-22s — %s\n", a.Tool, a.Target, dec.Reason)
		return
	case guard.VerdictRequireApproval:
		// Human-approval UX lands in a later phase; until then, fail safe by not
		// executing and recording that approval was required.
		fmt.Fprintf(e.out, "  HOLD  %-12s %-22s — needs approval: %s\n", a.Tool, a.Target, dec.Reason)
		e.audit.Record("approval_required", map[string]any{
			"action": a.ID, "tool": a.Tool, "target": a.Target, "reason": dec.Reason,
		})
		return
	}
	// VerdictAllow falls through.

	if e.opts.DryRun {
		fmt.Fprintf(e.out, "  ALLOW %-12s %-22s [dry-run] %s\n", a.Tool, a.Target, a.Rationale)
		return
	}

	t, ok := e.tools.Get(a.Tool)
	if !ok {
		fmt.Fprintf(e.out, "  SKIP  %-12s %-22s — no such tool registered\n", a.Tool, a.Target)
		e.audit.Record("result", map[string]any{"action": a.ID, "skipped": "unknown tool"})
		return
	}

	e.audit.Record("action", map[string]any{
		"action": a.ID, "tool": a.Tool, "target": a.Target, "params": a.Params,
	})

	res, err := t.Execute(ctx, a)
	if err != nil {
		fmt.Fprintf(e.out, "  ERROR %-12s %-22s — %v\n", a.Tool, a.Target, err)
	}
	for _, f := range res.Findings {
		e.state.AddFinding(f)
	}
	for i := range res.Assets {
		asset := res.Assets[i]
		e.state.AddAsset(&asset)
	}
	e.audit.Record("result", map[string]any{
		"action": a.ID, "success": res.Success, "output": res.Output,
		"findings": len(res.Findings), "assets": len(res.Assets),
	})
	if res.Output != "" {
		fmt.Fprintf(e.out, "  DONE  %-12s %-22s — %s\n", a.Tool, a.Target, res.Output)
	}
}
