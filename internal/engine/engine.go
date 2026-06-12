// Package engine runs the orchestration loop that ties tyto together:
// plan -> guard -> execute -> record -> repeat. It owns dry-run behaviour and is
// the only place actions flow from the planner, through the guard, to tools.
package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/planner"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool"
)

// defaultMaxCycles is the iteration cap used when Options.MaxCycles <= 0. The
// loop still terminates early on the no-progress contract or an empty plan, so a
// generous default lets a productive run keep discovering without re-tuning.
const defaultMaxCycles = 10

// Event is a structured progress event emitted during a run, for live UIs
// (the web console subscribes to these). Emitting is opt-in via Options.OnEvent;
// CLI runs leave it nil and pay nothing.
type Event struct {
	Kind     string    `json:"kind"` // cycle|action|decision|result|finding|done|error|log|approval_required
	Action   string    `json:"action,omitempty"`
	Cycle    int       `json:"cycle,omitempty"`
	Tool     string    `json:"tool,omitempty"`
	Target   string    `json:"target,omitempty"`
	Verdict  string    `json:"verdict,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Title    string    `json:"title,omitempty"`
	Message  string    `json:"message,omitempty"`
	Time     time.Time `json:"time"`
}

// Options tune one engine run.
type Options struct {
	// DryRun plans and guards but never executes tools.
	DryRun bool
	// MaxCycles caps plan/act iterations. <= 0 means the default (10); the loop
	// still terminates early on an empty plan or the no-progress contract.
	MaxCycles int
	// NoProgressCycleLimit halts the loop after this many consecutive cycles that
	// discover nothing new and run no novel action. <= 0 means the default (3).
	NoProgressCycleLimit int
	// PriorActionKeys are canonical keys of actions completed in an earlier run
	// (from a resumed snapshot); they are pre-seeded as "seen" so resume doesn't
	// re-execute them.
	PriorActionKeys []string
	// OnEvent, if set, receives a structured Event at each step of the loop (for
	// live monitoring). It is called synchronously on the run goroutine, so it
	// must not block; the web console hands off to a buffered channel.
	OnEvent func(Event)
	// RequireApproval enables human-in-the-loop gating: high-impact actions
	// (exploit/identity category or RiskHigh tools) pause for explicit operator
	// approval instead of auto-running within scope.
	RequireApproval bool
	// Approver decides a high-impact action when RequireApproval is on. It may
	// block (e.g. awaiting a click in the web console). nil + RequireApproval =
	// fail closed (deny). The error return propagates (e.g. ctx cancelled).
	Approver func(ctx context.Context, a action.Action) (bool, error)
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
	// seen holds the canonical keys of actions already handled this run so
	// duplicates are skipped deterministically (part of the termination contract).
	seen     map[string]bool
	throttle *throttle
	// sessions maps a host to an established session cookie (from the login tool),
	// injected into later actions against that host so they run authenticated.
	sessions map[string]string
	// scratch is the planner's short-term memory (already-done + denied actions),
	// fed back each cycle so the model stops re-proposing finished or out-of-bounds work.
	scratch *planner.Scratchpad
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
	e := &Engine{eng: eng, guard: g, planner: p, tools: tools, state: st, audit: a, out: out, opts: opts, seen: make(map[string]bool), throttle: newThrottle(eng.RoE), sessions: make(map[string]string), scratch: planner.NewScratchpad()}
	for _, k := range opts.PriorActionKeys {
		e.seen[k] = true
	}
	return e
}

// CompletedActionKeys returns the canonical keys of every action handled this
// run (deduped, sorted) for persisting to a resumable snapshot.
func (e *Engine) CompletedActionKeys() []string {
	keys := make([]string, 0, len(e.seen))
	for k := range e.seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Sessions returns a copy of the host→session-cookie map established during the
// run (keyed by bare, port-stripped host). The report finalize path uses it to
// re-prove findings with the SAME authentication the scan had, so an
// authenticated-only finding isn't wrongly refuted on an unauthenticated
// re-fetch. Returns a copy so callers can't mutate engine state.
func (e *Engine) Sessions() map[string]string {
	out := make(map[string]string, len(e.sessions))
	for h, c := range e.sessions {
		out[h] = c
	}
	return out
}

// highImpact reports whether an action warrants human approval: an exploit/
// identity/post-exploit/dos tool, or any RiskHigh tool.
func highImpact(t tool.Tool) bool {
	if t.MaxRisk() >= action.RiskHigh {
		return true
	}
	switch t.Category() {
	case action.CategoryExploit, action.CategoryIdentity, action.CategoryPostExploit, action.CategoryDoS:
		return true
	}
	return false
}

// engagementHost extracts the bare host from a target (URL or host[:port]) so
// sessions can be keyed by host across actions.
func engagementHost(target string) string {
	t := target
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	return t
}

// emit sends a structured progress event if a listener is attached (no-op for
// CLI runs). Time is stamped here.
func (e *Engine) emit(ev Event) {
	if e.opts.OnEvent != nil {
		ev.Time = time.Now().UTC()
		e.opts.OnEvent(ev)
	}
}

// rec writes an audit entry and fails closed: if the load-bearing audit trail
// can't be written, the run must stop rather than continue unrecorded.
func (e *Engine) rec(kind string, data map[string]any) error {
	if err := e.audit.Record(kind, data); err != nil {
		fmt.Fprintf(e.out, "  AUDIT WRITE FAILED — halting (the audit trail is load-bearing): %v\n", err)
		return err
	}
	return nil
}

// Run executes the plan/act loop until cycles are exhausted, the planner
// proposes nothing, or the context is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	if err := e.rec("info", map[string]any{
		"event": "engagement_start", "id": e.eng.ID, "client": e.eng.Client, "dry_run": e.opts.DryRun,
	}); err != nil {
		return err
	}

	// Seed the asset graph from the authorized scope so the deterministic
	// methodology has a full frontier from cycle 1 (instead of an empty state that
	// forces the model to free-form and usually skip the deep checks).
	if seeded := seedAssets(e.eng.Scope.InScope); len(seeded) > 0 {
		n := 0
		for i := range seeded {
			a := seeded[i]
			if e.state.AddAsset(&a) {
				n++
			}
		}
		if n > 0 {
			fmt.Fprintf(e.out, "seeded %d asset(s) from scope to prime the methodology\n", n)
			e.emit(Event{Kind: "log", Message: fmt.Sprintf("seeded %d asset(s) from scope", n)})
			if err := e.rec("info", map[string]any{"event": "scope_seeded", "assets": n}); err != nil {
				return err
			}
		}
	}

	cycles := e.opts.MaxCycles
	if cycles <= 0 {
		cycles = defaultMaxCycles
	}
	noProgressLimit := e.opts.NoProgressCycleLimit
	if noProgressLimit <= 0 {
		noProgressLimit = 3
	}

	noProgress := 0
	for c := 1; c <= cycles; c++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "\n── cycle %d/%d ──\n", c, cycles)
		e.emit(Event{Kind: "cycle", Cycle: c})

		// Signal that the planner (local model) is now thinking. On a slow CPU model
		// this call can take a while; without this the live feed looks frozen between
		// a cycle marker and the first action. The UI renders it as a "thinking" state.
		e.emit(Event{Kind: "planning", Cycle: c, Message: "deciding the next actions…"})
		actions, err := e.planner.Plan(ctx, e.eng, e.state, e.tools.Names(), e.scratch)
		if err != nil {
			e.emit(Event{Kind: "error", Cycle: c, Message: fmt.Sprintf("planner error: %v", err)})
			return fmt.Errorf("cycle %d: %w", c, err)
		}
		if len(actions) == 0 {
			fmt.Fprintln(e.out, "planner proposed no further actions; stopping.")
			e.emit(Event{Kind: "log", Message: "planner proposed no further actions; stopping"})
			break
		}

		cycleProgress, err := e.runCycle(ctx, actions)
		if err != nil {
			return err
		}

		// Deterministic termination: a cycle that discovers nothing new and runs
		// no novel action counts as no-progress; halt after the limit so the loop
		// can't spin forever on duplicate or blocked proposals.
		if cycleProgress {
			noProgress = 0
			continue
		}
		noProgress++
		if noProgress >= noProgressLimit {
			fmt.Fprintf(e.out, "no progress for %d cycle(s); halting.\n", noProgress)
			if err := e.rec("no_progress_halt", map[string]any{"cycle": c, "limit": noProgressLimit}); err != nil {
				return err
			}
			break
		}
	}

	if err := e.rec("info", map[string]any{"event": "engagement_end", "id": e.eng.ID}); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "\naudit head: %s\n", e.audit.Head())
	e.emit(Event{Kind: "done", Message: "audit head " + e.audit.Head()})
	return nil
}

// admitted carries an action that survived the serial ADMIT phase (deduped,
// guard-allowed, approved, params injected) into the concurrent EXECUTE phase and
// then the serial COMMIT phase. The slot index preserves planner order across the
// concurrent fan-out so COMMIT applies results back in the original sequence.
type admitted struct {
	a    action.Action
	tool tool.Tool
	res  action.Result // filled by EXECUTE
	err  error         // execution error (non-cancellation), surfaced in COMMIT
}

// runCycle drives one plan/act cycle through three phases:
//
//	ADMIT   (serial, planner order) — dedup, guard.Evaluate, decision audit, and
//	          approval gating. All decision-side audit records and the e.seen
//	          dedup happen here, in planner order, exactly as before.
//	EXECUTE (concurrent) — admitted actions run via errgroup, each gated by the
//	          throttle semaphore (so MaxConcurrent still caps in-flight work). Only
//	          per-slot fields are touched, so no shared state races.
//	COMMIT  (serial, planner order) — results fold into state/sessions/scratch and
//	          the result-side audit, in the original planner order.
//
// It returns whether the cycle made progress, preserving the no-progress
// termination contract exactly (a cycle is progress iff any committed action ran
// a novel action successfully or discovered a new asset/finding/credential).
func (e *Engine) runCycle(ctx context.Context, actions []action.Action) (bool, error) {
	// ── ADMIT (serial, planner order) ───────────────────────────────────────────
	admit := make([]*admitted, 0, len(actions))
	for _, a := range actions {
		ad, err := e.admit(ctx, a)
		if err != nil {
			return false, err
		}
		if ad != nil {
			admit = append(admit, ad)
		}
	}

	// ── EXECUTE (concurrent, throttle-gated) ────────────────────────────────────
	// Each admitted action writes only its own slot (res/err); nothing shared is
	// mutated here, so the fan-out is race-free. The throttle's semaphore enforces
	// the RoE MaxConcurrent cap across all in-flight executions.
	if len(admit) > 0 {
		g, gctx := errgroup.WithContext(ctx)
		for _, ad := range admit {
			ad := ad
			g.Go(func() error {
				release, err := e.throttle.acquire(gctx, ad.a.Target)
				if err != nil {
					return err // context cancelled / deadline during pacing
				}
				defer release()
				res, err := ad.tool.Execute(gctx, ad.a)
				ad.res = res
				ad.err = err
				if err != nil && gctx.Err() != nil {
					return gctx.Err() // cancellation aborts the whole cycle
				}
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return false, err
		}
	}

	// ── COMMIT (serial, planner order) ──────────────────────────────────────────
	cycleProgress := false
	for _, ad := range admit {
		progressed, err := e.commit(ad)
		if err != nil {
			return false, err
		}
		if progressed {
			cycleProgress = true
		}
	}
	return cycleProgress, nil
}

// admit runs one action through dedup + the guard + approval gating, all SERIAL
// and in planner order. It returns a non-nil *admitted only for actions that must
// proceed to concurrent execution; nil means the action was skipped/denied/held/
// dry-run here (the decision audit and scratchpad were already recorded). The
// error return is reserved for audit-write failures and a cancelled approver.
func (e *Engine) admit(ctx context.Context, a action.Action) (*admitted, error) {
	// Deduplicate first (cheapest check): an action we've already handled this run
	// never re-executes, and counts as no progress. Dedup precedes the guard, so a
	// previously-denied action also won't be retried.
	key := a.CanonicalKey()
	if e.seen[key] {
		fmt.Fprintf(e.out, "  SKIP  %-12s %-22s — duplicate of an earlier action\n", a.Tool, a.Target)
		return nil, e.rec("duplicate_action_skipped", map[string]any{
			"action": a.ID, "tool": a.Tool, "target": a.Target, "key": key,
		})
	}
	e.seen[key] = true
	e.emit(Event{Kind: "action", Tool: a.Tool, Target: a.Target, Message: a.Rationale})

	dec := e.guard.Evaluate(a)
	// a.Category / a.Risk are the model's SELF-DECLARED values, recorded for
	// audit only; the guard gates on authoritative tool metadata.
	if err := e.rec("decision", map[string]any{
		"action": a.ID, "tool": a.Tool, "declared_category": a.Category,
		"target": a.Target, "declared_risk": a.Risk.String(),
		"verdict": dec.Verdict.String(), "allowed": dec.IsAllowed(), "reason": dec.Reason,
	}); err != nil {
		return nil, err
	}
	e.emit(Event{Kind: "decision", Tool: a.Tool, Target: a.Target, Verdict: dec.Verdict.String(), Reason: dec.Reason})

	switch dec.Verdict {
	case guard.VerdictDeny:
		fmt.Fprintf(e.out, "  DENY  %-12s %-22s — %s\n", a.Tool, a.Target, dec.Reason)
		e.scratch.Record(planner.Attempt{Tool: a.Tool, Target: a.Target, Verdict: "deny", Reason: dec.Reason})
		return nil, nil
	case guard.VerdictRequireApproval:
		// Human-approval UX lands in a later phase; until then, fail safe by not
		// executing and recording that approval was required.
		fmt.Fprintf(e.out, "  HOLD  %-12s %-22s — needs approval: %s\n", a.Tool, a.Target, dec.Reason)
		e.scratch.Record(planner.Attempt{Tool: a.Tool, Target: a.Target, Verdict: "require_approval", Reason: dec.Reason})
		return nil, e.rec("approval_required", map[string]any{
			"action": a.ID, "tool": a.Tool, "target": a.Target, "reason": dec.Reason,
		})
	}
	// VerdictAllow falls through.

	if e.opts.DryRun {
		fmt.Fprintf(e.out, "  ALLOW %-12s %-22s [dry-run] %s\n", a.Tool, a.Target, a.Rationale)
		return nil, nil
	}

	t, ok := e.tools.Get(a.Tool)
	if !ok {
		fmt.Fprintf(e.out, "  SKIP  %-12s %-22s — no such tool registered\n", a.Tool, a.Target)
		return nil, e.rec("result", map[string]any{"action": a.ID, "skipped": "unknown tool"})
	}

	// Human-in-the-loop: a high-impact action (exploit/identity tool or RiskHigh)
	// pauses for explicit operator approval when RequireApproval is on. In addition,
	// a tool may FORCE approval for a specific action via ApprovalGater (the kali
	// arsenal tool does this for any non-read-only command) — so arbitrary commands
	// always wait for an operator click regardless of the global setting. Approval
	// is serial (it may block on an operator) and mutates the audit, so it stays in
	// ADMIT, before the concurrent execute phase.
	forceApproval := false
	if g, ok := t.(tool.ApprovalGater); ok {
		forceApproval = g.NeedsApproval(a.Params)
	}
	if forceApproval || (e.opts.RequireApproval && highImpact(t)) {
		approved := false
		var aerr error
		if e.opts.Approver != nil {
			fmt.Fprintf(e.out, "  WAIT  %-12s %-22s — awaiting approval\n", a.Tool, a.Target)
			approved, aerr = e.opts.Approver(ctx, a)
			if aerr != nil {
				return nil, aerr
			}
		}
		if rerr := e.audit.RecordApproval(audit.Approval{
			Approver: "operator", ActionID: a.ID,
			GuardReason: fmt.Sprintf("high-impact %s/%s", t.Category(), t.MaxRisk()), Approved: approved,
		}); rerr != nil {
			return nil, rerr
		}
		if !approved {
			fmt.Fprintf(e.out, "  DENY  %-12s %-22s — operator declined\n", a.Tool, a.Target)
			e.emit(Event{Kind: "decision", Action: a.ID, Tool: a.Tool, Target: a.Target, Verdict: "denied", Reason: "operator declined"})
			return nil, nil
		}
		fmt.Fprintf(e.out, "  OK    %-12s %-22s — operator approved\n", a.Tool, a.Target)
	}

	if err := e.rec("action", map[string]any{
		"action": a.ID, "tool": a.Tool, "target": a.Target, "params": a.Params,
	}); err != nil {
		return nil, err
	}

	// Inject any established session for this target's host so the tool runs
	// authenticated (tools that support it attach a.Cookie to their requests).
	// Sessions are read here in ADMIT (serial) and written back in COMMIT (serial),
	// so the e.sessions map is never touched from a concurrent goroutine.
	if c := e.sessions[engagementHost(a.Target)]; c != "" {
		a.Cookie = c
	}

	// For the login tool, fill credentials from a matching provisioned credential
	// when the planner didn't supply them.
	if a.Tool == "login" {
		if pc, ok := e.eng.ProvisionedFor(a.Target); ok {
			merged := map[string]string{"username": pc.Username, "password": pc.Secret}
			if pc.LoginURL != "" {
				merged["login_url"] = pc.LoginURL
			}
			if pc.Mode != "" {
				merged["mode"] = pc.Mode
			}
			for k, v := range a.Params { // planner-supplied params win
				merged[k] = v
			}
			a.Params = merged
		}
	}

	// The AD/identity adapters authenticate to the directory with provisioned
	// domain credentials (Kerberoasting needs an authenticated bind; LDAP enum
	// gets far more with one). Inject a matching provisioned credential as
	// username/password when the planner didn't supply them.
	if a.Tool == "ldapenum" || a.Tool == "kerberoast" {
		if pc, ok := e.eng.ProvisionedFor(a.Target); ok {
			merged := map[string]string{"username": pc.Username, "password": pc.Secret}
			for k, v := range a.Params { // planner-supplied params win
				merged[k] = v
			}
			a.Params = merged
		}
	}

	return &admitted{a: a, tool: t}, nil
}

// commit folds one executed action's result back into shared state, in the
// SERIAL COMMIT phase and in original planner order: state mutations, session
// capture, the scratchpad note, and the result-side audit all happen here so
// their ordering is deterministic regardless of how EXECUTE interleaved. It
// reports whether the action made progress (novel success, or a new asset/
// finding/credential) for the no-progress termination contract.
func (e *Engine) commit(ad *admitted) (bool, error) {
	a, res := ad.a, ad.res
	if ad.err != nil {
		fmt.Fprintf(e.out, "  ERROR %-12s %-22s — %v\n", a.Tool, a.Target, ad.err)
	}
	newFinding := false
	for _, f := range res.Findings {
		if e.state.AddFinding(f) {
			newFinding = true
			e.emit(Event{Kind: "finding", Severity: f.Severity.String(), Title: f.Title, Target: f.Target, Tool: f.Tool})
		}
	}
	newAsset := false
	for i := range res.Assets {
		asset := res.Assets[i]
		if e.state.AddAsset(&asset) {
			newAsset = true
		}
	}
	newCred := false
	for _, c := range res.Credentials {
		if e.state.AddCredential(c) {
			newCred = true
			// Audit the recovery, but REDACTED — never the plaintext secret.
			if err := e.rec("credential", c.Redacted()); err != nil {
				return false, err
			}
		}
	}
	// Capture an established session so later actions against the host inherit it.
	if res.Session != nil && res.Session.Cookie != "" {
		// Key by bare host (port-stripped) so later actions on any port of the same
		// host inherit the session — matches the lookup in the inject step above.
		e.sessions[engagementHost(res.Session.Host)] = res.Session.Cookie
		if err := e.rec("session_established", map[string]any{"host": res.Session.Host, "action": a.ID}); err != nil {
			return false, err
		}
	}
	if err := e.rec("result", map[string]any{
		"action": a.ID, "success": res.Success, "output": res.Output,
		"findings": len(res.Findings), "assets": len(res.Assets),
	}); err != nil {
		return false, err
	}
	if res.Output != "" {
		fmt.Fprintf(e.out, "  DONE  %-12s %-22s — %s\n", a.Tool, a.Target, res.Output)
	}
	e.emit(Event{Kind: "result", Tool: a.Tool, Target: a.Target, Message: res.Output})
	// Remember this ran (with a short outcome) so the planner won't re-propose it.
	e.scratch.Record(planner.Attempt{Tool: a.Tool, Target: a.Target, Verdict: "allow", Outcome: outcomeSummary(res, newFinding)})
	// Progress = a novel action that ran successfully, or any new asset/finding/cred.
	return res.Success || newFinding || newAsset || newCred, nil
}

// outcomeSummary is a short human note of what an action produced, for the
// planner's scratchpad ("3 finding(s)", "no new findings", "error").
func outcomeSummary(res action.Result, newFinding bool) string {
	if res.Err != "" && len(res.Findings) == 0 {
		return "error/no result"
	}
	if len(res.Findings) > 0 {
		if newFinding {
			return fmt.Sprintf("%d finding(s)", len(res.Findings))
		}
		return "findings (already known)"
	}
	return "no findings"
}
