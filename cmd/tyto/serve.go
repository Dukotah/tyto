package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/engine"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/methodology"
	"github.com/dukotah/tyto/internal/planner"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/report"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/sysinfo"
	"github.com/dukotah/tyto/internal/tool/adapter"
	"github.com/dukotah/tyto/internal/tool/builtin/shell"
	"github.com/dukotah/tyto/internal/validate"
	"github.com/dukotah/tyto/internal/webui"
)

// console is the in-memory state behind the operational web dashboard: the
// active run's engagement/state, a captured audit trail, and the live event hub
// that streams the plan->guard->execute loop to connected browsers.
type console struct {
	mu        sync.Mutex
	running   bool
	eng       *engagement.Engagement
	st        *state.State
	auditBuf  *safeBuffer
	subs      map[chan engine.Event]struct{}
	history   []engine.Event
	ollamaURL string
	// model overrides the local model used for chat AND planning. Empty = fall
	// back to $TYTO_MODEL, then the RAM-aware default. Set via serve --model so a
	// faster model (e.g. qwen2.5-coder:7b) can drive snappier interactive loops.
	model string
	// pending holds approval channels keyed by action ID while a run is paused
	// awaiting an operator decision (human-in-the-loop mode).
	pending map[string]chan bool
	// runCancel cancels the in-progress run (used by /api/stop).
	runCancel context.CancelFunc
	// pendingShell holds an arbitrary (non-read-only) shell command the assistant
	// proposed and is waiting for the operator to confirm before running on the
	// local Kali host. Empty when nothing is awaiting confirmation.
	pendingShell string
	// operatorCancel cancels the autonomous operator loop (nil when none runs).
	operatorCancel context.CancelFunc
	// operatorFreeRun, when true, lets the operator loop run arbitrary (mutating)
	// local commands unattended. Default false: only read-only toolbox commands
	// run on their own; this is the explicit "I'm present and accountable" switch.
	operatorFreeRun bool
	// pendingPentest holds a target+depth the assistant proposed and is waiting for
	// the operator to confirm authorization before launching an ad-hoc engagement.
	pendingPentest *pentestReq
	// pendingScope holds a self-attested engagement built from a pasted bug-bounty
	// program's scope, waiting for the operator to confirm ingestion. A mis-parsed
	// scope must never auto-run, so this mirrors pendingPentest's confirm gate.
	pendingScope *engagement.Engagement
	// authorizedTargets remembers targets the operator has already confirmed
	// authorization for THIS session, keyed by normalized target. A repeat request
	// for the same target skips the confirm gate — the operator attests once, not
	// every time they mention it down the chat. The first confirmation is still
	// recorded in the engagement's authorization record + audit trail.
	authorizedTargets map[string]bool
	// runSessions is a snapshot of the host→session-cookie map from the most recent
	// run, captured at run end so the submission report's adversarial re-proof can
	// re-fetch authenticated (see handleReport / runEngagement).
	runSessions map[string]string
}

// normTarget canonicalizes a target for the authorized-once set: lowercased,
// scheme and any path/query stripped, so "https://x.com/", "x.com", and
// "HTTP://X.com/a" all map to one key.
func normTarget(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	return strings.TrimSuffix(t, ".")
}

// rememberAuthorized records that the operator confirmed authorization for a
// target this session, so future requests for it skip the confirm gate.
func (c *console) rememberAuthorized(target string) {
	k := normTarget(target)
	if k == "" {
		return
	}
	c.mu.Lock()
	if c.authorizedTargets == nil {
		c.authorizedTargets = map[string]bool{}
	}
	c.authorizedTargets[k] = true
	c.mu.Unlock()
}

// isAuthorized reports whether the operator already attested authorization for a
// target this session.
func (c *console) isAuthorized(target string) bool {
	k := normTarget(target)
	if k == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authorizedTargets[k]
}

func newServeCmd() *cobra.Command {
	c := &console{subs: map[chan engine.Event]struct{}{}, pending: map[string]chan bool{}}
	var addr string
	var execSpec string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the operational web console (drive + monitor engagements in a browser)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Select where tools run. Explicit --exec/$TYTO_EXEC wins; otherwise, on
			// Windows, auto-route to a detected Kali WSL distro so the agent drives
			// real Kali out of the box. Inside Kali (linux) the default host backend
			// is already correct.
			spec := strings.TrimSpace(execSpec)
			if spec == "" {
				spec = strings.TrimSpace(os.Getenv("TYTO_EXEC"))
			}
			if spec == "" && runtime.GOOS == "windows" {
				if d := detectKaliWSL(); d != "" {
					spec = "wsl:" + d
				}
			}
			if err := adapter.Configure(spec); err != nil {
				return err
			}
			if b := adapter.Backend(); b != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "tool execution backend: %s (tools run in Kali)\n", b)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "tool execution backend: host (tyto runs where its tools are)")
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				// Never let the browser cache the console: the embedded page changes with
				// every build, and a stale copy would silently miss live-feed fixes.
				w.Header().Set("Cache-Control", "no-store, must-revalidate")
				_, _ = w.Write(webui.Index)
			})
			mux.HandleFunc("/api/status", c.handleStatus)
			mux.HandleFunc("/api/engagements", c.handleEngagements)
			mux.HandleFunc("/api/engagements/create", c.handleCreateEngagement)
			mux.HandleFunc("/api/engagements/delete", c.handleDeleteEngagement)
			mux.HandleFunc("/api/tools", c.handleTools)
			mux.HandleFunc("/api/methodology", c.handleMethodology)
			mux.HandleFunc("/api/run", c.handleRun)
			mux.HandleFunc("/api/stop", c.handleStop)
			mux.HandleFunc("/api/clear", c.handleClear)
			mux.HandleFunc("/api/approve", c.handleApprove)
			mux.HandleFunc("/api/chat", c.handleChat)
			mux.HandleFunc("/api/events", c.handleEvents)
			mux.HandleFunc("/api/findings", c.handleFindings)
			mux.HandleFunc("/api/report", c.handleReport)
			mux.HandleFunc("/api/audit", c.handleAudit)

			fmt.Fprintf(cmd.OutOrStdout(), "tyto console live → http://%s   (Ctrl-C to stop)\n", addr)
			return http.ListenAndServe(addr, mux)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8088", "listen address")
	cmd.Flags().StringVar(&c.ollamaURL, "ollama-url", "http://localhost:11434", "ollama base URL (for the local-model planner)")
	cmd.Flags().StringVar(&c.model, "model", "", "local model for chat + planning (default: $TYTO_MODEL or a RAM-aware pick; e.g. qwen2.5-coder:7b for speed)")
	cmd.Flags().StringVar(&execSpec, "exec", "", `where tools run: ""=host, "wsl:<distro>"=a WSL distro (auto-detects Kali on Windows)`)
	return cmd
}

// detectKaliWSL returns the name of an installed Kali WSL distro, or "" if none.
// `wsl -l -q` emits UTF-16 with NULs; strip them and match case-insensitively.
func detectKaliWSL() string {
	out, err := exec.Command("wsl", "-l", "-q").Output()
	if err != nil {
		return ""
	}
	s := strings.ReplaceAll(string(out), "\x00", "")
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(strings.Trim(line, "\r"))
		if l != "" && strings.Contains(strings.ToLower(l), "kali") {
			return l
		}
	}
	return ""
}

// --- event hub -------------------------------------------------------------

func (c *console) broadcast(ev engine.Event) {
	c.mu.Lock()
	c.history = append(c.history, ev)
	if len(c.history) > 3000 {
		c.history = c.history[len(c.history)-3000:]
	}
	for ch := range c.subs {
		select {
		case ch <- ev:
		default: // slow client: drop rather than block the run goroutine
		}
	}
	c.mu.Unlock()
}

func (c *console) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan engine.Event, 512)
	c.mu.Lock()
	c.subs[ch] = struct{}{}
	hist := append([]engine.Event(nil), c.history...)
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.subs, ch); c.mu.Unlock() }()

	send := func(ev engine.Event) {
		b, _ := json.Marshal(ev)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
	for _, ev := range hist {
		send(ev)
	}
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			send(ev)
		}
	}
}

// --- run orchestration -----------------------------------------------------

type runReq struct {
	Engagement      string `json:"engagement"`
	Planner         string `json:"planner"`
	Cycles          int    `json:"cycles"`
	Depth           string `json:"depth"` // per-run risk dial; tightens the engagement's RoE down for this run
	DryRun          bool   `json:"dryRun"`
	Objective       string `json:"objective"`
	RequireApproval bool   `json:"requireApproval"`
}

// approve blocks until the operator approves/denies the action via /api/approve
// (or the run context is cancelled). It's the engine's Approver in HITL mode.
func (c *console) approve(ctx context.Context, a action.Action) (bool, error) {
	ch := make(chan bool, 1)
	c.mu.Lock()
	c.pending[a.ID] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, a.ID); c.mu.Unlock() }()

	// Surface the exact command for arbitrary-command tools (kali/shell) so the
	// operator approves what will ACTUALLY run, not just a rationale.
	msg := a.Rationale
	if cmd := strings.TrimSpace(a.Params["command"]); cmd != "" {
		msg = "$ " + cmd
		if a.Rationale != "" {
			msg += "\n" + a.Rationale
		}
	}
	c.broadcast(engine.Event{
		Kind: "approval_required", Action: a.ID, Tool: a.Tool, Target: a.Target,
		Message: msg, Time: time.Now().UTC(),
	})
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case ok := <-ch:
		return ok, nil
	}
}

func (c *console) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Action   string `json:"action"`
		Approved bool   `json:"approved"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"error": "bad request"})
		return
	}
	c.mu.Lock()
	ch := c.pending[req.Action]
	c.mu.Unlock()
	if ch == nil {
		writeJSON(w, map[string]any{"error": "no pending approval for that action"})
		return
	}
	select {
	case ch <- req.Approved:
	default:
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (c *console) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req runReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"error": "bad request: " + err.Error()})
		return
	}

	if errMsg := c.startRun(req.Engagement, req.Objective, req.Planner, req.Cycles, req.Depth, req.DryRun, req.RequireApproval); errMsg != "" {
		writeJSON(w, map[string]any{"error": errMsg})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// startRun loads an engagement and launches the autonomous run goroutine. Shared
// by the Run form (handleRun) and the agentic chat (handleChat). The objective
// becomes the model's top-priority instruction; the guard still gates every
// action against the engagement's authorized scope. Returns "" on success.
func (c *console) startRun(engPath, objective, planner string, cycles int, depth string, dryRun, requireApproval bool) string {
	if strings.TrimSpace(engPath) == "" {
		return "no engagement selected"
	}
	eng, err := engagement.Load(engPath)
	if err != nil {
		return "load engagement: " + err.Error()
	}
	return c.launchEngagement(eng, objective, planner, cycles, depth, dryRun, requireApproval)
}

// launchEngagement starts the autonomous run goroutine for an already-built
// engagement (loaded from disk by startRun, or constructed on the fly by the
// conversational pentest on-ramp). The objective becomes the model's top-priority
// instruction; the guard still gates every action against the engagement's scope.
// Returns "" on success.
func (c *console) launchEngagement(eng *engagement.Engagement, objective, planner string, cycles int, depth string, dryRun, requireApproval bool) string {
	c.mu.Lock()
	already := c.running
	c.mu.Unlock()
	if already {
		return "a run is already in progress"
	}
	if obj := strings.TrimSpace(objective); obj != "" {
		eng.Objectives = append([]string{"OPERATOR INSTRUCTION (top priority): " + obj}, eng.Objectives...)
	}
	client, err := c.plannerClient(runReq{Planner: planner}, eng)
	if err != nil {
		return err.Error()
	}
	if cycles <= 0 {
		cycles = 3
	}
	st := state.New()
	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.eng, c.st, c.auditBuf, c.history, c.running, c.runCancel = eng, st, &safeBuffer{}, nil, true, cancel
	c.mu.Unlock()
	go c.runEngagement(ctx, eng, st, client, cycles, depth, dryRun, requireApproval)
	return ""
}

func (c *console) plannerClient(req runReq, eng *engagement.Engagement) (llm.Client, error) {
	kind := req.Planner
	if kind == "" {
		kind = "scripted"
	}
	switch kind {
	case "mock":
		return llm.NewDemoMock(), nil
	case "scripted":
		var targets []string
		for _, t := range eng.Scope.InScope {
			targets = append(targets, t.Value)
		}
		return llm.NewScriptedMock(targets), nil
	case "ollama":
		return llm.NewOllama(c.ollamaURL, c.resolveModel()), nil
	default:
		return nil, fmt.Errorf("unknown planner %q (want scripted|mock|ollama)", kind)
	}
}

func (c *console) runEngagement(ctx context.Context, eng *engagement.Engagement, st *state.State, client llm.Client, cycles int, depth string, dryRun, requireApproval bool) {
	defer func() {
		c.mu.Lock()
		c.running = false
		c.runCancel = nil
		c.mu.Unlock()
	}()

	// Verify the client signature against the ORIGINAL (signed) engagement before
	// any per-run tightening — lowering max_risk/categories changes the canonical
	// bytes and would (correctly) fail verification.
	grants, err := eng.VerifiedGrants()
	if err != nil {
		c.broadcast(engine.Event{Kind: "error", Message: "authorization: " + err.Error()})
		c.broadcast(engine.Event{Kind: "done"})
		return
	}
	reg := defaultRegistry()
	alog := audit.NewLog(c.auditBuf)
	_ = alog.Record("authorization", map[string]any{
		"scope_hash": eng.ScopeHash(), "verified_grants": len(grants),
		"mode": authMode(eng), "authorized_by": eng.Authorization.AuthorizedBy,
		"agreement_ref": eng.Authorization.AgreementRef,
	})

	// Per-run "risk dial": tighten the engagement's RoE DOWN to the chosen depth
	// (intersect categories, take the lower risk ceiling). Tightening only — it never
	// widens past the authorized/signed ceiling — so the verified grants still apply.
	// Done after verification + audit so the recorded scope_hash reflects the signed
	// scope, not the per-run narrowing.
	if d := strings.TrimSpace(depth); d != "" {
		allowed, maxRisk, norm := profileFor(d)
		eng.RoE.AllowedCategories = intersectCats(eng.RoE.AllowedCategories, allowed)
		if lower, ok := lowerRisk(eng.RoE.MaxRisk, maxRisk); ok {
			eng.RoE.MaxRisk = lower
		}
		c.broadcast(engine.Event{
			Kind: "log", Time: time.Now().UTC(),
			Message: "run depth: " + norm + "  (≤ " + eng.RoE.MaxRisk + " risk; " + strings.Join(eng.RoE.AllowedCategories, "/") + ")",
		})
	}

	eg := engine.New(eng, guard.New(eng, toolSnapshot(reg), grants).WithClassifier(defaultClassifier()), planner.New(client),
		reg, st, alog, io.Discard, engine.Options{
			DryRun: dryRun, MaxCycles: cycles, OnEvent: c.broadcast,
			RequireApproval: requireApproval, Approver: c.approve,
		})

	// ctx is cancelable via /api/stop; the run otherwise continues even if the
	// launching browser tab closes.
	if err := eg.Run(ctx); err != nil {
		c.broadcast(engine.Event{Kind: "error", Message: err.Error()})
		c.broadcast(engine.Event{Kind: "done"})
	}

	// Capture the run's established sessions so the submission report's adversarial
	// re-proof (handleReport) runs with the SAME authentication the scan had — an
	// authenticated-only finding would otherwise be re-fetched logged-out and
	// wrongly refuted. Kept on the console because the engine is gone by report time.
	c.mu.Lock()
	c.runSessions = eg.Sessions()
	c.mu.Unlock()
}

// handleStop cancels an in-progress run.
func (c *console) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c.mu.Lock()
	cancel, running, opCancel := c.runCancel, c.running, c.operatorCancel
	c.mu.Unlock()
	if opCancel != nil {
		opCancel()
		c.broadcast(engine.Event{Kind: "log", Message: "operator loop stopped", Time: time.Now().UTC()})
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	if running && cancel != nil {
		cancel()
		c.broadcast(engine.Event{Kind: "log", Message: "operator requested stop", Time: time.Now().UTC()})
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	writeJSON(w, map[string]any{"ok": false, "error": "no run in progress"})
}

// handleClear resets the live engagement view to a clean slate: findings,
// assets, credentials, the activity feed, and the in-memory audit buffer are
// all dropped so the operator can start fresh without restarting the server.
// It refuses while a run is in progress (clearing mid-run would race the
// engine's state writes and orphan the audit trail) — stop the run first. The
// engagement selection itself is preserved; only the run's accumulated results
// are cleared. The persisted audit log on disk is untouched.
func (c *console) handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		writeJSON(w, map[string]any{"ok": false, "error": "a run is in progress — stop it before clearing"})
		return
	}
	c.st = state.New()
	c.history = nil
	c.auditBuf = &safeBuffer{}
	c.mu.Unlock()

	c.broadcast(engine.Event{Kind: "cleared", Message: "findings and activity cleared", Time: time.Now().UTC()})
	writeJSON(w, map[string]any{"ok": true})
}

// handleChat is an engagement-aware assistant: the operator can ask about
// findings and next steps in plain language. It feeds the LOCAL model a safe
// projection of the live engagement state (finding titles/severities/targets +
// asset/cred counts — never raw evidence/secrets), so answers reflect what the
// run has actually found, even mid-engagement.
func (c *console) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Message string `json:"message"`
		History []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"history"`
		// Engagement is tolerant: the UI's /api/status projection makes it an object
		// once a run exists, but older callers send a string. RawMessage decodes
		// either without failing the whole request; engStr below pulls the string form.
		Engagement      json.RawMessage `json:"engagement"`
		Depth           string          `json:"depth"`
		RequireApproval bool            `json:"requireApproval"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Message) == "" {
		writeJSON(w, map[string]any{"error": "empty or malformed message"})
		return
	}
	// Pull a string engagement path if one was sent as a JSON string; anything
	// else (object, null, absent) yields "" — the chat flows that need an
	// engagement build their own, so this is only the optional "run loaded" path.
	var engStr string
	if len(req.Engagement) > 0 {
		_ = json.Unmarshal(req.Engagement, &engStr)
	}

	// Fast path: control commands must never wait on the model (which may be busy
	// planning a running engagement). Handle stop/halt directly.
	msg := strings.ToLower(strings.TrimSpace(req.Message))
	if msg == "stop" || msg == "halt" || msg == "cancel" || msg == "abort" || msg == "pause" ||
		strings.HasPrefix(msg, "stop ") || strings.HasPrefix(msg, "halt ") || strings.Contains(msg, "stop the") {
		c.mu.Lock()
		runCancel, opCancel := c.runCancel, c.operatorCancel
		c.mu.Unlock()
		switch {
		case opCancel != nil:
			opCancel()
			writeJSON(w, map[string]any{"reply": "Stopping the operator.", "stopped": true})
		case runCancel != nil:
			runCancel()
			writeJSON(w, map[string]any{"reply": "Stopping the run.", "stopped": true})
		default:
			writeJSON(w, map[string]any{"reply": "Nothing is running right now."})
		}
		return
	}

	// Fast path: toggle the operator loop's free-run gate. Off by default; this is
	// the explicit "I'm present and accountable — run what you need on the box" switch.
	switch msg {
	case "free run", "free-run", "free roam", "unlock", "go autonomous", "full autonomy":
		c.mu.Lock()
		c.operatorFreeRun = true
		c.mu.Unlock()
		writeJSON(w, map[string]any{"reply": "Free-run is ON — the operator can run arbitrary commands on the box. Say 'lock down' to revert."})
		return
	case "lock down", "lockdown", "read only", "read-only", "lock":
		c.mu.Lock()
		c.operatorFreeRun = false
		c.mu.Unlock()
		writeJSON(w, map[string]any{"reply": "Locked down — only read-only toolbox commands run unattended now."})
		return
	}

	// Fast path: a previously-proposed arbitrary shell command is awaiting the
	// operator's yes/no. Resolve it here so confirmation never depends on the
	// model re-deriving the exact command from history.
	c.mu.Lock()
	pend := c.pendingShell
	c.mu.Unlock()
	if pend != "" {
		switch {
		case isAffirmative(msg):
			c.mu.Lock()
			c.pendingShell = ""
			c.mu.Unlock()
			out, ok := c.runShell(r.Context(), pend)
			writeJSON(w, map[string]any{"reply": formatShellReply(pend, out, ok), "ran": true})
			return
		case isNegative(msg):
			c.mu.Lock()
			c.pendingShell = ""
			c.mu.Unlock()
			writeJSON(w, map[string]any{"reply": "Okay — left it alone."})
			return
		default:
			// Operator moved on; drop the pending command and handle normally.
			c.mu.Lock()
			c.pendingShell = ""
			c.mu.Unlock()
		}
	}

	// Fast path: a pasted bug-bounty scope is parsed and awaiting the operator's
	// confirm-to-ingest yes/no. Resolve here so the (potentially large, multi-target)
	// engagement is committed exactly as previewed — never re-derived from history,
	// and never auto-launched.
	c.mu.Lock()
	ps := c.pendingScope
	c.mu.Unlock()
	if ps != nil {
		switch {
		case isAffirmative(msg):
			c.mu.Lock()
			c.pendingScope = nil
			c.mu.Unlock()
			reply, ok := c.commitScopeEngagement(ps)
			writeJSON(w, map[string]any{"reply": reply, "ingested": ok})
			return
		case isNegative(msg):
			c.mu.Lock()
			c.pendingScope = nil
			c.mu.Unlock()
			writeJSON(w, map[string]any{"reply": "Discarded that scope — nothing was set up."})
			return
		default:
			c.mu.Lock()
			c.pendingScope = nil
			c.mu.Unlock()
		}
	}

	// Fast path: an ad-hoc pentest is awaiting the operator's authorization yes/no.
	c.mu.Lock()
	pp := c.pendingPentest
	c.mu.Unlock()
	if pp != nil {
		switch {
		case isAffirmative(msg):
			c.mu.Lock()
			c.pendingPentest = nil
			c.mu.Unlock()
			reply, started := c.launchPentest(pp.Target, pp.Depth)
			writeJSON(w, map[string]any{"reply": reply, "started": started})
			return
		case isNegative(msg):
			c.mu.Lock()
			c.pendingPentest = nil
			c.mu.Unlock()
			writeJSON(w, map[string]any{"reply": "Standing down — nothing launched."})
			return
		default:
			c.mu.Lock()
			c.pendingPentest = nil
			c.mu.Unlock()
		}
	}

	// Fast path: a pasted bug-bounty program's scope (multi-target / scope vocab)
	// goes straight to the strict scope extractor, which builds a self-attested
	// engagement and asks for confirmation — it never launches. Detected
	// deterministically so a single "scan example.com" still takes the ad-hoc path.
	if looksLikePastedScope(req.Message) {
		writeJSON(w, c.ingestScopePaste(r.Context(), req.Message))
		return
	}

	// Fast path: "pentest/scan/recon <target>" is parsed deterministically so
	// starting a run is INSTANT — no waiting on the (CPU-bound) model just to route.
	if target, depth, ok := parsePentestIntent(req.Message); ok {
		depth, note := normalizeAdHocDepth(depth)
		// Already authorized this session → launch immediately, no re-confirm.
		if c.isAuthorized(target) {
			reply, started := c.launchPentest(target, depth)
			writeJSON(w, map[string]any{"reply": reply, "started": started})
			return
		}
		c.mu.Lock()
		c.pendingPentest = &pentestReq{Target: target, Depth: depth}
		c.pendingShell = ""
		c.mu.Unlock()
		writeJSON(w, map[string]any{
			"reply": "I'll run an authorized **" + depth + "** assessment of **" + target + "** — tools execute in Kali, the Scope Guard keeps it in bounds. " + note +
				"\n\nConfirm you're authorized to test " + target + ": reply **yes** to start, **no** to cancel.",
			"needsConfirm": true,
		})
		return
	}

	c.mu.Lock()
	eng, st := c.eng, c.st
	running := c.running
	hist := append([]engine.Event(nil), c.history...)
	c.mu.Unlock()

	client := c.newChatClient()

	// Agentic: the assistant decides whether to answer, RUN the engagement, or
	// STOP it. Running stays inside the loaded engagement's authorized scope — the
	// guard gates every action regardless of what the chat asks for.
	system := "You are tyto's operator assistant for an AUTHORIZED penetration test. You are talking " +
		"to the operator like a teammate — write replies in natural, plain language, not as a form. " +
		"Decide how to handle their latest message and reply ONLY as JSON matching the schema.\n" +
		"IMPORTANT: the word 'run' is NOT a mode signal. Choose by INTENT, not keywords:\n" +
		"mode='pentest': they name a TARGET host/IP/CIDR/domain/URL to assess/scan/pentest/attack/test — " +
		"'pentest 10.0.0.5', 'scan example.com', 'assess 192.168.1.0/24', 'test https://app.example.com', " +
		"'go after that box'. Put the target in 'target'. For 'depth': DEFAULT TO 'scan' (the useful " +
		"default that actually finds vulnerabilities) unless they explicitly ask for passive/recon-only " +
		"('recon'), AD/identity depth ('internal'), or exploitation to confirm findings ('full' — they say " +
		"'exploit', 'pop it', 'get a shell', 'go all the way'). I set up an authorized engagement and run the " +
		"autonomous guarded pentest in Kali — USE THIS EVEN IF NO ENGAGEMENT IS LOADED.\n" +
		"mode='shell': execute ONE specific command on the Kali box tyto runs on (its own toolbox) and show " +
		"the output — 'run uname -a', 'is rockyou here', 'what version is nmap', 'show me this file'. Put the " +
		"EXACT command in 'command'. Read-only runs immediately; mutating commands ask for confirmation.\n" +
		"mode='operate': an open-ended, MULTI-STEP task ON THE BOX (not a target) needing several commands " +
		"with reading results between — 'hunt the wordlists for likely creds', 'see what tools are installed', " +
		"'analyze this loot'. Put the task in 'objective'; it runs autonomously.\n" +
		"mode='run': ONLY to launch/continue an ALREADY-LOADED engagement with no new target named — " +
		"'start the assessment', 'begin the loaded engagement'. Put the objective in 'objective'.\n" +
		"mode='scope': they PASTED a bug-bounty program's scope/rules text — MULTIPLE in-scope " +
		"domains/wildcards (e.g. '*.example.com'), an out-of-scope list, a rate limit, and/or rules — " +
		"rather than naming a single target. This is ingestion, NOT a target to attack; I extract the " +
		"scope into a self-attested engagement and ask the operator to confirm before anything runs.\n" +
		"mode='stop': halt the running engagement or operator loop.\n" +
		"mode='answer': a question or advice with no action — put your conversational answer in 'reply'.\n" +
		"Stay within authorized scope; the guard enforces every target action.\n" +
		"AUTHORIZATION IS ALREADY ESTABLISHED AND RECORDED for the operator's targets, and the " +
		"deterministic Scope Guard independently enforces every action against the signed scope. " +
		"Therefore: NEVER add safety, legal, or ethical disclaimers; NEVER warn that testing needs " +
		"permission; NEVER tell the operator to 'ensure you are authorized' or re-confirm scope for a " +
		"target that is in scope or already confirmed; NEVER refuse an in-scope request. The operator " +
		"is a professional running an authorized engagement — answer and act directly, like a teammate, " +
		"with no caveats or hedging.\n\n" +
		"================ GROUND TRUTH (the COMPLETE, authoritative record of this engagement — " +
		"you may ONLY state what appears here) ================\n" +
		runStatus(running, hist) +
		chatContext(eng, st) +
		"\nHONESTY RULES — these override everything else:\n" +
		"1. NEVER claim a tool ran, a vulnerability was found, data/credentials/tokens were extracted, " +
		"or that you are 'currently exploiting' anything UNLESS it is explicitly listed in the record above. " +
		"Do NOT invent findings, session tokens, exploited bugs, or in-progress work. Fabricating results is " +
		"the worst possible failure — these reports get submitted to bug-bounty programs.\n" +
		"2. If RUN STATUS says COMPLETE or not started, the engine is NOT working — there is NO background " +
		"task, no scan still running, no report 'building as we go'. Say plainly that the run finished.\n" +
		"3. 'run complete' means the autonomous assessment finished. Report it as finished — never explain it " +
		"away as a sub-step of some tool that is still going.\n" +
		"4. When asked what you found, list ONLY the findings in the record above, verbatim. If there are " +
		"none, say clearly that no findings were recorded yet — do NOT speculate about what 'could' be " +
		"vulnerable as if it were confirmed.\n" +
		"5. You have no activity, memory, or knowledge of this run beyond the record above."

	var b strings.Builder
	if n := len(req.History); n > 12 {
		req.History = req.History[n-12:]
	}
	for _, m := range req.History {
		label := "Operator"
		if m.Role == "assistant" {
			label = "Assistant"
		}
		fmt.Fprintf(&b, "%s: %s\n", label, m.Content)
	}
	fmt.Fprintf(&b, "Operator: %s", req.Message)

	schema := json.RawMessage(`{"type":"object","properties":{"mode":{"type":"string","enum":["answer","pentest","run","stop","shell","operate","scope"]},"objective":{"type":"string"},"command":{"type":"string"},"target":{"type":"string"},"depth":{"type":"string","enum":["recon","scan","internal","full"]},"reply":{"type":"string"}},"required":["mode","reply"]}`)
	ctx, cancel := context.WithTimeout(r.Context(), 240*time.Second)
	defer cancel()
	raw, err := client.GenerateSchema(ctx, system, b.String(), schema)
	if err != nil {
		writeJSON(w, map[string]any{"error": "chat: " + err.Error()})
		return
	}
	var d struct {
		Mode      string `json:"mode"`
		Objective string `json:"objective"`
		Command   string `json:"command"`
		Target    string `json:"target"`
		Depth     string `json:"depth"`
		Reply     string `json:"reply"`
	}
	_ = json.Unmarshal([]byte(raw), &d)

	switch d.Mode {
	case "pentest":
		target := strings.TrimSpace(d.Target)
		if target == "" {
			writeJSON(w, map[string]any{"reply": "Which target should I assess? e.g. \"pentest 10.0.0.5\" or \"scan example.com\"."})
			return
		}
		depth, note := normalizeAdHocDepth(d.Depth)
		// Already authorized this session → launch immediately, no re-confirm.
		if c.isAuthorized(target) {
			reply, started := c.launchPentest(target, depth)
			writeJSON(w, map[string]any{"reply": reply, "started": started})
			return
		}
		c.mu.Lock()
		c.pendingPentest = &pentestReq{Target: target, Depth: depth}
		c.pendingShell = ""
		c.mu.Unlock()
		writeJSON(w, map[string]any{
			"reply": "I'll run an authorized **" + depth + "** assessment of **" + target + "** — tools execute in Kali, the Scope Guard keeps it in bounds. " + note +
				"\n\nConfirm you're authorized to test " + target + ": reply **yes** to start, **no** to cancel.",
			"needsConfirm": true,
		})
		return
	case "scope":
		// The model recognized a pasted bug-bounty program. Run the strict extractor
		// over the operator's raw message, build a self-attested engagement, and ask
		// to confirm — never launch.
		writeJSON(w, c.ingestScopePaste(r.Context(), req.Message))
		return
	case "operate":
		task := strings.TrimSpace(d.Objective)
		if task == "" {
			task = req.Message
		}
		if errMsg := c.startOperator(task); errMsg != "" {
			writeJSON(w, map[string]any{"reply": errMsg})
			return
		}
		reply := strings.TrimSpace(d.Reply)
		if reply == "" {
			reply = "On it — I'll work through this on the box. Watch me step through it live."
		}
		writeJSON(w, map[string]any{"reply": reply, "operating": true})
		return
	case "shell":
		cmd := strings.TrimSpace(d.Command)
		if cmd == "" {
			writeJSON(w, map[string]any{"reply": "Tell me the exact command to run on the Kali box."})
			return
		}
		if shell.IsReadOnly(cmd) {
			out, ok := c.runShell(r.Context(), cmd)
			writeJSON(w, map[string]any{"reply": formatShellReply(cmd, out, ok), "ran": true})
			return
		}
		// Arbitrary command — hold it and ask the operator to confirm.
		c.mu.Lock()
		c.pendingShell = cmd
		c.mu.Unlock()
		writeJSON(w, map[string]any{
			"reply":        "That runs an arbitrary command on the Kali host:\n\n    " + cmd + "\n\nReply **yes** to run it, or **no** to skip.",
			"needsConfirm": true,
		})
		return
	case "run":
		obj := strings.TrimSpace(d.Objective)
		if obj == "" {
			obj = req.Message
		}
		if errMsg := c.startRun(engStr, obj, "ollama", 3, req.Depth, false, req.RequireApproval); errMsg != "" {
			writeJSON(w, map[string]any{"reply": "I couldn't start the run: " + errMsg + ". Pick an authorized engagement on the Run tab, then ask again."})
			return
		}
		reply := strings.TrimSpace(d.Reply)
		if reply == "" {
			reply = "Starting the assessment — watch it live on the Dashboard."
		}
		writeJSON(w, map[string]any{"reply": reply, "started": true})
	case "stop":
		c.mu.Lock()
		runCancel, opCancel := c.runCancel, c.operatorCancel
		c.mu.Unlock()
		reply := strings.TrimSpace(d.Reply)
		cancelled := false
		if opCancel != nil {
			opCancel()
			cancelled = true
			if reply == "" {
				reply = "Stopping the operator."
			}
		} else if runCancel != nil {
			runCancel()
			cancelled = true
			if reply == "" {
				reply = "Stopping the run."
			}
		} else if reply == "" {
			reply = "Nothing is running right now."
		}
		writeJSON(w, map[string]any{"reply": reply, "stopped": cancelled})
	default:
		reply := strings.TrimSpace(d.Reply)
		if reply == "" {
			reply = strings.TrimSpace(raw)
		}
		writeJSON(w, map[string]any{"reply": reply})
	}
}

// newChatClient builds the local-model client used by both the chat assistant
// and the autonomous operator loop, so they share one model (RAM-aware default
// unless TYTO_MODEL overrides).
// resolveModel picks the local model: the --model flag, else $TYTO_MODEL, else a
// RAM-aware default. Shared by chat and planning so they always agree.
func (c *console) resolveModel() string {
	c.mu.Lock()
	m := strings.TrimSpace(c.model)
	c.mu.Unlock()
	if m == "" {
		m = strings.TrimSpace(os.Getenv("TYTO_MODEL"))
	}
	if m == "" {
		ram, derr := sysinfo.TotalRAMBytes()
		m = llm.DefaultModel(ram, derr == nil).Model
	}
	return m
}

func (c *console) newChatClient() llm.SchemaClient {
	c.mu.Lock()
	url := c.ollamaURL
	c.mu.Unlock()
	return llm.NewOllama(url, c.resolveModel())
}

// runShell executes one operator command on tyto's own host via the shell tool
// and returns its captured output. This path is the OPERATOR's own toolbox, not
// a client target: read-only commands are vetted by shell.IsReadOnly before they
// reach here, and arbitrary ones only arrive after explicit operator confirmation.
func (c *console) runShell(ctx context.Context, cmd string) (string, bool) {
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	res, err := shell.New().Execute(cctx, action.Action{
		Tool:   "shell",
		Target: shell.LocalTarget,
		Params: map[string]string{"command": cmd},
	})
	if err != nil {
		return err.Error(), false
	}
	out := res.Output
	if strings.TrimSpace(out) == "" {
		if res.Err != "" {
			return res.Err, res.Success
		}
		out = "(no output)"
	}
	return out, res.Success
}

// formatShellReply renders a command + its output as a chat reply, capping the
// output so a huge wordlist dump can't blow up the chat pane.
func formatShellReply(cmd, out string, ok bool) string {
	const cap = 4000
	if len(out) > cap {
		out = out[:cap] + "\n… (truncated)"
	}
	prefix := "$ " + cmd + "\n\n"
	if !ok && strings.TrimSpace(out) != "" {
		return prefix + out + "\n\n(command exited non-zero)"
	}
	return prefix + out
}

// isAffirmative / isNegative recognize a short operator confirmation so a held
// shell command can be run or dropped without another model round-trip.
func isAffirmative(msg string) bool {
	switch msg {
	case "y", "yes", "yeah", "yep", "yup", "ok", "okay", "sure", "do it", "run it",
		"go", "go ahead", "confirm", "yes run it", "run", "send it":
		return true
	}
	return strings.HasPrefix(msg, "yes") || strings.HasPrefix(msg, "run it") || strings.HasPrefix(msg, "do it")
}

func isNegative(msg string) bool {
	switch msg {
	case "n", "no", "nope", "nah", "cancel", "skip", "don't", "dont", "stop", "no don't":
		return true
	}
	return strings.HasPrefix(msg, "no")
}

// runStatus renders the AUTHORITATIVE run state for the chat model — built from
// the live event history, not the model's imagination — so it reports what
// actually happened (which tools ran, whether the engine is still going) instead
// of inventing a plausible pentest narrative. This is the guard against the chat
// model hallucinating findings/exploitation that never occurred.
func runStatus(running bool, hist []engine.Event) string {
	cycles, done := 0, false
	ran := map[string]int{}
	denied := map[string]int{}
	last := ""
	for _, ev := range hist {
		if ev.Cycle > cycles {
			cycles = ev.Cycle
		}
		switch ev.Kind {
		case "result":
			if ev.Tool != "" {
				ran[ev.Tool]++
				last = strings.TrimSpace(ev.Tool + " " + ev.Target)
			}
		case "action":
			if ev.Tool != "" && ev.Tool != "operator" {
				last = strings.TrimSpace(ev.Tool + " " + ev.Target)
			}
		case "decision":
			if strings.EqualFold(ev.Verdict, "deny") && ev.Tool != "" {
				denied[ev.Tool]++
			}
		case "done":
			done = true
		}
	}
	state := "NOT STARTED — no run is in progress"
	if running {
		state = "RUNNING right now"
	} else if done || len(ran) > 0 {
		state = "COMPLETE — the engine has finished; nothing is running in the background"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "RUN STATUS: %s. Cycles executed: %d.\n", state, cycles)
	if len(ran) > 0 {
		fmt.Fprintf(&b, "Tools that actually ran to completion: %s\n", joinCounts(ran))
	} else {
		b.WriteString("No tools have completed yet.\n")
	}
	if len(denied) > 0 {
		fmt.Fprintf(&b, "Blocked by the Scope Guard (did NOT run): %s\n", joinCounts(denied))
	}
	if last != "" {
		fmt.Fprintf(&b, "Most recent tool activity: %s\n", last)
	}
	return b.String()
}

// joinCounts renders a tool->count map as a stable "a, b(x3), c" string.
func joinCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if m[k] > 1 {
			parts = append(parts, fmt.Sprintf("%s(x%d)", k, m[k]))
		} else {
			parts = append(parts, k)
		}
	}
	return strings.Join(parts, ", ")
}

// chatContext is the safe, bounded projection of engagement state fed to the
// chat model (no raw evidence/secrets).
func chatContext(eng *engagement.Engagement, st *state.State) string {
	var b strings.Builder
	if eng != nil {
		var scope []string
		for _, t := range eng.Scope.InScope {
			scope = append(scope, t.Value)
		}
		fmt.Fprintf(&b, "Current engagement: %s for %s. In-scope: %s.\n", eng.ID, eng.Client, strings.Join(scope, ", "))
	} else {
		b.WriteString("No engagement is running yet — to start one, tell the operator to use the Run tab.\n")
	}
	if st != nil {
		fs := st.Findings()
		fmt.Fprintf(&b, "Findings so far: %d.\n", len(fs))
		for i, f := range fs {
			if i >= 25 {
				fmt.Fprintf(&b, "...and %d more.\n", len(fs)-25)
				break
			}
			fmt.Fprintf(&b, "- [%s] %s (%s)\n", f.Severity.String(), f.Title, f.Target)
		}
		fmt.Fprintf(&b, "Assets discovered: %d. Recovered credentials: %d.\n", len(st.Assets()), len(st.Credentials()))
	}
	return b.String()
}

// --- read APIs -------------------------------------------------------------

func (c *console) handleStatus(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp := map[string]any{
		"running": c.running, "engagement": nil, "findings": 0,
		"bySeverity": map[string]int{}, "assets": 0, "actions": 0, "credentials": 0,
	}
	if c.eng != nil {
		resp["engagement"] = map[string]string{"id": c.eng.ID, "client": c.eng.Client}
	}
	if c.st != nil {
		fs := c.st.Findings()
		resp["findings"] = len(fs)
		sev := map[string]int{}
		for _, f := range fs {
			sev[f.Severity.String()]++
		}
		resp["bySeverity"] = sev
		resp["assets"] = len(c.st.Assets())
		resp["credentials"] = len(c.st.Credentials())
	}
	actions := 0
	for _, ev := range c.history {
		if ev.Kind == "action" {
			actions++
		}
	}
	resp["actions"] = actions
	writeJSON(w, resp)
}

func (c *console) handleEngagements(w http.ResponseWriter, _ *http.Request) {
	out := []map[string]any{}
	seen := map[string]bool{}
	for _, pat := range []string{"*.yaml", "*.yml", "configs/*.yaml", "configs/*.yml"} {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			if seen[m] {
				continue
			}
			seen[m] = true
			eng, err := engagement.Load(m)
			if err != nil {
				continue
			}
			scope := []string{}
			inS := []map[string]string{}
			for _, t := range eng.Scope.InScope {
				scope = append(scope, t.Value)
				inS = append(inS, map[string]string{"type": string(t.Type), "value": t.Value})
			}
			outS := []map[string]string{}
			for _, t := range eng.Scope.OutOfScope {
				outS = append(outS, map[string]string{"type": string(t.Type), "value": t.Value})
			}
			cats := eng.RoE.AllowedCategories
			if cats == nil {
				cats = []string{}
			}
			out = append(out, map[string]any{
				"path": m, "id": eng.ID, "client": eng.Client, "scope": scope,
				"risk": eng.RoE.MaxRisk, "categories": cats,
				"inScope": inS, "outOfScope": outS, "depth": depthOf(cats),
			})
		}
	}
	writeJSON(w, out)
}

// profileFor maps a console "test depth" to the engagement's allowed categories
// and risk ceiling — a linear capability ladder where each step adds one tier:
//
//	recon    → recon only (OSINT/DNS), nothing intrusive
//	scan     → + active scanning, vuln detection, web testing (no exploitation)
//	internal → + Active Directory enumeration & Kerberos roasting
//	full     → + exploitation & post-exploitation to confirm findings
//
// It returns the allowed-category list, the max-risk string, and the normalized
// depth name (unknown input falls back to "scan", the safe useful default). This
// is the single source of truth shared by the create handler and its tests.
func profileFor(depth string) (allowed []string, maxRisk, normalized string) {
	switch strings.ToLower(strings.TrimSpace(depth)) {
	case "recon":
		return []string{"recon"}, "low", "recon"
	case "internal", "ad":
		return []string{"recon", "scan", "identity"}, "medium", "internal"
	case "full", "exploit":
		return []string{"recon", "scan", "identity", "exploit", "post-exploit"}, "high", "full"
	default:
		return []string{"recon", "scan"}, "medium", "scan"
	}
}

// intersectCats returns the categories present in both lists (case-insensitive),
// preserving the order of a. Used to tighten an engagement's allowed categories to
// a per-run depth without ever introducing one the engagement didn't authorize.
func intersectCats(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range b {
		set[strings.ToLower(strings.TrimSpace(x))] = true
	}
	out := []string{}
	for _, x := range a {
		if set[strings.ToLower(strings.TrimSpace(x))] {
			out = append(out, x)
		}
	}
	return out
}

// lowerRisk returns the lower of two risk-level strings (and ok=false if either
// can't be parsed, so the caller leaves the ceiling untouched). Used so the per-run
// dial can only narrow the engagement's max_risk, never raise it.
func lowerRisk(a, b string) (string, bool) {
	ra, ea := action.ParseRiskLevel(a)
	rb, eb := action.ParseRiskLevel(b)
	if ea != nil || eb != nil {
		return "", false
	}
	if rb < ra {
		return b, true
	}
	return a, true
}

// detectTargetType resolves a scope entry's type. An explicit type
// (url/domain/ip/cidr) is honored; "" or "auto" is inferred from the value
// (CIDR, then IP, then URL if it has a scheme/path, else domain).
func detectTargetType(declared, value string) (engagement.TargetType, bool) {
	switch strings.ToLower(strings.TrimSpace(declared)) {
	case "url":
		return engagement.TargetURL, true
	case "domain", "host":
		return engagement.TargetDomain, true
	case "ip":
		return engagement.TargetIP, true
	case "cidr":
		return engagement.TargetCIDR, true
	case "", "auto":
		// infer below
	default:
		return "", false
	}
	v := strings.TrimSpace(value)
	if _, _, err := net.ParseCIDR(v); err == nil {
		return engagement.TargetCIDR, true
	}
	if net.ParseIP(v) != nil {
		return engagement.TargetIP, true
	}
	if strings.Contains(v, "://") || strings.Contains(v, "/") {
		return engagement.TargetURL, true
	}
	return engagement.TargetDomain, true
}

// hostLabel extracts a bare host from a scope value (for the engagement label and
// filename slug).
func hostLabel(v string) string {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "://") {
		if pu, err := url.Parse(v); err == nil && pu.Hostname() != "" {
			return pu.Hostname()
		}
	}
	if i := strings.IndexAny(v, "/:"); i >= 0 {
		v = v[:i]
	}
	return v
}

// depthOf reverse-maps an allowed-category set to a console depth name, so the
// scope editor can preselect the right depth when editing an existing engagement.
func depthOf(cats []string) string {
	set := map[string]bool{}
	for _, c := range cats {
		set[strings.ToLower(strings.TrimSpace(c))] = true
	}
	switch {
	case set["exploit"] || set["post-exploit"]:
		return "full"
	case set["identity"]:
		return "internal"
	case set["scan"]:
		return "scan"
	default:
		return "recon"
	}
}

// handleCreateEngagement is the in-console "Add Target" path: it turns a single
// URL/host (for an asset the operator OWNS or is authorized to test) into a
// complete, self-signed engagement and writes it where the console can load it.
//
// "Fully dialed up" needs a verified client grant (the guard requires one for
// exploit-category or high-risk actions). For a third-party client the client
// signs on their own machine; for an asset you own you ARE the client, so we
// generate an ephemeral keypair, sign the engagement's canonical scope, embed the
// grant, and discard the private key (re-creating re-signs if scope changes).
func (c *console) handleCreateEngagement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	type targetReq struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	var req struct {
		URL        string      `json:"url"`        // single-target shorthand (quick add)
		Name       string      `json:"name"`       // optional label
		InScope    []targetReq `json:"inScope"`    // explicit scope-editor entries
		OutOfScope []targetReq `json:"outOfScope"` // carve-outs (always win)
		Authorized bool        `json:"authorized"`
		Depth      string      `json:"depth"`
		Replace    string      `json:"replace"` // optional engagement path to replace (edit-in-place)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"error": "bad request"})
		return
	}
	if !req.Authorized {
		writeJSON(w, map[string]any{"error": "you must confirm you own or are authorized to test these targets"})
		return
	}

	toTargets := func(list []targetReq) ([]engagement.Target, error) {
		out := make([]engagement.Target, 0, len(list))
		for _, t := range list {
			v := strings.TrimSpace(t.Value)
			if v == "" {
				continue
			}
			tt, ok := detectTargetType(t.Type, v)
			if !ok {
				return nil, fmt.Errorf("unknown target type %q for %q", t.Type, v)
			}
			out = append(out, engagement.Target{Type: tt, Value: v})
		}
		return out, nil
	}

	inScope, err := toTargets(req.InScope)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	// URL shorthand when no explicit in-scope list was supplied (the quick-add box):
	// the URL itself (for web tools) plus the bare host (for recon/scan tools).
	if len(inScope) == 0 && strings.TrimSpace(req.URL) != "" {
		u := strings.TrimSpace(req.URL)
		if !strings.Contains(u, "://") {
			u = "http://" + u
		}
		pu, perr := url.Parse(u)
		if perr != nil || pu.Hostname() == "" {
			writeJSON(w, map[string]any{"error": "could not parse that as a URL or host"})
			return
		}
		inScope = append(inScope, engagement.Target{Type: engagement.TargetURL, Value: pu.String()})
		if net.ParseIP(pu.Hostname()) != nil {
			inScope = append(inScope, engagement.Target{Type: engagement.TargetIP, Value: pu.Hostname()})
		} else {
			inScope = append(inScope, engagement.Target{Type: engagement.TargetDomain, Value: pu.Hostname()})
		}
	}
	if len(inScope) == 0 {
		writeJSON(w, map[string]any{"error": "add at least one in-scope target"})
		return
	}
	outOfScope, err := toTargets(req.OutOfScope)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	allowed, maxRisk, depth := profileFor(req.Depth)

	now := time.Now().UTC()
	label := strings.TrimSpace(req.Name)
	if label == "" {
		label = "Self (owned: " + hostLabel(inScope[0].Value) + ")"
	}
	slug := sanitizeFilename(hostLabel(inScope[0].Value))
	if slug == "" {
		slug = "target"
	}
	eng := &engagement.Engagement{
		ID:          "ENG-" + slug + "-" + now.Format("20060102-150405"),
		Client:      label,
		Description: "Self-authorized engagement created from the console scope editor (" + depth + " depth).",
		Objectives:  []string{"Assess the in-scope targets for security issues."},
		Authorization: engagement.Authorization{
			AuthorizedBy: "Operator (self-authorized owned asset)",
			AuthorizedOn: now.Format("2006-01-02"),
			AgreementRef: "self-owned",
		},
		Scope: engagement.Scope{InScope: inScope, OutOfScope: outOfScope},
		RoE: engagement.RoE{
			MaxRisk:             maxRisk,
			AllowedCategories:   allowed,
			ForbiddenCategories: []string{"dos"},
			MaxRPS:              10,
			MaxConcurrent:       4,
		},
	}

	// Self-sign so high/exploit actions are authorized for this owned asset. The
	// grant is signed over CanonicalBytes (client+scope+max_risk), which excludes
	// the grants themselves, so embedding the grant afterward doesn't invalidate it.
	//
	// CRITICAL: sign the canonical bytes as they will be AFTER a YAML round-trip.
	// yaml normalizes nil vs empty slices (e.g. an unset out_of_scope serializes to
	// `[]`, which reloads as a non-nil empty slice), and that changes the
	// JSON-encoded canonical bytes. Signing the in-memory struct directly would then
	// fail to verify at load time. So marshal → reload (normalize) → sign that.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		writeJSON(w, map[string]any{"error": "keygen: " + err.Error()})
		return
	}
	pre, err := yaml.Marshal(eng)
	if err != nil {
		writeJSON(w, map[string]any{"error": "marshal: " + err.Error()})
		return
	}
	if err := yaml.Unmarshal(pre, eng); err != nil {
		writeJSON(w, map[string]any{"error": "normalize: " + err.Error()})
		return
	}
	sig := ed25519.Sign(priv, eng.CanonicalBytes())
	eng.Authorization.ClientPublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	eng.Authorization.Grants = []engagement.AuthGrant{{
		PublicKeyB64:  base64.StdEncoding.EncodeToString(pub),
		SignatureB64:  base64.StdEncoding.EncodeToString(sig),
		CoversTargets: inScope,
		MaxTier:       "high",
	}}

	if err := eng.Validate(); err != nil {
		writeJSON(w, map[string]any{"error": "built an invalid engagement: " + err.Error()})
		return
	}
	if _, err := eng.VerifiedGrants(); err != nil {
		writeJSON(w, map[string]any{"error": "self-signature failed to verify: " + err.Error()})
		return
	}

	out, err := yaml.Marshal(eng)
	if err != nil {
		writeJSON(w, map[string]any{"error": "marshal: " + err.Error()})
		return
	}
	if err := os.MkdirAll("configs", 0o755); err != nil {
		writeJSON(w, map[string]any{"error": "mkdir configs: " + err.Error()})
		return
	}
	path := filepath.Join("configs", slug+"-"+now.Format("150405")+".engagement.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		writeJSON(w, map[string]any{"error": "write: " + err.Error()})
		return
	}
	// Belt-and-suspenders: load the file back exactly as the engine will and confirm
	// the self-signature verifies, so we never return ok for an engagement that would
	// fail authorization at run time.
	if loaded, lerr := engagement.Load(path); lerr != nil {
		os.Remove(path)
		writeJSON(w, map[string]any{"error": "wrote an unloadable engagement: " + lerr.Error()})
		return
	} else if _, verr := loaded.VerifiedGrants(); verr != nil {
		os.Remove(path)
		writeJSON(w, map[string]any{"error": "signature did not verify after save: " + verr.Error()})
		return
	}
	// Edit-in-place: if this Save replaced an existing engagement, delete the old
	// file now that the new one is written and verified.
	if rep := strings.TrimSpace(req.Replace); rep != "" && rep != path {
		for _, pat := range []string{"*.yaml", "*.yml", "configs/*.yaml", "configs/*.yml"} {
			matches, _ := filepath.Glob(pat)
			for _, m := range matches {
				if m == rep {
					os.Remove(rep)
				}
			}
		}
	}
	writeJSON(w, map[string]any{"ok": true, "path": path, "id": eng.ID, "client": eng.Client, "depth": depth})
}

// handleDeleteEngagement removes an engagement's config file so the operator can
// manage engagements entirely from the console. It only deletes a path the console
// currently lists (same globs as handleEngagements), so it cannot be used for path
// traversal or to delete arbitrary files on disk.
func (c *console) handleDeleteEngagement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"error": "bad request"})
		return
	}
	target := strings.TrimSpace(req.Path)
	if target == "" {
		writeJSON(w, map[string]any{"error": "no engagement specified"})
		return
	}
	allowed := false
	for _, pat := range []string{"*.yaml", "*.yml", "configs/*.yaml", "configs/*.yml"} {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			if m == target {
				allowed = true
			}
		}
	}
	if !allowed {
		writeJSON(w, map[string]any{"error": "unknown engagement (not in the configs list)"})
		return
	}
	if err := os.Remove(target); err != nil {
		writeJSON(w, map[string]any{"error": "delete: " + err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (c *console) handleTools(w http.ResponseWriter, _ *http.Request) {
	type row struct{ Name, Category, Risk string }
	var rows []row
	for _, t := range defaultRegistry().All() {
		rows = append(rows, row{t.Name(), t.Category().String(), t.MaxRisk().String()})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].Name < rows[j].Name
	})
	out := make([]map[string]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]string{"name": r.Name, "category": r.Category, "risk": r.Risk})
	}
	writeJSON(w, out)
}

func (c *console) handleMethodology(w http.ResponseWriter, _ *http.Request) {
	out := []map[string]string{}
	for _, t := range methodology.All() {
		out = append(out, map[string]string{"phase": t.Phase, "name": t.Name, "tool": t.Tool})
	}
	writeJSON(w, out)
}

func (c *console) handleFindings(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	eng, st := c.eng, c.st
	c.mu.Unlock()
	if eng == nil || st == nil {
		writeJSON(w, report.Report{})
		return
	}
	writeJSON(w, report.Build(eng, st))
}

// handleReport renders the active engagement's client-ready report in the
// requested format (md|html|sarif|json) and serves it as a download. Same
// safe projection as the Findings tab — never raw secrets beyond what
// report.Build already redacts.
func (c *console) handleReport(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	eng, st := c.eng, c.st
	sessions := c.runSessions
	c.mu.Unlock()
	if eng == nil || st == nil {
		http.Error(w, "no engagement loaded — start a run first", http.StatusConflict)
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "md"
	}
	var (
		body        []byte
		contentType string
		ext         string
		err         error
	)
	switch format {
	case "md", "markdown":
		body, contentType, ext = []byte(report.Render(eng, st)), "text/markdown; charset=utf-8", "md"
	case "submission":
		// The submission report is what gets sent to a bug-bounty program, so it
		// runs through the adversarial validation brain: only findings re-proved
		// live reach the actionable body; refuted/inconclusive are retained as
		// flagged noise. Bound the live re-proof so a slow target can't hang the
		// download.
		vctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		fetch := validate.NewHTTPFetcher()
		fetch.Cookies = sessions // re-prove authenticated, per host, with the run's sessions
		body, contentType, ext = []byte(report.RenderSubmissionValidated(vctx, eng, st, fetch)), "text/markdown; charset=utf-8", "md"
	case "html":
		body, err = report.RenderHTML(eng, st)
		contentType, ext = "text/html; charset=utf-8", "html"
	case "sarif":
		body, err = report.RenderSARIF(eng, st)
		contentType, ext = "application/sarif+json", "sarif"
	case "json":
		body, err = report.RenderJSON(eng, st)
		contentType, ext = "application/json", "json"
	default:
		http.Error(w, "unknown format (want md|submission|html|sarif|json)", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "render: "+err.Error(), http.StatusInternalServerError)
		return
	}

	name := sanitizeFilename(eng.ID)
	if name == "" {
		name = "engagement"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "tyto-report-"+name+"."+ext))
	_, _ = w.Write(body)
}

// sanitizeFilename keeps a download name to a safe, header-injection-free subset.
func sanitizeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, s)
}

func (c *console) handleAudit(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	buf := c.auditBuf
	c.mu.Unlock()
	out := []audit.Entry{}
	if buf != nil {
		for _, line := range buf.Lines() {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var e audit.Entry
			if json.Unmarshal([]byte(line), &e) == nil {
				out = append(out, e)
			}
		}
	}
	writeJSON(w, out)
}

// --- helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// safeBuffer is a concurrency-safe byte buffer capturing the audit JSONL.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) Lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Split(strings.TrimSpace(s.buf.String()), "\n")
}
