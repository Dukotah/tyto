package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

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
	// pending holds approval channels keyed by action ID while a run is paused
	// awaiting an operator decision (human-in-the-loop mode).
	pending map[string]chan bool
	// runCancel cancels the in-progress run (used by /api/stop).
	runCancel context.CancelFunc
}

func newServeCmd() *cobra.Command {
	c := &console{subs: map[chan engine.Event]struct{}{}, pending: map[string]chan bool{}}
	var addr string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the operational web console (drive + monitor engagements in a browser)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(webui.Index)
			})
			mux.HandleFunc("/api/status", c.handleStatus)
			mux.HandleFunc("/api/engagements", c.handleEngagements)
			mux.HandleFunc("/api/tools", c.handleTools)
			mux.HandleFunc("/api/methodology", c.handleMethodology)
			mux.HandleFunc("/api/run", c.handleRun)
			mux.HandleFunc("/api/stop", c.handleStop)
			mux.HandleFunc("/api/approve", c.handleApprove)
			mux.HandleFunc("/api/chat", c.handleChat)
			mux.HandleFunc("/api/events", c.handleEvents)
			mux.HandleFunc("/api/findings", c.handleFindings)
			mux.HandleFunc("/api/audit", c.handleAudit)

			fmt.Fprintf(cmd.OutOrStdout(), "tyto console live → http://%s   (Ctrl-C to stop)\n", addr)
			return http.ListenAndServe(addr, mux)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8088", "listen address")
	cmd.Flags().StringVar(&c.ollamaURL, "ollama-url", "http://localhost:11434", "ollama base URL (for the local-model planner)")
	return cmd
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

	c.broadcast(engine.Event{
		Kind: "approval_required", Action: a.ID, Tool: a.Tool, Target: a.Target,
		Message: a.Rationale, Time: time.Now().UTC(),
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

	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		writeJSON(w, map[string]any{"error": "a run is already in progress"})
		return
	}

	eng, err := engagement.Load(req.Engagement)
	if err != nil {
		c.mu.Unlock()
		writeJSON(w, map[string]any{"error": "load engagement: " + err.Error()})
		return
	}
	// The operator's instruction is fed to the model as the top-priority objective
	// — it decides which tools to run, the guard still gates every action.
	if obj := strings.TrimSpace(req.Objective); obj != "" {
		eng.Objectives = append([]string{"OPERATOR INSTRUCTION (top priority): " + obj}, eng.Objectives...)
	}

	client, err := c.plannerClient(req, eng)
	if err != nil {
		c.mu.Unlock()
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}

	cycles := req.Cycles
	if cycles <= 0 {
		cycles = 3
	}
	st := state.New()
	ctx, cancel := context.WithCancel(context.Background())
	c.eng, c.st, c.auditBuf, c.history, c.running, c.runCancel = eng, st, &safeBuffer{}, nil, true, cancel
	c.mu.Unlock()

	go c.runEngagement(ctx, eng, st, client, cycles, req.DryRun, req.RequireApproval)
	writeJSON(w, map[string]any{"ok": true})
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
		model := strings.TrimSpace(os.Getenv("TYTO_MODEL"))
		if model == "" {
			ram, derr := sysinfo.TotalRAMBytes()
			model = llm.DefaultModel(ram, derr == nil).Model
		}
		return llm.NewOllama(c.ollamaURL, model), nil
	default:
		return nil, fmt.Errorf("unknown planner %q (want scripted|mock|ollama)", kind)
	}
}

func (c *console) runEngagement(ctx context.Context, eng *engagement.Engagement, st *state.State, client llm.Client, cycles int, dryRun, requireApproval bool) {
	defer func() {
		c.mu.Lock()
		c.running = false
		c.runCancel = nil
		c.mu.Unlock()
	}()

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
	})

	eg := engine.New(eng, guard.New(eng, toolSnapshot(reg), grants), planner.New(client),
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
}

// handleStop cancels an in-progress run.
func (c *console) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c.mu.Lock()
	cancel, running := c.runCancel, c.running
	c.mu.Unlock()
	if running && cancel != nil {
		cancel()
		c.broadcast(engine.Event{Kind: "log", Message: "operator requested stop", Time: time.Now().UTC()})
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	writeJSON(w, map[string]any{"ok": false, "error": "no run in progress"})
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
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Message) == "" {
		writeJSON(w, map[string]any{"error": "empty or malformed message"})
		return
	}

	c.mu.Lock()
	eng, st, url := c.eng, c.st, c.ollamaURL
	c.mu.Unlock()

	model := strings.TrimSpace(os.Getenv("TYTO_MODEL"))
	if model == "" {
		model = "qwen3:14b"
	}
	client := llm.NewOllama(url, model)

	system := "You are tyto's assistant for an AUTHORIZED penetration-testing engagement. " +
		"Help the operator understand findings and decide next steps. Stay strictly within the " +
		"authorized scope — never suggest testing out-of-scope or unauthorized targets. Be concise " +
		"and practical.\n\n" + chatContext(eng, st)

	var b strings.Builder
	n := len(req.History)
	if n > 12 {
		req.History = req.History[n-12:] // bound the context to the last turns
	}
	for _, m := range req.History {
		label := "Operator"
		if m.Role == "assistant" {
			label = "Assistant"
		}
		fmt.Fprintf(&b, "%s: %s\n", label, m.Content)
	}
	fmt.Fprintf(&b, "Operator: %s\nAssistant:", req.Message)

	ctx, cancel := context.WithTimeout(r.Context(), 240*time.Second)
	defer cancel()
	reply, err := client.Chat(ctx, system, b.String())
	if err != nil {
		writeJSON(w, map[string]any{"error": "chat: " + err.Error()})
		return
	}
	writeJSON(w, map[string]any{"reply": strings.TrimSpace(reply)})
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
	out := []map[string]string{}
	for _, pat := range []string{"*.yaml", "*.yml", "configs/*.yaml", "configs/*.yml"} {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			if eng, err := engagement.Load(m); err == nil {
				out = append(out, map[string]string{"path": m, "id": eng.ID, "client": eng.Client})
			}
		}
	}
	writeJSON(w, out)
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
