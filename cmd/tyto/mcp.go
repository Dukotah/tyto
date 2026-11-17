package main

// tyto mcp — exposes the tyto arsenal to an external agent (Claude Code / Opus)
// over the Model Context Protocol (stdio JSON-RPC 2.0). The agent becomes the
// operator: it plans, adapts, and chains tools natively. tyto remains the BODY —
// every tool call is routed through the SAME deterministic Scope Guard, approval
// gate, and audit log the autonomous engine uses, so "full access" never means
// "bypass scope." The guard is the law; the agent cannot override it.
//
// Transport: newline-delimited JSON-RPC 2.0 over stdin/stdout (the MCP stdio
// convention). stdout carries ONLY protocol frames; all human/log output goes to
// stderr so it never corrupts the channel.
//
// Safety invariants (identical to the engine's admit path):
//   - Unknown tool          => DENY (fail closed).
//   - Out-of-scope target   => DENY.
//   - Risk/category/time/auth over the ceiling => DENY.
//   - RequireApproval verdict, or a tool's ApprovalGater (the kali arsenal tool
//     for any non-read-only command) => BLOCKED until a human authorizes. The
//     human gate is the operator approving the agent's tool call (CC's own
//     permission prompt) and relaying it as approve:true; the guard still
//     re-checks scope/risk on the approved run.
//   - Every decision + action + result is written to the tamper-evident audit log.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/report"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool"
	"github.com/dukotah/tyto/internal/tool/adapter"
	"github.com/dukotah/tyto/pkg/version"
)

// mcpProtocolVersion is the MCP revision this server speaks.
const mcpProtocolVersion = "2024-11-05"

// perCallTimeout bounds a single tool execution so one hung scan can't wedge the
// whole session. Long scanners (nmap/nuclei) fit comfortably; raise if needed.
const perCallTimeout = 15 * time.Minute

type mcpOptions struct {
	engPath   string
	exec      string
	auditPath string
}

func newMcpCmd() *cobra.Command {
	o := &mcpOptions{}
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve the tyto arsenal to an MCP client (Claude Code/Opus as the operator)",
		Long: "Expose tyto's scope-guarded tool arsenal over the Model Context Protocol\n" +
			"(stdio). An external agent (e.g. Claude Code driven by Opus) becomes the\n" +
			"operator and drives a full engagement, while every tool call is routed\n" +
			"through the same Scope Guard, approval gate, and audit log as the engine.",
		Args: cobra.NoArgs,
		RunE: o.run,
	}
	f := cmd.Flags()
	f.StringVar(&o.engPath, "engagement", "", "path to engagement YAML (required) — defines scope + rules the guard enforces")
	f.StringVar(&o.exec, "exec", "", `where shell-out tools run: ""=host (auto-detects Kali WSL on Windows), "wsl:<distro>"`)
	f.StringVar(&o.auditPath, "audit", "", "audit log path (default: <engagement-id>.mcp.audit.jsonl)")
	return cmd
}

func (o *mcpOptions) run(cmd *cobra.Command, _ []string) error {
	if o.engPath == "" {
		return fmt.Errorf("--engagement is required")
	}
	eng, err := engagement.Load(o.engPath)
	if err != nil {
		return err
	}

	// Route shell-out tools to an execution backend (same resolution as `tyto run`).
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

	// Verify authorization grants up front; fail closed on a bad one.
	grants, err := eng.VerifiedGrants()
	if err != nil {
		return fmt.Errorf("authorization: %w", err)
	}

	ap := o.auditPath
	if ap == "" {
		ap = eng.ID + ".mcp.audit.jsonl"
	}
	alog, closeAudit, err := audit.Open(ap)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer closeAudit()

	reg := defaultRegistry()
	g := guard.New(eng, toolSnapshot(reg), grants).WithClassifier(defaultClassifier())
	st := state.New()

	if err := alog.Record("authorization", map[string]any{
		"scope_hash": eng.ScopeHash(), "verified_grants": len(grants),
		"mode": "mcp", "self_attested": eng.Authorization.SelfAttested(),
	}); err != nil {
		return fmt.Errorf("write audit head: %w", err)
	}

	srv := &mcpServer{
		eng:      eng,
		reg:      reg,
		guard:    g,
		state:    st,
		audit:    alog,
		sessions: make(map[string]string),
	}

	fmt.Fprintf(os.Stderr, "tyto mcp %s — engagement %s (%s)\n", version.Version, eng.ID, eng.Client)
	if spec != "" {
		fmt.Fprintf(os.Stderr, "tool execution backend: %s\n", spec)
	} else {
		fmt.Fprintln(os.Stderr, "tool execution backend: host")
	}
	fmt.Fprintf(os.Stderr, "audit: %s — %d tools armed. Waiting for MCP client on stdio.\n", ap, len(reg.Names()))

	return srv.serve(cmd.Context())
}

// mcpServer holds the engagement body. Requests arrive serially over stdio, so
// no locking is needed beyond the state store's own.
type mcpServer struct {
	eng      *engagement.Engagement
	reg      *tool.Registry
	guard    *guard.Guard
	state    *state.State
	audit    *audit.Log
	sessions map[string]string // host -> cookie, replayed to later actions
	actionNo atomic.Int64
}

// ---- JSON-RPC plumbing ----------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *mcpServer) serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r := bufio.NewReaderSize(os.Stdin, 1<<20)
	w := bufio.NewWriter(os.Stdout)
	for {
		line, err := r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			s.handle(ctx, bytes.TrimSpace(line), w)
			w.Flush()
		}
		if err != nil {
			return nil // EOF or client closed stdin → clean shutdown
		}
	}
}

func (s *mcpServer) handle(ctx context.Context, line []byte, w *bufio.Writer) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		s.write(w, &rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"

	switch req.Method {
	case "initialize":
		s.reply(w, req.ID, map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "tyto", "version": version.Version},
		})
	case "notifications/initialized", "notifications/cancelled":
		// notifications: no response
	case "ping":
		s.reply(w, req.ID, map[string]any{})
	case "tools/list":
		s.reply(w, req.ID, map[string]any{"tools": toolManifest()})
	case "tools/call":
		s.handleToolCall(ctx, req, w)
	default:
		if !isNotification {
			s.write(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found: " + req.Method}})
		}
	}
}

func (s *mcpServer) reply(w *bufio.Writer, id json.RawMessage, result any) {
	if len(id) == 0 {
		return
	}
	s.write(w, &rpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func (s *mcpServer) write(w *bufio.Writer, resp *rpcResponse) {
	b, err := json.Marshal(resp)
	if err != nil {
		b, _ = json.Marshal(&rpcResponse{JSONRPC: "2.0", ID: resp.ID, Error: &rpcError{Code: -32603, Message: "marshal error"}})
	}
	w.Write(b)
	w.WriteByte('\n')
}

// text wraps a plain-text tool result in the MCP content envelope.
func textResult(isErr bool, s string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": s}},
		"isError": isErr,
	}
}

// ---- tool manifest --------------------------------------------------------

func toolManifest() []map[string]any {
	strObj := func() map[string]any { return map[string]any{"type": "string"} }
	return []map[string]any{
		{
			"name":        "tyto_scope",
			"description": "Show the loaded engagement: client, in-scope targets, risk ceiling, allowed/forbidden categories, and authorization mode. READ THIS FIRST — it is the boundary every action is checked against.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "tyto_list_tools",
			"description": "List every tool in the arsenal with its category and risk ceiling, and whether it forces human approval. Use this to pick the right tool for tyto_execute.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "tyto_execute",
			"description": "Run one arsenal tool against an in-scope target. Every call passes the Scope Guard (scope/risk/category/time/auth) before running. Returns the tool output plus any findings, assets, and credentials discovered. If the guard requires approval, it returns BLOCKED — re-call with approve=true once the human has authorized.",
			"inputSchema": map[string]any{
				"type": "object",
				"required": []string{"tool", "target"},
				"properties": map[string]any{
					"tool":      map[string]any{"type": "string", "description": "tool name (see tyto_list_tools), e.g. nmapscan, httpprobe, nucleiscan, sqlmap"},
					"target":    map[string]any{"type": "string", "description": "host, IP, CIDR, or URL — must be in scope"},
					"params":    map[string]any{"type": "object", "description": "tool-specific parameters (string values)", "additionalProperties": strObj()},
					"rationale": map[string]any{"type": "string", "description": "why you chose this action (recorded in the audit log and report)"},
					"approve":   map[string]any{"type": "boolean", "description": "set true to authorize an action the guard gated for approval (human sign-off relayed)"},
				},
			},
		},
		{
			"name":        "tyto_kali",
			"description": "Run an ARBITRARY command in the Kali execution backend — the full distro, for anything the built-in tools don't cover (install a tool, write and run a custom script, chain utilities). Read-only commands run within the risk ceiling; any state-changing command is forced through human approval (re-call with approve=true). Contained to the Kali VM, never tyto's own host.",
			"inputSchema": map[string]any{
				"type": "object",
				"required": []string{"target", "command"},
				"properties": map[string]any{
					"target":    map[string]any{"type": "string", "description": "the in-scope target this command acts on (for scope + audit)"},
					"command":   map[string]any{"type": "string", "description": "the shell command to run inside Kali, e.g. 'gobuster dir -u http://... -w ...'"},
					"rationale": map[string]any{"type": "string", "description": "why you are running it (audited)"},
					"approve":   map[string]any{"type": "boolean", "description": "set true to authorize a non-read-only command after human sign-off"},
				},
			},
		},
		{
			"name":        "tyto_findings",
			"description": "Dump the current engagement knowledge: discovered assets (hosts/services/URLs), findings (with severity), and recovered credentials (redacted). This is your persistent memory across the run.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "tyto_report",
			"description": "Render the markdown penetration-test report from everything discovered so far.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
	}
}

// ---- tool dispatch --------------------------------------------------------

func (s *mcpServer) handleToolCall(ctx context.Context, req rpcRequest, w *bufio.Writer) {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.reply(w, req.ID, textResult(true, "invalid tools/call params: "+err.Error()))
		return
	}
	args := p.Arguments
	switch p.Name {
	case "tyto_scope":
		s.reply(w, req.ID, textResult(false, s.scopeText()))
	case "tyto_list_tools":
		s.reply(w, req.ID, textResult(false, s.listToolsText()))
	case "tyto_findings":
		s.reply(w, req.ID, textResult(false, s.findingsText()))
	case "tyto_report":
		s.reply(w, req.ID, textResult(false, report.Render(s.eng, s.state)))
	case "tyto_execute":
		out, isErr := s.execAction(ctx, argStr(args, "tool"), argStr(args, "target"), argParams(args, "params"), argStr(args, "rationale"), argBool(args, "approve"))
		s.reply(w, req.ID, textResult(isErr, out))
	case "tyto_kali":
		cmd := argStr(args, "command")
		out, isErr := s.execAction(ctx, "kali", argStr(args, "target"), map[string]string{"command": cmd}, argStr(args, "rationale"), argBool(args, "approve"))
		s.reply(w, req.ID, textResult(isErr, out))
	default:
		s.reply(w, req.ID, textResult(true, "unknown tool: "+p.Name))
	}
}

// execAction is the single-action execution path — the MCP mirror of the
// engine's admit→execute→commit, with the SAME guard, approval, and audit order.
func (s *mcpServer) execAction(ctx context.Context, toolName, target string, params map[string]string, rationale string, approved bool) (string, bool) {
	toolName = strings.TrimSpace(toolName)
	target = strings.TrimSpace(target)
	if toolName == "" || target == "" {
		return "ERROR: both 'tool' and 'target' are required.", true
	}
	if params == nil {
		params = map[string]string{}
	}

	t, ok := s.reg.Get(toolName)
	if !ok {
		return fmt.Sprintf("DENIED: unknown tool %q (not registered). Call tyto_list_tools.", toolName), true
	}

	id := fmt.Sprintf("mcp-%03d", s.actionNo.Add(1))
	a := action.Action{
		ID:        id,
		Tool:      toolName,
		Category:  string(t.Category()),
		Target:    target,
		Params:    params,
		Risk:      t.MaxRisk(),
		Rationale: rationale,
	}

	// 1. Scope Guard — authoritative, fail closed.
	dec := s.guard.Evaluate(a)
	_ = s.audit.Record("decision", map[string]any{
		"action": id, "tool": toolName, "target": target,
		"declared_category": a.Category, "declared_risk": a.Risk.String(),
		"verdict": dec.Verdict.String(), "allowed": dec.IsAllowed(), "reason": dec.Reason,
		"source": "mcp",
	})
	if dec.Verdict == guard.VerdictDeny {
		return fmt.Sprintf("DENIED by Scope Guard: %s", dec.Reason), true
	}

	// 2. Approval gate: guard-required OR tool-forced (kali for mutating commands).
	needApproval := dec.Verdict == guard.VerdictRequireApproval
	if ag, ok := t.(tool.ApprovalGater); ok && ag.NeedsApproval(params) {
		needApproval = true
	}
	if needApproval && !approved {
		_ = s.audit.Record("approval_required", map[string]any{
			"action": id, "tool": toolName, "target": target, "reason": dec.Reason, "source": "mcp",
		})
		reason := dec.Reason
		if reason == "" {
			reason = "this action is state-changing / high-impact and requires human authorization"
		}
		return fmt.Sprintf("BLOCKED — human approval required: %s\n\nConfirm with the operator, then re-call this tool with approve=true to run it.", reason), false
	}
	if needApproval && approved {
		_ = s.audit.Record("approval_granted", map[string]any{
			"action": id, "tool": toolName, "target": target, "approver": "operator-via-agent", "source": "mcp",
		})
	}

	// 3. Execute. Replay any established session cookie for this host.
	_ = s.audit.Record("action", map[string]any{"action": id, "tool": toolName, "target": target, "params": params, "source": "mcp"})
	if c := s.sessions[hostKey(target)]; c != "" {
		a.Cookie = c
	}

	cctx, cancel := context.WithTimeout(ctx, perCallTimeout)
	defer cancel()
	res, err := t.Execute(cctx, a)
	if err != nil {
		_ = s.audit.Record("result", map[string]any{"action": id, "success": false, "error": err.Error(), "source": "mcp"})
		return fmt.Sprintf("tool %q errored: %v", toolName, err), true
	}

	// 4. Fold results into shared state (the agent's persistent memory).
	var newFindings, newAssets, newCreds int
	for _, f := range res.Findings {
		if s.state.AddFinding(f) {
			newFindings++
		}
	}
	for i := range res.Assets {
		asset := res.Assets[i]
		if s.state.AddAsset(&asset) {
			newAssets++
		}
	}
	for _, c := range res.Credentials {
		if s.state.AddCredential(c) {
			newCreds++
			_ = s.audit.Record("credential", c.Redacted())
		}
	}
	if res.Session != nil && res.Session.Cookie != "" {
		s.sessions[hostKey(res.Session.Host)] = res.Session.Cookie
	}
	_ = s.audit.Record("result", map[string]any{
		"action": id, "success": res.Success, "output": res.Output,
		"findings": len(res.Findings), "assets": len(res.Assets), "source": "mcp",
	})

	return s.formatResult(toolName, target, res, newFindings, newAssets, newCreds), false
}

func (s *mcpServer) formatResult(toolName, target string, res action.Result, nf, na, nc int) string {
	var b strings.Builder
	status := "OK"
	if !res.Success {
		status = "completed (no success flag)"
	}
	fmt.Fprintf(&b, "[%s] %s %s — %s\n", status, toolName, target, dur(res))
	if res.Err != "" {
		fmt.Fprintf(&b, "note: %s\n", res.Err)
	}
	fmt.Fprintf(&b, "new: %d finding(s), %d asset(s), %d credential(s)\n", nf, na, nc)
	if len(res.Findings) > 0 {
		b.WriteString("\nfindings this run:\n")
		for _, f := range res.Findings {
			mark := ""
			if f.Validated {
				mark = " [validated]"
			}
			fmt.Fprintf(&b, "  - [%s] %s (%s)%s\n", f.Severity.String(), f.Title, f.Target, mark)
		}
	}
	if len(res.Assets) > 0 {
		b.WriteString("\nassets this run:\n")
		for _, as := range res.Assets {
			fmt.Fprintf(&b, "  - %s: %s\n", as.Type, as.Value)
		}
	}
	if strings.TrimSpace(res.Output) != "" {
		b.WriteString("\noutput:\n")
		b.WriteString(res.Output)
		b.WriteByte('\n')
	}
	return b.String()
}

// ---- read-only views ------------------------------------------------------

func (s *mcpServer) scopeText() string {
	e := s.eng
	var b strings.Builder
	fmt.Fprintf(&b, "Engagement: %s\nClient: %s\n", e.ID, e.Client)
	authDesc := "client-signed grant"
	if e.Authorization.SelfAttested() {
		authDesc = "self-attested (operator owns/controls the targets)"
	}
	fmt.Fprintf(&b, "Authorization: %s\n", authDesc)
	fmt.Fprintf(&b, "Max risk ceiling: %s\n", e.RoE.MaxRisk)
	if len(e.RoE.AllowedCategories) > 0 {
		fmt.Fprintf(&b, "Allowed categories: %s\n", strings.Join(e.RoE.AllowedCategories, ", "))
	}
	if len(e.RoE.ForbiddenCategories) > 0 {
		fmt.Fprintf(&b, "Forbidden categories: %s\n", strings.Join(e.RoE.ForbiddenCategories, ", "))
	}
	b.WriteString("\nIn scope:\n")
	if len(e.Scope.InScope) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, t := range e.Scope.InScope {
		fmt.Fprintf(&b, "  - %s\n", t.Value)
	}
	b.WriteString("\nEvery tyto_execute / tyto_kali target is checked against this scope and these rules. Out-of-scope or over-ceiling actions are denied.\n")
	return b.String()
}

func (s *mcpServer) listToolsText() string {
	names := s.reg.Names()
	sort.Strings(names)
	var b strings.Builder
	fmt.Fprintf(&b, "%d tools armed (name — category — risk ceiling):\n\n", len(names))
	for _, n := range names {
		t, ok := s.reg.Get(n)
		if !ok {
			continue
		}
		gate := ""
		if ag, ok := t.(tool.ApprovalGater); ok && ag.NeedsApproval(map[string]string{"command": "x"}) {
			gate = "  [approval-gated for mutating use]"
		}
		fmt.Fprintf(&b, "  %-14s %-10s %s%s\n", n, t.Category(), t.MaxRisk(), gate)
	}
	b.WriteString("\nRun one with tyto_execute {tool, target, params}. For anything not listed, use tyto_kali to run an arbitrary Kali command.\n")
	return b.String()
}

func (s *mcpServer) findingsText() string {
	var b strings.Builder
	findings := s.state.Findings()
	assets := s.state.Assets()
	creds := s.state.Credentials()
	fmt.Fprintf(&b, "Knowledge so far: %d finding(s), %d asset(s), %d credential(s).\n", len(findings), len(assets), len(creds))
	if len(findings) > 0 {
		b.WriteString("\nFindings:\n")
		for _, f := range findings {
			mark := ""
			if f.Validated {
				mark = " [validated]"
			}
			fmt.Fprintf(&b, "  - [%s] %s (%s)%s\n", f.Severity.String(), f.Title, f.Target, mark)
		}
	}
	if len(assets) > 0 {
		b.WriteString("\nAssets:\n")
		for _, a := range assets {
			fmt.Fprintf(&b, "  - %s: %s\n", a.Type, a.Value)
		}
	}
	if len(creds) > 0 {
		b.WriteString("\nCredentials (redacted):\n")
		for _, c := range creds {
			r := c.Redacted()
			fmt.Fprintf(&b, "  - %v\n", r)
		}
	}
	return b.String()
}

// ---- small helpers --------------------------------------------------------

func dur(res action.Result) string {
	if res.StartedAt.IsZero() || res.FinishedAt.IsZero() {
		return ""
	}
	return res.FinishedAt.Sub(res.StartedAt).Round(time.Millisecond).String()
}

// hostKey strips scheme and port so a session established on one port/scheme is
// replayed to later actions against the same host.
func hostKey(target string) string {
	h := target
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

func argStr(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}
	return ""
}

func argBool(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	switch v := m[k].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

func argParams(m map[string]any, k string) map[string]string {
	out := map[string]string{}
	if m == nil {
		return out
	}
	raw, ok := m[k]
	if !ok {
		return out
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return out
	}
	for kk, vv := range obj {
		if s, ok := vv.(string); ok {
			out[kk] = s
		} else {
			out[kk] = fmt.Sprint(vv)
		}
	}
	return out
}
