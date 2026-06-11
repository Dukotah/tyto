// Package kali gives the autonomous agent access to the WHOLE Kali toolbox, not
// just the curated built-in tools: it runs an arbitrary command inside the
// configured execution backend (the Kali WSL distro, or the host when tyto runs
// in Kali). This is the "use anything in the distro" capability.
//
// Safety model (this is the important part):
//   - The command runs in KALI (the pentest VM), never re-targeted at tyto's own
//     host — so even a destructive command is contained to the disposable VM.
//   - Read-only commands (shell.IsReadOnly) run within the engagement's risk
//     ceiling like any recon tool.
//   - ANY non-read-only command implements ApprovalGater.NeedsApproval => it is
//     forced through explicit operator approval on the dashboard BEFORE it runs,
//     regardless of the run's global approval setting. The operator sees the exact
//     command and clicks approve/deny. No approver wired => denied (fail closed).
//   - The guard still gates category/risk/scope: arbitrary commands are classified
//     RiskHigh (via defaultClassifier -> shell.Classify), so they only run in an
//     engagement whose risk ceiling permits high (e.g. "full" depth).
package kali

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
	"github.com/dukotah/tyto/internal/tool/builtin/shell"
)

// Tool runs an arbitrary command in the Kali execution backend.
type Tool struct{}

// New constructs the kali arsenal tool.
func New() *Tool { return &Tool{} }

func (t *Tool) Name() string { return "kali" }

// Category is recon (the read-only floor). The per-param classifier raises an
// arbitrary (mutating) command to RiskHigh — that, plus NeedsApproval, is where
// the real gating happens. Mirrors the shell tool's risk model.
func (t *Tool) Category() action.Category { return action.CategoryRecon }

// MaxRisk is the LOW floor; the guard takes max(floor, classifier), so a
// read-only command stays low and an arbitrary one is lifted to high.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

// NeedsApproval forces dashboard approval for any command that is not provably
// read-only. Read-only recon runs unattended; anything that could change state
// waits for the operator. Implements tool.ApprovalGater.
func (t *Tool) NeedsApproval(params map[string]string) bool {
	return !shell.IsReadOnly(strings.TrimSpace(params["command"]))
}

// Execute runs Params["command"] in the configured backend (Kali) and captures
// its output. The Scope Guard has already authorized the action and — for a
// mutating command — the operator has already approved it on the dashboard.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	cmd := strings.TrimSpace(a.Params["command"])
	if cmd == "" {
		res.Err = "no command provided"
		res.Output = "kali: no command provided (set params.command)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	bin := adapter.Detect("bash", "sh")
	if bin == "" {
		res.Findings = []state.Finding{adapter.Missing("kali", a.Target, "a POSIX shell (bash/sh) in the Kali distro")}
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	out, err := adapter.Run(ctx, bin, []string{"-lc", cmd}, adapter.DefaultMaxOutput)
	res.Output = fmt.Sprintf("$ %s\n%s", cmd, out)
	res.Success = err == nil
	if err != nil {
		res.Err = err.Error()
	}
	// Record the run as an informational finding so it lands in the report/audit
	// with the exact command for traceability (output is evidence, capped).
	res.Findings = append(res.Findings, state.Finding{
		ID:          "KALI-" + a.ID,
		Title:       "Ran Kali command: " + truncate(cmd, 80),
		Severity:    state.SeverityInfo,
		Target:      a.Target,
		Description: "operator-authorized arbitrary Kali command executed in the engagement backend",
		Evidence:    truncate(out, 600),
		Tool:        t.Name(),
		Validated:   true,
		FoundAt:     time.Now().UTC(),
	})
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
