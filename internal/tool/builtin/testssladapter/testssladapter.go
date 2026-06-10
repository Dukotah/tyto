// Package testssladapter is a deep TLS/crypto assessment adapter that shells out
// to the EXTERNAL testssl.sh binary and parses its JSON output into typed
// findings. Like every tyto shell-out adapter it is runtime-detected: tyto stays
// a pure-Go, offline-by-default binary, so if testssl.sh is not installed this
// adapter DEGRADES GRACEFULLY — it emits a single info finding and succeeds
// rather than failing. The live scan path is only taken when an operator has
// testssl.sh on PATH.
//
// It is scan-category and RiskLow (TLS handshakes + cipher probing against a
// single host:port is benign active contact relative to exploitation), so the
// Scope Guard gates it before Execute is ever reached. testssl.sh is driven
// without a shell (args are a slice), and a.Params is intentionally ignored so a
// tool/model-controlled string can never inject arbitrary testssl flags.
package testssladapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool implements an external testssl.sh TLS-assessment adapter.
type Tool struct{}

// New returns a testssladapter Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "testssl" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk implements tool.Tool. TLS/cipher probing of a single endpoint is
// benign active contact relative to exploitation, so the ceiling is Low.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

// maxFindings caps emitted findings so a host with a huge issue count (or a
// crafted JSON payload) can't balloon the result.
const maxFindings = 100

// Execute resolves the host:port from the target, detects testssl.sh, and — if
// present — runs `testssl.sh --jsonfile - --quiet --color 0 <host:port>` and
// parses the JSON array into findings. With testssl.sh not installed it degrades
// gracefully to a single info finding and Success=true. A present-but-failing
// run with no parseable output is reported in res.Output (still a nil error).
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	target := hostPort(a.Target)

	bin := adapter.Detect("testssl.sh", "testssl")
	if bin == "" {
		res.Findings = []state.Finding{adapter.Missing("testssl", a.Target, "apt install testssl.sh")}
		res.Success = true
		res.Output = "testssl not available; TLS assessment skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Honor cancellation before launching the external process. (adapter.Run also
	// binds ctx, so an in-flight scan is killed on cancel too.)
	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	// --jsonfile - writes the JSON result array to stdout, --quiet suppresses the
	// banner, --color 0 disables ANSI. a.Params is deliberately NOT honored
	// (injection safety); only the vetted target reaches the args slice.
	args := []string{"--jsonfile", "-", "--quiet", "--color", "0", target}

	out, runErr := adapter.Run(ctx, bin, args, 4<<20)

	findings := parseTestssl(out)

	// Stamp IDs/host/tool on parsed findings (parseTestssl stays host/tool-agnostic
	// so it is purely unit-testable on a captured JSON string).
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%s-%d", a.ID, i)
		if findings[i].Target == "" {
			findings[i].Target = target
		}
		findings[i].Tool = t.Name()
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = time.Now().UTC()
		}
	}
	res.Findings = append(res.Findings, findings...)

	summary := fmt.Sprintf("testssl: %d issue(s)", len(findings))
	if runErr != nil && len(findings) == 0 {
		// testssl present but failed (host down, no TLS, etc.) and gave us nothing
		// parseable. Not an error from tyto's perspective — report it and move on.
		summary = fmt.Sprintf("testssl run error with no parseable output: %v", runErr)
	} else if runErr != nil {
		summary += fmt.Sprintf(" (testssl exited non-zero: %v)", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// testsslEntry mirrors the subset of a testssl.sh JSON array element this adapter
// consumes. Fields outside this struct are ignored; every field is optional so
// malformed/partial documents parse without error.
type testsslEntry struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve"`
}

// parseTestssl best-effort parses `testssl.sh --jsonfile -` output (a JSON array
// of result objects) into findings. It emits a finding ONLY for an actionable
// severity (LOW/MEDIUM/HIGH/CRITICAL/WARN), skipping OK/INFO/DEBUG noise, maps
// the testssl severity onto tyto's scale, and caps at ~100. It is host/tool-
// agnostic for unit-testing.
func parseTestssl(jsonOut string) []state.Finding {
	var entries []testsslEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonOut)), &entries); err != nil {
		return nil
	}

	var findings []state.Finding
	for _, e := range entries {
		sev, emit := mapSeverity(e.Severity)
		if !emit {
			continue
		}
		if len(findings) >= maxFindings {
			break
		}

		evidence := e.ID
		if e.CVE != "" {
			evidence = strings.TrimSpace(e.ID + " " + e.CVE)
		}
		findings = append(findings, state.Finding{
			Title:       "TLS: " + e.ID,
			Severity:    sev,
			Description: e.Finding,
			Evidence:    evidence,
			Validated:   true,
		})
	}
	return findings
}

// mapSeverity maps a testssl.sh severity string onto tyto's Severity scale. The
// bool is false for severities that should not produce a finding (OK/INFO/DEBUG
// and anything unrecognized).
func mapSeverity(s string) (state.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return state.SeverityCritical, true
	case "HIGH":
		return state.SeverityHigh, true
	case "MEDIUM":
		return state.SeverityMedium, true
	case "LOW", "WARN":
		return state.SeverityLow, true
	default:
		return state.SeverityInfo, false
	}
}

// hostPort resolves a target (host, host:port, or url) to "host:port", defaulting
// to :443 when no port is present. A URL like "https://h/x" becomes "h:443"; an
// explicit "h:8443" passes through.
func hostPort(target string) string {
	t := strings.TrimSpace(target)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if t == "" {
		return ":443"
	}
	if h, p, err := net.SplitHostPort(t); err == nil {
		if p == "" {
			p = "443"
		}
		return net.JoinHostPort(h, p)
	}
	// No port (or a bare IPv6 literal that SplitHostPort rejects): default to 443.
	return net.JoinHostPort(t, "443")
}
