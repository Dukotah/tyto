// Package niktoadapter is a scan-category adapter that drives Nikto — a web
// server vulnerability scanner — as a runtime-detected shell-out. tyto stays a
// pure-Go offline binary by default, so when nikto isn't installed this adapter
// DEGRADES GRACEFULLY (emits an info finding and succeeds) instead of failing.
// The live shell-out path is only taken when an operator has nikto present.
//
// It is RiskMedium (active vuln scanning), so the Scope Guard gates it before
// Execute is ever reached. JSON parsing lives in a separate, host-agnostic
// parseNikto func so it stays unit-testable on a captured sample.
package niktoadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool implements the nikto web vulnerability scanner adapter.
type Tool struct{}

// New returns a nikto Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "nikto" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk implements tool.Tool.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

// maxOutput caps captured combined output to bound memory (~2 MiB — nikto JSON
// can be sizable on a result-rich host).
const maxOutput = 2 << 20

// maxFindings caps how many vulnerability findings a single run emits.
const maxFindings = 100

// Execute detects nikto and runs it against the target. With nikto absent it
// degrades gracefully to a single info finding and Success=true. A nikto that is
// present but exits non-zero is still parsed (it often prints results anyway).
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	bin := adapter.Detect("nikto")
	if bin == "" {
		res.Findings = append(res.Findings, adapter.Missing("nikto", a.Target, "apt install nikto"))
		res.Success = true
		res.Output = "nikto not installed; skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Honor cancellation before launching the external process.
	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	args := []string{"-h", a.Target, "-Format", "json", "-output", "-"}
	if p := a.Params["port"]; p != "" {
		args = append(args, "-p", p)
	}
	if a.Params["ssl"] == "true" {
		args = append(args, "-ssl")
	}

	out, runErr := adapter.Run(ctx, bin, args, maxOutput)

	findings := parseNikto(out)
	if len(findings) > maxFindings {
		findings = findings[:maxFindings]
	}
	// Stamp IDs/tool/timestamp on parsed findings (parseNikto stays metadata-free
	// so it is purely unit-testable on a raw string).
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%s-%d", a.ID, i)
		findings[i].Tool = t.Name()
		if findings[i].Target == "" {
			findings[i].Target = a.Target
		}
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = time.Now().UTC()
		}
	}
	res.Findings = append(res.Findings, findings...)

	summary := fmt.Sprintf("nikto: %d item(s)", len(findings))
	if runErr != nil {
		// nikto present but non-zero exit. Not an error from tyto's perspective.
		summary += fmt.Sprintf(" — tool exit: %v", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// niktoVuln is one entry from nikto's JSON "vulnerabilities" array.
type niktoVuln struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Msg    string `json:"msg"`
	OSVDB  string `json:"OSVDB"`
}

// niktoResult is nikto's top-level JSON object for a single host.
type niktoResult struct {
	Host            string      `json:"host"`
	IP              string      `json:"ip"`
	Port            string      `json:"port"`
	Banner          string      `json:"banner"`
	Vulnerabilities []niktoVuln `json:"vulnerabilities"`
}

// parseNikto best-effort parses nikto's `-Format json` output into findings,
// one per vulnerability entry. The top level may be a single object OR an array
// of objects (some nikto builds wrap results in an array) — both are handled.
// It is metadata-free and host-agnostic so it can be unit-tested on a captured
// sample without nikto present.
func parseNikto(jsonOut string) []state.Finding {
	s := strings.TrimSpace(jsonOut)
	if s == "" {
		return nil
	}

	var results []niktoResult

	// Try the array form first when it looks like one; fall back to the object
	// form. Tolerate either without erroring out.
	if strings.HasPrefix(s, "[") {
		if err := json.Unmarshal([]byte(s), &results); err != nil {
			return nil
		}
	} else {
		var single niktoResult
		if err := json.Unmarshal([]byte(s), &single); err != nil {
			return nil
		}
		results = []niktoResult{single}
	}

	var findings []state.Finding
	for _, r := range results {
		host := r.Host
		if host == "" {
			host = r.IP
		}
		for _, v := range r.Vulnerabilities {
			msg := strings.TrimSpace(v.Msg)
			if msg == "" {
				continue
			}

			target := host
			if v.URL != "" {
				target = strings.TrimSpace(host + v.URL)
			}

			evidence := strings.TrimSpace(strings.TrimSpace(v.Method+" "+v.URL) + " " + v.ID)

			findings = append(findings, state.Finding{
				Title:       "nikto: " + msg,
				Severity:    severityFor(msg),
				Target:      target,
				Description: msg,
				Evidence:    evidence,
				Validated:   true,
			})
		}
	}
	return findings
}

// bumpKeywords promote a finding from Low to Medium — they indicate an
// outdated/vulnerable/disclosing/default-credential/admin-surface condition.
var bumpKeywords = []string{"outdated", "vulnerable", "disclosure", "default", "admin"}

// infoMarkers flag purely informational entries (header notes, etc.) that should
// stay Info rather than Low.
var infoMarkers = []string{
	"retrieved",
	"the anti-clickjacking",
	"the x-xss-protection",
	"the x-content-type-options",
	"no cgi directories found",
	"uncommon header",
	"allowed http methods",
}

// severityFor classifies a vulnerability message: Medium when it mentions an
// outdated/vulnerable/disclosure/default/admin condition, Info for purely
// informational header/note entries, else Low.
func severityFor(msg string) state.Severity {
	l := strings.ToLower(msg)
	for _, k := range bumpKeywords {
		if strings.Contains(l, k) {
			return state.SeverityMedium
		}
	}
	for _, m := range infoMarkers {
		if strings.Contains(l, m) {
			return state.SeverityInfo
		}
	}
	return state.SeverityLow
}
