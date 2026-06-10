// Package wpscanadapter drives wpscan (the WordPress security scanner) as a
// runtime-detected, shell-out adapter. tyto stays pure-Go and offline by
// default: if wpscan is not installed this adapter DEGRADES GRACEFULLY (emits a
// single info finding and succeeds) rather than failing. When wpscan IS present
// it scans the target URL and parses wpscan's JSON output into findings — the
// WordPress core version + its vulnerabilities, vulnerable/detected plugins,
// interesting findings, and enumerated users.
//
// It is scan-category and RiskLow, so the Scope Guard gates it before Execute is
// ever reached. The live shell-out path is only taken when an operator has
// wpscan installed; the JSON parser is split into parseWpscan so it stays purely
// unit-testable on captured sample output without the external tool present.
package wpscanadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool implements an external WordPress scanning adapter.
type Tool struct{}

// New returns a wpscan Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "wpscan" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk implements tool.Tool.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

// maxOutput caps captured combined output to bound memory against a runaway
// scan; wpscan JSON for a large site can be sizeable, so allow ~2 MiB.
const maxOutput = 2 << 20

// maxFindings caps the number of parsed findings so a hostile/huge JSON blob
// can't blow up memory or the report.
const maxFindings = 150

// Execute detects wpscan and runs it against the target URL. With wpscan not
// installed it degrades gracefully to a single info finding and Success=true. A
// tool that is present but exits non-zero is still parsed (wpscan exits non-zero
// when it finds vulnerabilities), and the run never returns an error from tyto's
// perspective.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	bin := adapter.Detect("wpscan")
	if bin == "" {
		res.Findings = append(res.Findings, adapter.Missing("wpscan", a.Target, "apt install wpscan"))
		res.Success = true
		res.Output = "wpscan not installed; skipped (graceful degrade)"
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

	args := []string{
		"--url", a.Target,
		"--format", "json",
		"--no-banner",
		"--random-user-agent",
		"--enumerate", "vp,u",
	}
	if tok := a.Params["api_token"]; tok != "" {
		args = append(args, "--api-token", tok)
	}

	out, runErr := adapter.Run(ctx, bin, args, maxOutput)

	findings := parseWpscan(out)
	// Stamp IDs/target/tool/timestamps on parsed findings (parseWpscan is
	// target-agnostic so it stays purely unit-testable on a raw string).
	now := time.Now().UTC()
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%s-%d", a.ID, i)
		if findings[i].Target == "" {
			findings[i].Target = a.Target
		}
		findings[i].Tool = t.Name()
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = now
		}
	}
	res.Findings = append(res.Findings, findings...)

	summary := fmt.Sprintf("wpscan: %d item(s)", len(findings))
	if runErr != nil {
		// wpscan exits non-zero on vuln detection (or genuine failure). Not an
		// error from tyto's perspective — note it and move on.
		summary += fmt.Sprintf(" — exit: %v", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// wpscanReport mirrors the subset of `wpscan --format json` we consume. wpscan
// tolerates partial WordPress detection: a non-WP site yields few/no fields, so
// every section is a pointer/map and missing sections are simply skipped.
type wpscanReport struct {
	Version             *wpVersion          `json:"version"`
	Plugins             map[string]wpPlugin `json:"plugins"`
	InterestingFindings []wpInteresting     `json:"interesting_findings"`
	Users               map[string]wpUser   `json:"users"`
}

type wpVersion struct {
	Number          string   `json:"number"`
	Status          string   `json:"status"`
	Vulnerabilities []wpVuln `json:"vulnerabilities"`
}

type wpPlugin struct {
	Version         *wpPluginVersion `json:"version"`
	Vulnerabilities []wpVuln         `json:"vulnerabilities"`
}

type wpPluginVersion struct {
	Number string `json:"number"`
}

type wpVuln struct {
	Title      string       `json:"title"`
	References wpReferences `json:"references"`
}

type wpReferences struct {
	CVE []string `json:"cve"`
}

type wpInteresting struct {
	Type string `json:"type"`
	ToS  string `json:"to_s"`
	URL  string `json:"url"`
}

type wpUser struct {
	// wpscan emits per-user detail (id, found_by, ...) we don't need; the map
	// key is the username. Kept as a struct so the map decodes cleanly.
}

// parseWpscan parses `wpscan --format json` output into findings. It is
// target-agnostic and tolerant of missing sections so it can be unit-tested on
// captured sample output without the external tool present. Output is capped at
// maxFindings.
func parseWpscan(jsonOut string) []state.Finding {
	var rep wpscanReport
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		// Not valid JSON (e.g. a target error message): nothing to report here.
		return nil
	}

	var findings []state.Finding
	add := func(f state.Finding) {
		if len(findings) < maxFindings {
			findings = append(findings, f)
		}
	}

	// WordPress core version + its vulnerabilities.
	if v := rep.Version; v != nil && v.Number != "" {
		sev := state.SeverityLow
		if v.Status == "insecure" || v.Status == "outdated" {
			sev = state.SeverityMedium
		}
		add(state.Finding{
			Title:       fmt.Sprintf("WordPress %s (%s)", v.Number, v.Status),
			Severity:    sev,
			Description: fmt.Sprintf("wpscan detected WordPress core version %s (status: %s).", v.Number, v.Status),
			Evidence:    fmt.Sprintf("version=%s status=%s", v.Number, v.Status),
			Validated:   true,
		})
		for _, vuln := range v.Vulnerabilities {
			add(state.Finding{
				Title:       fmt.Sprintf("WordPress core vuln: %s", vuln.Title),
				Severity:    state.SeverityHigh,
				Description: fmt.Sprintf("wpscan reported a WordPress core vulnerability affecting version %s: %s", v.Number, vuln.Title),
				Evidence:    cveEvidence(vuln.References.CVE),
				Validated:   true,
			})
		}
	}

	// Plugins: an Info finding naming each detected plugin+version, plus a High
	// finding per plugin vulnerability.
	for name, p := range rep.Plugins {
		ver := ""
		if p.Version != nil {
			ver = p.Version.Number
		}
		add(state.Finding{
			Title:       fmt.Sprintf("WordPress plugin detected: %s %s", name, ver),
			Severity:    state.SeverityInfo,
			Description: fmt.Sprintf("wpscan detected WordPress plugin %q (version %q).", name, ver),
			Evidence:    fmt.Sprintf("plugin=%s version=%s", name, ver),
			Validated:   true,
		})
		for _, vuln := range p.Vulnerabilities {
			add(state.Finding{
				Title:       fmt.Sprintf("Plugin %s vuln: %s", name, vuln.Title),
				Severity:    state.SeverityHigh,
				Description: fmt.Sprintf("wpscan reported a vulnerability in plugin %q: %s", name, vuln.Title),
				Evidence:    cveEvidence(vuln.References.CVE),
				Validated:   true,
			})
		}
	}

	// Interesting findings (headers, readme, robots.txt entries, ...).
	for _, f := range rep.InterestingFindings {
		title := f.ToS
		if title == "" {
			title = f.Type
		}
		add(state.Finding{
			Title:       fmt.Sprintf("Interesting finding: %s", title),
			Severity:    state.SeverityInfo,
			Description: fmt.Sprintf("wpscan interesting finding (%s): %s", f.Type, f.ToS),
			Evidence:    f.URL,
			Validated:   true,
		})
	}

	// Enumerated users.
	for name := range rep.Users {
		add(state.Finding{
			Title:       fmt.Sprintf("WordPress user enumerated: %s", name),
			Severity:    state.SeverityLow,
			Description: fmt.Sprintf("wpscan enumerated WordPress user %q.", name),
			Evidence:    "user=" + name,
			Validated:   true,
		})
	}

	return findings
}

// cveEvidence renders a CVE list as evidence text.
func cveEvidence(cves []string) string {
	if len(cves) == 0 {
		return ""
	}
	out := "CVE:"
	for i, c := range cves {
		if i > 0 {
			out += ","
		}
		out += " " + c
	}
	return out
}
