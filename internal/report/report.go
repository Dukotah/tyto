// Package report turns engagement state into a client-ready report — grouped
// Markdown or structured JSON. SARIF and Typst PDF are on the roadmap (v0.2+).
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/cvss"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/evidence"
	"github.com/dukotah/tyto/internal/state"
)

// Report is the structured form of an engagement's results (the JSON export and
// the source the Markdown renderer formats).
type Report struct {
	EngagementID string           `json:"engagement_id"`
	Client       string           `json:"client"`
	AuthorizedBy string           `json:"authorized_by"`
	Agreement    string           `json:"agreement_ref"`
	ScopeHash    string           `json:"scope_hash"`
	Totals       Totals           `json:"totals"`
	Findings     []FindingView    `json:"findings"`
	Assets       []AssetView      `json:"assets"`
	Credentials  []CredentialView `json:"credentials,omitempty"`
	// DefensiveControls are the client controls that visibly reacted to testing;
	// Unchallenged are targets that took attack-like activity with no visible
	// reaction. Together they are the report's blue-team view (see defense.go).
	DefensiveControls []DefenseView      `json:"defensive_controls,omitempty"`
	Unchallenged      []UnchallengedView `json:"no_defensive_reaction,omitempty"`
}

// CredentialView is the report-facing projection of a recovered credential.
type CredentialView struct {
	Kind     string `json:"kind"`
	Username string `json:"username,omitempty"`
	Target   string `json:"target,omitempty"`
	Source   string `json:"source,omitempty"`
	Secret   string `json:"secret,omitempty"`
}

// Totals summarizes counts for the report header.
type Totals struct {
	Assets     int            `json:"assets"`
	Findings   int            `json:"findings"`
	Validated  int            `json:"validated"`
	BySeverity map[string]int `json:"by_severity"`
}

// FindingView is the report-facing projection of a finding.
type FindingView struct {
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Target      string  `json:"target"`
	Tool        string  `json:"tool"`
	Validated   bool    `json:"validated"`
	CVSS        float64 `json:"cvss,omitempty"`
	CVSSVector  string  `json:"cvss_vector,omitempty"`
	Description string  `json:"description,omitempty"`
	Repro       string  `json:"repro,omitempty"`
	Impact      string  `json:"impact,omitempty"`
	Evidence    string  `json:"evidence,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
	// EvidenceRecords are the captured HTTP request/response pairs proving this
	// finding, attached by finding ID from an evidence.Store. Empty (and omitted
	// from JSON) when no store was supplied or the finding has no captured
	// traffic — so a report built without evidence renders exactly as before.
	EvidenceRecords []evidence.Record `json:"evidence_records,omitempty"`
}

// remediationByTool maps a finding's producing tool to concrete remediation
// guidance, so every report finding ships with a fix — not just a description.
var remediationByTool = map[string]string{
	"dotgit":       "Block web access to the .git directory (deny /.git at the web server/proxy) and rotate any secrets found in the leaked history.",
	"cookieaudit":  "Set Secure, HttpOnly, and SameSite=Lax (or Strict) on all session cookies.",
	"graphqlcheck": "Disable GraphQL introspection in production, enforce per-field authorization, and add query depth/cost limits.",
	"webcheck":     "Add the missing security headers (Content-Security-Policy, X-Frame-Options/frame-ancestors, X-Content-Type-Options, HSTS).",
	"tlscheck":     "Disable deprecated TLS versions and weak ciphers; renew or repair the certificate chain.",
	"testssl":      "Disable deprecated TLS versions and weak ciphers; renew or repair the certificate chain.",
	"corscheck":    "Restrict Access-Control-Allow-Origin to a vetted allowlist; never reflect arbitrary origins together with credentials.",
	"secretscan":   "Remove the secret from client-delivered code and rotate it; serve secrets only from the server side.",
	"jsmine":       "Remove the secret from JavaScript bundles and rotate it; keep credentials server-side.",
	"jwtcheck":     "Reject alg:none, sign with a strong key/secret, and validate every claim (exp, aud, iss).",
	"sqliexploit":  "Use parameterized queries/prepared statements and validate input; never concatenate user input into SQL.",
	"webinject":    "Use parameterized queries and context-aware output encoding; validate and sanitize all input.",
	"redircheck":   "Validate redirect destinations against an allowlist; avoid user-controlled redirect targets.",
	"ssti":         "Never render user input as a template; use a sandboxed engine and context-aware escaping.",
	"httpmethods":  "Disable unused HTTP methods (PUT/DELETE/TRACE) at the server or proxy.",
	"jwt":          "Reject alg:none, sign with a strong key, and validate all claims.",
	"subtakeover":  "Remove the dangling DNS record or reclaim the referenced resource immediately.",
}

func remediationFor(toolName string) string { return remediationByTool[strings.ToLower(toolName)] }

// writeEvidenceRecords renders a finding's captured request/response pairs as a
// nested, fenced block under the finding. It emits nothing when there is no
// captured evidence, so findings without evidence render exactly as before.
func writeEvidenceRecords(b *strings.Builder, recs []evidence.Record) {
	for _, rec := range recs {
		fmt.Fprintf(b, "  - evidence (%s): %s %s -> %d\n", rec.EvidenceID, rec.Method, rec.URL, rec.Status)
		b.WriteString("    ```http\n")
		fmt.Fprintf(b, "    %s %s\n", rec.Method, rec.URL)
		writeEvidenceHeaders(b, rec.RequestHeaders)
		if rec.RequestBody != "" {
			writeEvidenceBody(b, rec.RequestBody, rec.RequestTruncated)
		}
		fmt.Fprintf(b, "    --- %d ---\n", rec.Status)
		writeEvidenceHeaders(b, rec.ResponseHeaders)
		if rec.ResponseBody != "" {
			writeEvidenceBody(b, rec.ResponseBody, rec.ResponseTruncated)
		}
		b.WriteString("    ```\n")
	}
}

func writeEvidenceHeaders(b *strings.Builder, h map[string][]string) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(b, "    %s: %s\n", k, v)
		}
	}
}

func writeEvidenceBody(b *strings.Builder, body string, truncated bool) {
	b.WriteString("    \n")
	for _, line := range strings.Split(body, "\n") {
		fmt.Fprintf(b, "    %s\n", strings.TrimRight(line, "\r"))
	}
	if truncated {
		b.WriteString("    [truncated]\n")
	}
}

// execSummary renders an auto-generated executive-summary paragraph from the
// report totals — the high-level "what was found and how bad" a client or triager
// reads first.
func execSummary(r Report) string {
	crit := r.Totals.BySeverity["critical"]
	high := r.Totals.BySeverity["high"]
	med := r.Totals.BySeverity["medium"]
	var b strings.Builder
	b.WriteString("## Executive summary\n\n")
	fmt.Fprintf(&b, "This authorized assessment evaluated %d in-scope asset(s) and recorded %d finding(s) (%d validated). ",
		r.Totals.Assets, r.Totals.Findings, r.Totals.Validated)
	switch {
	case crit > 0:
		fmt.Fprintf(&b, "**%d critical** and %d high-severity issue(s) require immediate remediation. ", crit, high)
	case high > 0:
		fmt.Fprintf(&b, "**%d high-severity** issue(s) require prompt remediation. ", high)
	case med > 0:
		fmt.Fprintf(&b, "%d medium-severity issue(s) were identified; no critical or high issues were found. ", med)
	case r.Totals.Findings > 0:
		b.WriteString("Only low/informational issues were identified. ")
	default:
		b.WriteString("No security issues were recorded. ")
	}
	b.WriteString("Each finding below includes evidence and concrete remediation guidance.\n\n")
	return b.String()
}

// AssetView is the report-facing projection of an asset.
type AssetView struct {
	Type  string            `json:"type"`
	Value string            `json:"value"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Build assembles the structured Report from engagement state.
func Build(eng *engagement.Engagement, st *state.State) Report {
	return BuildWithEvidence(eng, st, nil)
}

// BuildWithEvidence assembles the Report and, when ev is non-nil, attaches each
// finding's captured HTTP request/response evidence (looked up by the finding's
// ID). A nil ev yields exactly the same Report as Build — no evidence is attached.
func BuildWithEvidence(eng *engagement.Engagement, st *state.State, ev evidence.Store) Report {
	findings := st.Findings()
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Severity > findings[j].Severity })

	r := Report{
		EngagementID: eng.ID,
		Client:       eng.Client,
		AuthorizedBy: eng.Authorization.AuthorizedBy,
		Agreement:    eng.Authorization.AgreementRef,
		ScopeHash:    eng.ScopeHash(),
		Totals:       Totals{Assets: len(st.Assets()), Findings: len(findings), BySeverity: map[string]int{}},
	}
	for _, f := range findings {
		r.Totals.BySeverity[f.Severity.String()]++
		if f.Validated {
			r.Totals.Validated++
		}
		fv := FindingView{
			Severity: f.Severity.String(), Title: f.Title, Target: f.Target, Tool: f.Tool,
			Validated: f.Validated, Description: f.Description, Evidence: f.Evidence,
			Repro: f.Repro, Impact: f.Impact, Remediation: remediationFor(f.Tool),
		}
		if f.CVSS != "" {
			if score, err := cvss.BaseScore(f.CVSS); err == nil {
				fv.CVSS = score
				fv.CVSSVector = f.CVSS
			}
		}
		if ev != nil {
			fv.EvidenceRecords = ev.For(f.ID)
		}
		r.Findings = append(r.Findings, fv)
	}
	for _, c := range st.Credentials() {
		r.Credentials = append(r.Credentials, CredentialView{
			Kind: string(c.Kind), Username: c.Username, Target: c.Target, Source: c.Source, Secret: c.Secret,
		})
	}
	for _, a := range st.Assets() {
		r.Assets = append(r.Assets, AssetView{Type: a.Type, Value: a.Value, Attrs: a.Attrs})
	}
	sort.SliceStable(r.Assets, func(i, j int) bool { return r.Assets[i].Value < r.Assets[j].Value })
	r.DefensiveControls, r.Unchallenged = buildDefense(st)
	return r
}

// RenderJSON returns the report as indented JSON.
func RenderJSON(eng *engagement.Engagement, st *state.State) ([]byte, error) {
	return json.MarshalIndent(Build(eng, st), "", "  ")
}

// RenderJSONWithEvidence is RenderJSON with captured request/response evidence
// attached to each finding (by finding ID) from ev. A nil ev is identical to
// RenderJSON.
func RenderJSONWithEvidence(eng *engagement.Engagement, st *state.State, ev evidence.Store) ([]byte, error) {
	return json.MarshalIndent(BuildWithEvidence(eng, st, ev), "", "  ")
}

// Render (Markdown) is the default human-readable report, grouped by target and
// separating validated findings from unvalidated candidates.
func Render(eng *engagement.Engagement, st *state.State) string {
	return RenderWithEvidence(eng, st, nil)
}

// RenderWithEvidence is Render with each finding's captured HTTP request/response
// evidence (by finding ID) rendered beneath it from ev. A nil ev renders exactly
// as Render — findings with no evidence are unchanged either way.
func RenderWithEvidence(eng *engagement.Engagement, st *state.State, ev evidence.Store) string {
	r := BuildWithEvidence(eng, st, ev)
	var b strings.Builder

	fmt.Fprintf(&b, "# Engagement report — %s\n\n", r.EngagementID)
	fmt.Fprintf(&b, "**Client:** %s  \n", r.Client)
	fmt.Fprintf(&b, "**Authorized by:** %s  \n", r.AuthorizedBy)
	fmt.Fprintf(&b, "**Agreement:** %s  \n", r.Agreement)
	fmt.Fprintf(&b, "**Scope hash:** `%s`\n\n", r.ScopeHash)

	b.WriteString(execSummary(r))

	fmt.Fprintf(&b, "## Summary\n\n- Assets discovered: %d\n- Findings: %d (%d validated, %d candidate)\n",
		r.Totals.Assets, r.Totals.Findings, r.Totals.Validated, r.Totals.Findings-r.Totals.Validated)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := r.Totals.BySeverity[sev]; n > 0 {
			fmt.Fprintf(&b, "  - %s: %d\n", sev, n)
		}
	}
	b.WriteString("\n")

	if len(r.Findings) == 0 {
		b.WriteString("No findings recorded.\n\n")
		writeDefense(&b, r)
		return b.String()
	}

	writeFindings := func(heading string, validated bool) {
		var group []FindingView
		for _, f := range r.Findings {
			if f.Validated == validated {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s\n", heading)
		// Group by target so the report reads host-by-host.
		byTarget := map[string][]FindingView{}
		var targets []string
		for _, f := range group {
			if _, ok := byTarget[f.Target]; !ok {
				targets = append(targets, f.Target)
			}
			byTarget[f.Target] = append(byTarget[f.Target], f)
		}
		sort.Strings(targets)
		for _, tgt := range targets {
			fmt.Fprintf(&b, "\n### %s\n", tgt)
			for _, f := range byTarget[tgt] {
				cvssTag := ""
				if f.CVSS > 0 {
					cvssTag = fmt.Sprintf(" — CVSS %.1f", f.CVSS)
				}
				fmt.Fprintf(&b, "- **[%s%s]** %s (`%s`)\n", strings.ToUpper(f.Severity), cvssTag, f.Title, f.Tool)
				if f.Description != "" {
					fmt.Fprintf(&b, "  - %s\n", f.Description)
				}
				if f.Impact != "" {
					fmt.Fprintf(&b, "  - impact: %s\n", f.Impact)
				}
				if f.Repro != "" {
					fmt.Fprintf(&b, "  - repro: %s\n", f.Repro)
				}
				if f.Evidence != "" {
					fmt.Fprintf(&b, "  - evidence: `%s`\n", f.Evidence)
				}
				if f.Remediation != "" {
					fmt.Fprintf(&b, "  - remediation: %s\n", f.Remediation)
				}
				writeEvidenceRecords(&b, f.EvidenceRecords)
			}
		}
		b.WriteString("\n")
	}

	writeFindings("Validated findings", true)
	writeFindings("Candidate findings (unvalidated)", false)

	if len(r.Credentials) > 0 {
		fmt.Fprintf(&b, "## Recovered credentials (%d)\n", len(r.Credentials))
		for _, c := range r.Credentials {
			fmt.Fprintf(&b, "- **%s**", c.Kind)
			if c.Username != "" {
				fmt.Fprintf(&b, " %s", c.Username)
			}
			if c.Target != "" {
				fmt.Fprintf(&b, " @ %s", c.Target)
			}
			fmt.Fprintf(&b, " — `%s`", c.Secret)
			if c.Source != "" {
				fmt.Fprintf(&b, " (from %s)", c.Source)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	writeDefense(&b, r)

	b.WriteString("_The tamper-evident audit log records every decision and action; verify its hash chain to confirm this report matches what ran._\n")
	return b.String()
}
