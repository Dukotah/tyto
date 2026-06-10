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
	"github.com/dukotah/tyto/internal/state"
)

// Report is the structured form of an engagement's results (the JSON export and
// the source the Markdown renderer formats).
type Report struct {
	EngagementID string        `json:"engagement_id"`
	Client       string        `json:"client"`
	AuthorizedBy string        `json:"authorized_by"`
	Agreement    string        `json:"agreement_ref"`
	ScopeHash    string        `json:"scope_hash"`
	Totals       Totals        `json:"totals"`
	Findings     []FindingView `json:"findings"`
	Assets       []AssetView   `json:"assets"`
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
	Evidence    string  `json:"evidence,omitempty"`
}

// AssetView is the report-facing projection of an asset.
type AssetView struct {
	Type  string            `json:"type"`
	Value string            `json:"value"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Build assembles the structured Report from engagement state.
func Build(eng *engagement.Engagement, st *state.State) Report {
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
		}
		if f.CVSS != "" {
			if score, err := cvss.BaseScore(f.CVSS); err == nil {
				fv.CVSS = score
				fv.CVSSVector = f.CVSS
			}
		}
		r.Findings = append(r.Findings, fv)
	}
	for _, a := range st.Assets() {
		r.Assets = append(r.Assets, AssetView{Type: a.Type, Value: a.Value, Attrs: a.Attrs})
	}
	sort.SliceStable(r.Assets, func(i, j int) bool { return r.Assets[i].Value < r.Assets[j].Value })
	return r
}

// RenderJSON returns the report as indented JSON.
func RenderJSON(eng *engagement.Engagement, st *state.State) ([]byte, error) {
	return json.MarshalIndent(Build(eng, st), "", "  ")
}

// Render (Markdown) is the default human-readable report, grouped by target and
// separating validated findings from unvalidated candidates.
func Render(eng *engagement.Engagement, st *state.State) string {
	r := Build(eng, st)
	var b strings.Builder

	fmt.Fprintf(&b, "# Engagement report — %s\n\n", r.EngagementID)
	fmt.Fprintf(&b, "**Client:** %s  \n", r.Client)
	fmt.Fprintf(&b, "**Authorized by:** %s  \n", r.AuthorizedBy)
	fmt.Fprintf(&b, "**Agreement:** %s  \n", r.Agreement)
	fmt.Fprintf(&b, "**Scope hash:** `%s`\n\n", r.ScopeHash)

	fmt.Fprintf(&b, "## Summary\n\n- Assets discovered: %d\n- Findings: %d (%d validated, %d candidate)\n",
		r.Totals.Assets, r.Totals.Findings, r.Totals.Validated, r.Totals.Findings-r.Totals.Validated)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := r.Totals.BySeverity[sev]; n > 0 {
			fmt.Fprintf(&b, "  - %s: %d\n", sev, n)
		}
	}
	b.WriteString("\n")

	if len(r.Findings) == 0 {
		b.WriteString("No findings recorded.\n")
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
				if f.Evidence != "" {
					fmt.Fprintf(&b, "  - evidence: `%s`\n", f.Evidence)
				}
			}
		}
		b.WriteString("\n")
	}

	writeFindings("Validated findings", true)
	writeFindings("Candidate findings (unvalidated)", false)

	b.WriteString("_The tamper-evident audit log records every decision and action; verify its hash chain to confirm this report matches what ran._\n")
	return b.String()
}
