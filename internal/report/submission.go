package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/cvss"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/triage"
)

// Submission is the triaged, submission-grade projection of an engagement: the
// raw finding stream collapsed into logical issues (deduplicated and correlated
// across hosts) with likely-noise foregrounded separately from actionable work.
// It is the form you hand to a client or paste into a bug-bounty submission —
// every actionable issue carries the fields a triager needs to act: severity
// (with CVSS where available), the affected target(s), reproduction steps,
// impact, and per-target evidence.
type Submission struct {
	EngagementID string              `json:"engagement_id"`
	Client       string              `json:"client"`
	Actionable   []SubmissionFinding `json:"actionable"`
	// Noise is retained, not dropped: likely-informational / false-positive
	// issues are surfaced separately so nothing is silently swallowed.
	Noise []SubmissionFinding `json:"noise,omitempty"`
}

// SubmissionFinding is one correlated issue ready for submission.
type SubmissionFinding struct {
	Title      string  `json:"title"`
	Severity   string  `json:"severity"`
	CVSS       float64 `json:"cvss,omitempty"`
	CVSSVector string  `json:"cvss_vector,omitempty"`
	Tool       string  `json:"tool,omitempty"`
	Validated  bool    `json:"validated"`
	// Targets is every affected host/URL the issue was observed on.
	Targets     []string         `json:"targets"`
	Description string           `json:"description,omitempty"`
	Impact      string           `json:"impact,omitempty"`
	Repro       string           `json:"repro,omitempty"`
	Evidence    []TargetEvidence `json:"evidence,omitempty"`
	Noise       bool             `json:"noise,omitempty"`
}

// TargetEvidence is one host's evidence for a correlated issue (kept per-target
// so correlation never discards a host's proof).
type TargetEvidence struct {
	Target    string `json:"target"`
	Evidence  string `json:"evidence,omitempty"`
	Validated bool   `json:"validated"`
}

// groupToFinding projects a triage.Group into the submission view, deriving the
// CVSS base score from the issue's vector where one is present.
func groupToFinding(g triage.Group) SubmissionFinding {
	sf := SubmissionFinding{
		Title:       g.Title,
		Severity:    g.Severity.String(),
		Tool:        g.Tool,
		Validated:   g.Validated,
		Targets:     g.Targets,
		Description: g.Description,
		Impact:      g.Impact,
		Repro:       g.Repro,
		Noise:       g.Noise,
	}
	if g.CVSS != "" {
		if score, err := cvss.BaseScore(g.CVSS); err == nil {
			sf.CVSS = score
			sf.CVSSVector = g.CVSS
		}
	}
	for _, e := range g.Evidence {
		if e.Evidence == "" {
			continue // omit empty per-target rows; the target is already listed
		}
		sf.Evidence = append(sf.Evidence, TargetEvidence{
			Target: e.Target, Evidence: e.Evidence, Validated: e.Validated,
		})
	}
	sort.SliceStable(sf.Evidence, func(i, j int) bool { return sf.Evidence[i].Target < sf.Evidence[j].Target })
	return sf
}

// BuildSubmission assembles the triaged Submission from engagement state. It
// reads a snapshot of findings (storage is untouched) and runs the deterministic
// triage projection.
func BuildSubmission(eng *engagement.Engagement, st *state.State) Submission {
	res := triage.Triage(st.Findings())
	s := Submission{EngagementID: eng.ID, Client: eng.Client}
	for _, g := range res.Actionable {
		s.Actionable = append(s.Actionable, groupToFinding(g))
	}
	for _, g := range res.Noise {
		s.Noise = append(s.Noise, groupToFinding(g))
	}
	return s
}

// RenderSubmission renders the triaged, submission-grade Markdown report:
// actionable issues first (deduped across hosts, with impact/repro/evidence),
// then a clearly-labelled list of flagged noise that was set aside but not
// dropped.
func RenderSubmission(eng *engagement.Engagement, st *state.State) string {
	s := BuildSubmission(eng, st)
	var b strings.Builder

	fmt.Fprintf(&b, "# Submission report — %s\n\n", s.EngagementID)
	if s.Client != "" {
		fmt.Fprintf(&b, "**Client:** %s\n\n", s.Client)
	}
	fmt.Fprintf(&b, "Actionable issues: %d  |  Flagged as noise: %d\n\n", len(s.Actionable), len(s.Noise))

	if len(s.Actionable) == 0 {
		b.WriteString("No actionable findings after triage.\n\n")
	} else {
		b.WriteString("## Actionable findings\n\n")
		for i, f := range s.Actionable {
			writeSubmissionFinding(&b, i+1, f)
		}
	}

	if len(s.Noise) > 0 {
		b.WriteString("## Flagged as noise (informational / likely false positive)\n\n")
		b.WriteString("_Retained for completeness — review before discarding; not included above._\n\n")
		for _, f := range s.Noise {
			fmt.Fprintf(&b, "- **[%s]** %s (`%s`) — %d target(s)\n",
				strings.ToUpper(f.Severity), f.Title, f.Tool, len(f.Targets))
		}
		b.WriteString("\n")
	}

	b.WriteString("_The tamper-evident audit log records every decision and action; verify its hash chain to confirm this report matches what ran._\n")
	return b.String()
}

// writeSubmissionFinding renders one actionable issue with the full
// submission-grade field set.
func writeSubmissionFinding(b *strings.Builder, n int, f SubmissionFinding) {
	cvssTag := ""
	if f.CVSS > 0 {
		cvssTag = fmt.Sprintf(" — CVSS %.1f", f.CVSS)
	}
	status := "candidate"
	if f.Validated {
		status = "validated"
	}
	fmt.Fprintf(b, "### %d. %s\n\n", n, f.Title)
	fmt.Fprintf(b, "- **Severity:** %s%s (%s)\n", strings.ToUpper(f.Severity), cvssTag, status)
	if f.CVSSVector != "" {
		fmt.Fprintf(b, "- **CVSS vector:** `%s`\n", f.CVSSVector)
	}
	fmt.Fprintf(b, "- **Affected target(s) (%d):** %s\n", len(f.Targets), strings.Join(f.Targets, ", "))
	if f.Description != "" {
		fmt.Fprintf(b, "- **Description:** %s\n", f.Description)
	}
	if f.Impact != "" {
		fmt.Fprintf(b, "- **Impact:** %s\n", f.Impact)
	}
	if f.Repro != "" {
		fmt.Fprintf(b, "- **Reproduction:** %s\n", f.Repro)
	}
	if len(f.Evidence) > 0 {
		b.WriteString("- **Evidence:**\n")
		for _, e := range f.Evidence {
			fmt.Fprintf(b, "  - `%s`: %s\n", e.Target, e.Evidence)
		}
	}
	b.WriteString("\n")
}
