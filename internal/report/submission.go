package report

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/bounty"
	"github.com/dukotah/tyto/internal/cvss"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/triage"
	"github.com/dukotah/tyto/internal/validate"
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

// BuildSubmissionValidated is the adversarial, refute-by-default variant of
// BuildSubmission. Before triage, every raw finding is re-proved against the
// live target through the validation brain (internal/validate): only findings
// it can actively re-observe RIGHT NOW reach the actionable body. Findings it
// refutes or cannot re-prove (inconclusive) are NOT dropped — they are retained
// in the Noise bucket, tagged with the re-verification reason, so the operator
// reviews them before discarding (autonomous-scanner noise gets you banned, not
// paid). This is the form to submit to a bug-bounty program.
//
// The fetch seam is injected so this is testable; production passes
// validate.NewHTTPFetcher(). Pass a context with a deadline — re-proof makes
// live requests. NOTE: if a finding was only observable while authenticated,
// set the fetcher's session cookie at the call site, else the unauthenticated
// re-proof will refute it (it is still retained as noise, never silently lost).
func BuildSubmissionValidated(ctx context.Context, eng *engagement.Engagement, st *state.State, fetch validate.Fetcher) Submission {
	verdicts := validate.New(fetch).ValidateAll(ctx, st.Findings())
	confirmed, refuted, inconclusive := validate.Partition(verdicts)

	// Actionable body is built ONLY from re-proved findings (Validated forced
	// true, with the live re-proof appended to the evidence).
	res := triage.Triage(validate.Confirmed(verdicts))
	s := Submission{EngagementID: eng.ID, Client: eng.Client}
	for _, g := range res.Actionable {
		s.Actionable = append(s.Actionable, groupToFinding(g))
	}
	for _, g := range res.Noise {
		s.Noise = append(s.Noise, groupToFinding(g))
	}
	// Retain everything the validator set aside, tagged with why — never drop.
	for _, vd := range refuted {
		s.Noise = append(s.Noise, verdictToNoise(vd, "refuted on re-verification"))
	}
	for _, vd := range inconclusive {
		s.Noise = append(s.Noise, verdictToNoise(vd, "could not be actively re-proved"))
	}
	_ = confirmed // confirmed flows through validate.Confirmed above; named for clarity
	return s
}

// verdictToNoise projects a set-aside verdict (refuted / inconclusive) into a
// noise-tagged SubmissionFinding so it is retained and reviewable, never
// silently swallowed by the validation gate.
func verdictToNoise(vd validate.Verdict, why string) SubmissionFinding {
	f := vd.Finding
	desc := f.Description
	note := fmt.Sprintf("validation: %s (%s)", why, vd.Reason)
	if desc == "" {
		desc = note
	} else {
		desc = desc + " | " + note
	}
	sf := SubmissionFinding{
		Title:       f.Title,
		Severity:    f.Severity.String(),
		Tool:        f.Tool,
		Validated:   false,
		Targets:     []string{f.Target},
		Description: desc,
		Impact:      f.Impact,
		Repro:       f.Repro,
		Noise:       true,
	}
	if f.CVSS != "" {
		if score, err := cvss.BaseScore(f.CVSS); err == nil {
			sf.CVSS = score
			sf.CVSSVector = f.CVSS
		}
	}
	if f.Evidence != "" {
		sf.Evidence = append(sf.Evidence, TargetEvidence{Target: f.Target, Evidence: f.Evidence, Validated: false})
	}
	return sf
}

// RenderSubmissionValidated renders the adversarially-validated submission
// report: only re-proved findings appear as actionable; everything the
// validator set aside is retained, tagged, under "flagged as noise".
func RenderSubmissionValidated(ctx context.Context, eng *engagement.Engagement, st *state.State, fetch validate.Fetcher) string {
	return renderSubmission(BuildSubmissionValidated(ctx, eng, st, fetch))
}

// RenderBounty renders the BOUNTY submission gate: the payability-tiered report
// that foregrounds the payable-for-an-automated-tool classes (subdomain takeover,
// exposed .git / secrets / config, known-CVE) as actionable CANDIDATES instead of
// burying them in noise. This is the no-network overnight-sweep output — no live
// validation, so a finding reaches the actionable body on its class + tool signal
// alone (still gated by the never-submit filter + negation guard in internal/bounty).
func RenderBounty(eng *engagement.Engagement, st *state.State) string {
	return bounty.RenderGate(eng.ID, bounty.Build(st.Findings(), nil))
}

// RenderBountyValidated additionally consults the validation brain: any candidate
// a live verifier re-proves is promoted from CANDIDATE to VALIDATED (submit-first).
// fetch should carry the run's per-host session cookies (see handleReport).
func RenderBountyValidated(ctx context.Context, eng *engagement.Engagement, st *state.State, fetch validate.Fetcher) string {
	verdicts := validate.New(fetch).ValidateAll(ctx, st.Findings())
	confirmed := map[string]bool{}
	for _, vd := range verdicts {
		if vd.Confirmed() {
			confirmed[vd.Finding.ID] = true
		}
	}
	return bounty.RenderGate(eng.ID, bounty.Build(st.Findings(), confirmed))
}

// RenderSubmission renders the triaged, submission-grade Markdown report:
// actionable issues first (deduped across hosts, with impact/repro/evidence),
// then a clearly-labelled list of flagged noise that was set aside but not
// dropped.
func RenderSubmission(eng *engagement.Engagement, st *state.State) string {
	return renderSubmission(BuildSubmission(eng, st))
}

// renderSubmission renders a prepared Submission to Markdown. Shared by the
// plain (RenderSubmission) and adversarially-validated (RenderSubmissionValidated)
// entry points so both produce identical formatting.
func renderSubmission(s Submission) string {
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
