package bounty

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/cvss"
	"github.com/dukotah/tyto/internal/state"
)

// Issue is one correlated, payability-classified issue ready for the submission
// gate: the same logical problem collapsed across every host it was seen on,
// tiered (VALIDATED / CANDIDATE / NOISE), classed, ranked, and rendered to a
// submission-ready Markdown writeup.
type Issue struct {
	Title    string
	Severity state.Severity
	Tier     Tier
	Class    PayClass
	Tool     string
	// Targets is every affected host/URL, sorted and de-duplicated.
	Targets []string
	// Evidence is the per-target proof, never collapsed away on correlation.
	Evidence []Evidence
	// Issue-level rendering fields, carried from the member findings.
	Description string
	Repro       string
	Impact      string
	CVSS        string  // original vector string, if any
	CVSSScore   float64 // derived base score (0 if no/invalid vector)
	// Writeup is the rendered, submission-ready Markdown for this single issue
	// (title, severity+CVSS, affected targets, repro, impact, evidence). A
	// triager can paste it as-is.
	Writeup string

	// anyConfirmed is set during correlation when any member finding was actively
	// re-proved (Validated flag or confirmedIDs). It is the sole input to the
	// VALIDATED tier decision and is intentionally unexported.
	anyConfirmed bool
}

// Evidence is one host's proof for a correlated issue.
type Evidence struct {
	Target    string
	Evidence  string
	Validated bool
}

// Count is the number of distinct affected targets.
func (i Issue) Count() int { return len(i.Targets) }

// Actionable reports whether the issue belongs in the submit body (VALIDATED or
// CANDIDATE). NOISE is never actionable.
func (i Issue) Actionable() bool { return i.Tier == TierValidated || i.Tier == TierCandidate }

// Gate is the tiered submission projection: actionable issues (validated +
// candidate, ranked for submission) separated from retained noise. Every input
// finding is accounted for in exactly one bucket; nothing is dropped.
type Gate struct {
	// Validated are issues a live verifier re-proved. Submit-first.
	Validated []Issue
	// Candidate are high-value, near-certain issues that lacked an active
	// verifier (the payable classes). Submission-ready, tagged as candidates.
	Candidate []Issue
	// Noise is retained, never submitted: missing headers, version banners,
	// info-only. Kept for the audit trail.
	Noise []Issue
}

// Actionable returns the full submit body: validated issues first, then
// candidates, each already ranked within its tier.
func (g Gate) Actionable() []Issue {
	out := make([]Issue, 0, len(g.Validated)+len(g.Candidate))
	out = append(out, g.Validated...)
	out = append(out, g.Candidate...)
	return out
}

// verdict carries an optional, caller-supplied validation outcome for a finding,
// decoupled from internal/validate so this package stays a pure transform with no
// dependency on the validation brain. Build these from validate.Verdict at the
// call site (see the integration recipe) or leave the map nil.
//
// A finding is treated as VALIDATED only when its Validated flag is set OR the
// caller passes confirmed=true for it here.

// Build runs the submission gate over a raw finding snapshot. confirmedIDs is an
// optional set of finding IDs an active verifier re-proved (pass nil if you only
// trust the per-finding Validated flag). The input slice is never mutated and no
// finding is dropped.
//
// Tier rules:
//   - VALIDATED: the finding (or any correlated member) was actively re-proved —
//     Validated flag true, or its ID is in confirmedIDs.
//   - CANDIDATE: not validated, but its class is a payable family (takeover,
//     secret, .git, config, CVE, injection) AND it clears the precision bar.
//   - NOISE: everything else, plus every never-submit class regardless.
func Build(findings []state.Finding, confirmedIDs map[string]bool) Gate {
	groups := correlate(findings, confirmedIDs)

	var g Gate
	for _, iss := range groups {
		iss.Writeup = RenderIssue(iss)
		switch iss.Tier {
		case TierValidated:
			g.Validated = append(g.Validated, iss)
		case TierCandidate:
			g.Candidate = append(g.Candidate, iss)
		default:
			g.Noise = append(g.Noise, iss)
		}
	}

	rankIssues(g.Validated)
	rankIssues(g.Candidate)
	rankIssues(g.Noise)
	return g
}

// correlate collapses findings into logical issues keyed by (normalized title +
// class), so one systemic problem across 50 hosts becomes a single issue listing
// all 50 targets — not 50 separate submissions. Keying on class (not the raw
// tool) means the same issue surfaced by two tools still collapses.
func correlate(findings []state.Finding, confirmedIDs map[string]bool) []Issue {
	order := []string{}
	byKey := map[string]*Issue{}
	seenTarget := map[string]map[string]bool{}

	for _, f := range findings {
		class := Classify(f)
		k := normalize(f.Title) + "\x00" + fmt.Sprint(int(class))
		iss, ok := byKey[k]
		if !ok {
			iss = &Issue{
				Title:       f.Title,
				Severity:    f.Severity,
				Class:       class,
				Tool:        f.Tool,
				Description: f.Description,
				Repro:       f.Repro,
				Impact:      f.Impact,
				CVSS:        f.CVSS,
			}
			byKey[k] = iss
			order = append(order, k)
			seenTarget[k] = map[string]bool{}
		}
		// Backfill issue-level fields from later members if the first omitted them.
		if iss.Description == "" {
			iss.Description = f.Description
		}
		if iss.Repro == "" {
			iss.Repro = f.Repro
		}
		if iss.Impact == "" {
			iss.Impact = f.Impact
		}
		if iss.CVSS == "" {
			iss.CVSS = f.CVSS
		}
		// Highest severity across members wins (a single high instance lifts the
		// correlated issue).
		if f.Severity > iss.Severity {
			iss.Severity = f.Severity
		}
		confirmed := f.Validated || confirmedIDs[f.ID]
		target := f.Target
		if !seenTarget[k][target] {
			seenTarget[k][target] = true
			iss.Targets = append(iss.Targets, target)
		}
		iss.Evidence = append(iss.Evidence, Evidence{
			Target: target, Evidence: f.Evidence, Validated: confirmed,
		})
		if confirmed {
			iss.anyConfirmed = true
		}
	}

	out := make([]Issue, 0, len(order))
	for _, k := range order {
		iss := byKey[k]
		sort.Strings(iss.Targets)
		if iss.CVSS != "" {
			if score, err := cvss.BaseScore(iss.CVSS); err == nil {
				iss.CVSSScore = score
			}
		}
		iss.Tier = tierFor(*iss)
		out = append(out, *iss)
	}
	return out
}

// tierFor assigns the payability tier for a correlated issue. Precision-first:
//   - never-submit classes are NOISE, full stop;
//   - re-proved issues are VALIDATED;
//   - payable-class issues are CANDIDATE (the gate fix — these used to fall to
//     noise for lacking an active verifier);
//   - everything else is NOISE.
func tierFor(i Issue) Tier {
	if i.Class.neverSubmit() {
		return TierNoise
	}
	if i.anyConfirmed {
		return TierValidated
	}
	if i.Class.payable() {
		return TierCandidate
	}
	return TierNoise
}

// rankIssues orders issues for submission: by payability class rank (high first),
// then severity, then breadth (more affected targets first), then CVSS score,
// then title — fully deterministic.
func rankIssues(issues []Issue) {
	sort.SliceStable(issues, func(a, b int) bool {
		ia, ib := issues[a], issues[b]
		if ra, rb := ia.Class.rank(), ib.Class.rank(); ra != rb {
			return ra > rb
		}
		if ia.Severity != ib.Severity {
			return ia.Severity > ib.Severity
		}
		if ia.Count() != ib.Count() {
			return ia.Count() > ib.Count()
		}
		if ia.CVSSScore != ib.CVSSScore {
			return ia.CVSSScore > ib.CVSSScore
		}
		return ia.Title < ib.Title
	})
}

// RenderIssue renders one issue to submission-ready Markdown: title, severity
// (with CVSS where present), the payability tier and class, affected targets,
// description, reproduction, impact and per-target evidence — clean enough for a
// triager to accept as-is.
func RenderIssue(i Issue) string {
	var b strings.Builder

	fmt.Fprintf(&b, "## %s\n\n", strings.TrimSpace(i.Title))

	// Severity line with CVSS.
	sevLine := fmt.Sprintf("**Severity:** %s", strings.ToUpper(i.Severity.String()))
	if i.CVSSScore > 0 {
		sevLine += fmt.Sprintf(" (CVSS %.1f)", i.CVSSScore)
	}
	fmt.Fprintf(&b, "%s\n\n", sevLine)
	if i.CVSS != "" {
		fmt.Fprintf(&b, "**CVSS vector:** `%s`\n\n", i.CVSS)
	}

	fmt.Fprintf(&b, "**Tier:** %s  |  **Class:** %s\n\n", i.Tier.String(), i.Class.label())

	// Affected targets.
	fmt.Fprintf(&b, "**Affected target(s) (%d):**\n", len(i.Targets))
	for _, t := range i.Targets {
		fmt.Fprintf(&b, "- %s\n", t)
	}
	b.WriteString("\n")

	if d := strings.TrimSpace(i.Description); d != "" {
		fmt.Fprintf(&b, "**Description:** %s\n\n", d)
	}

	// Reproduction — always present a heading so the writeup is structurally
	// complete; fall back to a per-target stub if the tool gave no explicit steps.
	b.WriteString("**Reproduction:**\n\n")
	if r := strings.TrimSpace(i.Repro); r != "" {
		fmt.Fprintf(&b, "%s\n\n", r)
	} else {
		fmt.Fprintf(&b, "%s\n\n", defaultRepro(i))
	}

	// Impact — always present; fall back to a class-level statement.
	impact := strings.TrimSpace(i.Impact)
	if impact == "" {
		impact = defaultImpact(i.Class)
	}
	fmt.Fprintf(&b, "**Impact:** %s\n\n", impact)

	// Evidence, per target.
	b.WriteString("**Evidence:**\n\n")
	any := false
	for _, e := range i.Evidence {
		ev := strings.TrimSpace(e.Evidence)
		if ev == "" {
			continue
		}
		tag := ""
		if e.Validated {
			tag = " (re-verified)"
		}
		fmt.Fprintf(&b, "- `%s`%s: %s\n", e.Target, tag, ev)
		any = true
	}
	if !any {
		fmt.Fprintf(&b, "- Observed by `%s` across %d target(s); see scan log for raw output.\n", i.Tool, len(i.Targets))
	}
	b.WriteString("\n")

	return b.String()
}

// defaultRepro produces a minimal, honest reproduction stub when a tool emitted
// no explicit steps, so every writeup is structurally complete.
func defaultRepro(i Issue) string {
	first := ""
	if len(i.Targets) > 0 {
		first = i.Targets[0]
	}
	switch i.Class {
	case ClassExposedGit:
		return fmt.Sprintf("Request `%s/.git/HEAD` and `%s/.git/config`; the server returns git metadata, confirming the repository is publicly readable.", first, first)
	case ClassSubdomainTakeover:
		return fmt.Sprintf("Resolve `%s` and follow its CNAME chain to an unclaimed provider; the dangling target can be registered by an attacker to serve content under this host.", first)
	case ClassExposedSecret, ClassExposedConfig:
		return fmt.Sprintf("Request `%s` and observe the sensitive material returned in the response body.", first)
	default:
		return fmt.Sprintf("Reproduce against `%s` using the tool `%s`; see the evidence below.", first, i.Tool)
	}
}

// defaultImpact gives a class-level impact statement when a tool emitted none.
func defaultImpact(c PayClass) string {
	switch c {
	case ClassSubdomainTakeover:
		return "An attacker can claim the dangling target and serve arbitrary content under a trusted hostname, enabling phishing, cookie theft, and OAuth/SSO abuse."
	case ClassExposedSecret:
		return "Leaked credentials/keys allow an attacker to authenticate to the associated service, potentially accessing or modifying protected data."
	case ClassExposedGit:
		return "The full source repository (history, secrets, internal logic) is downloadable, enabling code review for further vulnerabilities and credential extraction."
	case ClassExposedConfig:
		return "Exposed configuration may reveal credentials, internal hostnames, and infrastructure details usable to deepen compromise."
	case ClassKnownCVE:
		return "The target runs a version affected by a publicly known vulnerability with available exploit details."
	case ClassInjection:
		return "An attacker-controlled input is interpreted by the application, enabling data exfiltration or code/command execution depending on the sink."
	default:
		return "See description."
	}
}
