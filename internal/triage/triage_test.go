package triage

import (
	"testing"

	"github.com/dukotah/tyto/internal/state"
)

// N identical findings across N hosts must collapse into ONE issue listing all
// N affected targets — the core dedup/correlation contract.
func TestTriageCollapsesAcrossHosts(t *testing.T) {
	hosts := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	var findings []state.Finding
	for _, h := range hosts {
		findings = append(findings, state.Finding{
			Title:    "TLS 1.0 enabled",
			Severity: state.SeverityMedium,
			Target:   h,
			Tool:     "sslscan",
			Evidence: "TLSv1.0 accepted on " + h,
		})
	}

	res := Triage(findings)
	if len(res.Actionable) != 1 {
		t.Fatalf("expected 1 correlated issue, got %d", len(res.Actionable))
	}
	g := res.Actionable[0]
	if g.Count() != len(hosts) {
		t.Fatalf("expected %d affected targets, got %d (%v)", len(hosts), g.Count(), g.Targets)
	}
	// Per-target evidence must be preserved, not collapsed away.
	if len(g.Evidence) != len(hosts) {
		t.Fatalf("expected %d per-target evidence rows, got %d", len(hosts), len(g.Evidence))
	}
}

// The same check re-run on one host must not double-count that target.
func TestTriageDeduplicatesRepeatedTarget(t *testing.T) {
	findings := []state.Finding{
		{Title: "X", Severity: state.SeverityLow, Target: "h1", Tool: "t", Evidence: "a"},
		{Title: "X", Severity: state.SeverityLow, Target: "h1", Tool: "t", Evidence: "b"},
	}
	res := Triage(findings)
	if len(res.Actionable) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(res.Actionable))
	}
	if c := res.Actionable[0].Count(); c != 1 {
		t.Fatalf("repeated target should count once, got %d", c)
	}
	// But both pieces of evidence are kept.
	if len(res.Actionable[0].Evidence) != 2 {
		t.Fatalf("expected both evidence rows retained, got %d", len(res.Actionable[0].Evidence))
	}
}

// Title normalization (case + whitespace) must correlate cosmetically-different
// titles; differing tool or severity must NOT correlate.
func TestTriageKeying(t *testing.T) {
	findings := []state.Finding{
		{Title: "TLS 1.0  Enabled", Severity: state.SeverityMedium, Target: "h1", Tool: "t"},
		{Title: "tls 1.0 enabled", Severity: state.SeverityMedium, Target: "h2", Tool: "t"},
		// Different tool -> separate issue.
		{Title: "TLS 1.0 enabled", Severity: state.SeverityMedium, Target: "h3", Tool: "other"},
		// Different severity -> separate issue.
		{Title: "TLS 1.0 enabled", Severity: state.SeverityHigh, Target: "h4", Tool: "t"},
	}
	res := Triage(findings)
	if len(res.Actionable) != 3 {
		t.Fatalf("expected 3 distinct issues, got %d", len(res.Actionable))
	}
}

// A single validated instance makes the correlated issue actionable/validated.
func TestTriageValidatedAny(t *testing.T) {
	findings := []state.Finding{
		{Title: "X", Severity: state.SeverityHigh, Target: "h1", Tool: "t", Validated: false},
		{Title: "X", Severity: state.SeverityHigh, Target: "h2", Tool: "t", Validated: true},
	}
	res := Triage(findings)
	if len(res.Actionable) != 1 || !res.Actionable[0].Validated {
		t.Fatalf("expected one validated issue, got %+v", res.Actionable)
	}
}

// Info-level low-signal titles are FLAGGED as noise (and never dropped);
// actionable findings stay actionable.
func TestTriageFlagsNoise(t *testing.T) {
	findings := []state.Finding{
		{Title: "IKEv2 detected", Severity: state.SeverityInfo, Target: "h1", Tool: "nuclei"},
		{Title: "SNMPv3 detected", Severity: state.SeverityInfo, Target: "h1", Tool: "nuclei"},
		{Title: "SQL injection", Severity: state.SeverityHigh, Target: "h1", Tool: "webinject"},
	}
	res := Triage(findings)
	if len(res.Actionable) != 1 {
		t.Fatalf("expected 1 actionable, got %d", len(res.Actionable))
	}
	if len(res.Noise) != 2 {
		t.Fatalf("expected 2 noise issues, got %d", len(res.Noise))
	}
	// Nothing dropped: every issue is accounted for.
	if got := len(res.All()); got != 3 {
		t.Fatalf("expected 3 issues total (none dropped), got %d", got)
	}
	for _, g := range res.Noise {
		if !g.Noise {
			t.Errorf("noise group %q not marked Noise", g.Title)
		}
	}
}

func TestIsNoise(t *testing.T) {
	cases := []struct {
		sev   state.Severity
		title string
		want  bool
	}{
		{state.SeverityInfo, "IKEv2 detected", true},
		{state.SeverityInfo, "SNMPv3 detected", true},
		{state.SeverityInfo, "Server version disclosed", true},
		// Same low-signal title but non-info severity must NOT be flagged —
		// severity-bearing findings are never pushed below the fold.
		{state.SeverityMedium, "IKEv2 detected", false},
		// Info but a real issue title -> not flagged.
		{state.SeverityInfo, "Exposed .git directory with source", false},
	}
	for _, c := range cases {
		if got := IsNoise(c.sev, c.title); got != c.want {
			t.Errorf("IsNoise(%v, %q) = %v, want %v", c.sev, c.title, got, c.want)
		}
	}
}

// Actionable issues sort by severity (high first) then breadth.
func TestTriageSortOrder(t *testing.T) {
	findings := []state.Finding{
		{Title: "low one", Severity: state.SeverityLow, Target: "h1", Tool: "t"},
		{Title: "high broad", Severity: state.SeverityHigh, Target: "h1", Tool: "t"},
		{Title: "high broad", Severity: state.SeverityHigh, Target: "h2", Tool: "t"},
		{Title: "high narrow", Severity: state.SeverityHigh, Target: "h3", Tool: "t2"},
	}
	res := Triage(findings)
	if len(res.Actionable) != 3 {
		t.Fatalf("expected 3 issues, got %d", len(res.Actionable))
	}
	if res.Actionable[0].Title != "high broad" {
		t.Errorf("expected broadest high-severity issue first, got %q", res.Actionable[0].Title)
	}
	if res.Actionable[len(res.Actionable)-1].Severity != state.SeverityLow {
		t.Errorf("expected low-severity issue last")
	}
}

// Triage must not mutate the input slice.
func TestTriageDoesNotMutateInput(t *testing.T) {
	in := []state.Finding{
		{Title: "X", Severity: state.SeverityHigh, Target: "h1", Tool: "t"},
	}
	Triage(in)
	if in[0].Title != "X" || in[0].Target != "h1" {
		t.Fatalf("input finding was mutated: %+v", in[0])
	}
}
