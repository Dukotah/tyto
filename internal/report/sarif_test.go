package report

import (
	"encoding/json"
	"testing"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
)

func TestRenderSARIFWellFormed(t *testing.T) {
	eng := &engagement.Engagement{ID: "E", Client: "C"}
	st := state.New()
	st.AddFinding(state.Finding{Title: "Missing security header: HSTS", Severity: state.SeverityMedium, Target: "http://h/", Tool: "webcheck", Validated: true, Description: "no HSTS"})
	st.AddFinding(state.Finding{Title: "Server version disclosed", Severity: state.SeverityLow, Target: "http://h/", Tool: "webcheck", Validated: true})

	data, err := RenderSARIF(eng, st)
	if err != nil {
		t.Fatal(err)
	}

	// Must be valid JSON with the SARIF shape.
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if parsed["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", parsed["version"])
	}

	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "tyto" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 2 || len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("want 2 results + 2 rules, got %d/%d", len(run.Results), len(run.Tool.Driver.Rules))
	}
	// Severity -> level mapping and ruleIndex validity.
	for _, r := range run.Results {
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("ruleIndex %d out of range", r.RuleIndex)
		}
		if r.Level != "warning" && r.Level != "note" {
			t.Errorf("unexpected level %q", r.Level)
		}
		if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "http://h/" {
			t.Errorf("location uri = %q", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	cases := map[state.Severity]string{
		state.SeverityCritical: "error",
		state.SeverityHigh:     "error",
		state.SeverityMedium:   "warning",
		state.SeverityLow:      "note",
		state.SeverityInfo:     "note",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%s) = %q, want %q", sev, got, want)
		}
	}
}
