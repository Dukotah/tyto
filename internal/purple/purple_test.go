package purple

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/blue/attack"
	"github.com/dukotah/tyto/internal/blue/detect"
	"github.com/dukotah/tyto/internal/blue/event"
)

// fixtureAttacker replays canned steps (stands in for a live tyto attack + sensor).
type fixtureAttacker struct{ steps []Step }

func (f fixtureAttacker) Run(context.Context) ([]Step, error) { return f.steps, nil }

func newEngine(t *testing.T) *Engine {
	t.Helper()
	det, err := detect.NewDetector()
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	return New(det, attack.Embedded())
}

func TestPurpleDetectsAndMisses(t *testing.T) {
	e := newEngine(t)

	// Step 1 (T1571): outbound to Metasploit handler port 4444 -> an embedded
	// rule should fire => detected.
	detectedStep := Step{Technique: "T1571", Name: "c2-handler-port", Events: []event.Event{
		func() event.Event {
			ev := event.New("suricata", "network_activity")
			ev.DstIP, ev.DstPort = "203.0.113.9", 4444
			return ev
		}(),
	}}

	// Step 2 (T1613, container discovery): no embedded rule covers it => missed,
	// and a draft rule should be generated from the exemplar event.
	missedStep := Step{Technique: "T1613", Name: "container-discovery", Events: []event.Event{
		func() event.Event {
			ev := event.New("sysmon", "process_activity")
			ev.Process = `C:\Program Files\Docker\docker.exe`
			ev.CommandLine = "docker ps --all --quiet"
			return ev
		}(),
	}}

	rep, err := e.Run(context.Background(), fixtureAttacker{steps: []Step{detectedStep, missedStep}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !contains(rep.Attacked, "T1571") || !contains(rep.Attacked, "T1613") {
		t.Fatalf("Attacked = %v, want both T1571 and T1613", rep.Attacked)
	}
	if !contains(rep.Detected, "T1571") {
		t.Errorf("T1571 (port 4444) should be detected; Detected = %v, FiredRules = %v", rep.Detected, rep.FiredRules)
	}
	if !contains(rep.Missed, "T1613") {
		t.Errorf("T1613 should be missed; Missed = %v", rep.Missed)
	}
	if contains(rep.Missed, "T1571") {
		t.Errorf("T1571 must not be in Missed")
	}

	// a draft rule for the miss, tagged with the technique and keyed on the exemplar
	var draft *DraftRule
	for i := range rep.Drafts {
		if rep.Drafts[i].Technique == "T1613" {
			draft = &rep.Drafts[i]
		}
	}
	if draft == nil {
		t.Fatalf("expected a draft rule for missed T1613; drafts = %+v", rep.Drafts)
	}
	if !strings.Contains(draft.YAML, "attack.t1613") {
		t.Errorf("draft YAML missing technique tag:\n%s", draft.YAML)
	}
	if !strings.Contains(strings.ToLower(draft.YAML), "docker") {
		t.Errorf("draft YAML should key on the exemplar (docker.exe / docker ps):\n%s", draft.YAML)
	}
	if !strings.Contains(draft.YAML, "condition: selection") {
		t.Errorf("draft YAML not a well-formed Sigma stub:\n%s", draft.YAML)
	}

	// coverage matrix spans the whole catalog
	if rep.Matrix.Summary.Total != attack.Embedded().Len() {
		t.Errorf("matrix total %d != catalog %d", rep.Matrix.Summary.Total, attack.Embedded().Len())
	}
	if rep.Events != 2 {
		t.Errorf("Events = %d, want 2", rep.Events)
	}
}

func TestPurpleNoStepsIsClean(t *testing.T) {
	e := newEngine(t)
	rep, err := e.Run(context.Background(), fixtureAttacker{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Attacked) != 0 || len(rep.Drafts) != 0 || rep.Events != 0 {
		t.Fatalf("empty run should be empty: %+v", rep)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
