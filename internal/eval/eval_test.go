package eval

import (
	"context"
	"io"
	"testing"
)

func TestHermeticDemoSuite(t *testing.T) {
	sc := DemoSuite().ScoreHermetic(context.Background())

	byName := map[string]CaseScore{}
	for _, c := range sc.Cases {
		byName[c.Name] = c
	}

	// The valid 3-action case must parse and every verdict must match expectations.
	demo := byName["demo-allow-deny-deny"]
	if !demo.Parsed {
		t.Fatalf("demo case should parse, err=%s", demo.ParseErr)
	}
	if len(demo.Actions) != 3 {
		t.Fatalf("want 3 scored actions, got %d", len(demo.Actions))
	}
	for _, a := range demo.Actions {
		if !a.Match {
			t.Errorf("action %d: verdict %s, expected %s", a.Index, a.Verdict, a.Expected)
		}
	}

	// Malformed and out-of-taxonomy outputs must fail closed (not parse).
	if byName["malformed-json"].Parsed {
		t.Error("malformed JSON should not parse")
	}
	if byName["out-of-taxonomy-category"].Parsed {
		t.Error("out-of-taxonomy category should fail validation (fail closed)")
	}

	// 1 of 3 cases is schema-valid; all of that case's verdicts match.
	if sc.SchemaValidRate < 0.33 || sc.SchemaValidRate > 0.34 {
		t.Errorf("SchemaValidRate = %v, want ~0.333", sc.SchemaValidRate)
	}
	if sc.VerdictMatchRate != 1.0 {
		t.Errorf("VerdictMatchRate = %v, want 1.0", sc.VerdictMatchRate)
	}
}

func TestScorecardWriteJSON(t *testing.T) {
	if err := DemoSuite().ScoreHermetic(context.Background()).WriteJSON(io.Discard); err != nil {
		t.Fatal(err)
	}
}
