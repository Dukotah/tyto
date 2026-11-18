package coverage

import (
	"testing"

	"github.com/dukotah/tyto/internal/blue/attack"
)

func attackEmbedded(t *testing.T) *attack.Catalog {
	t.Helper()
	cat := attack.Embedded()
	if cat == nil || cat.Len() == 0 {
		t.Fatal("embedded ATT&CK catalog is empty")
	}
	return cat
}

func TestBuildCountsAndRollup(t *testing.T) {
	cat := attackEmbedded(t)
	// A sub-technique in covered should roll up to its parent.
	m := Build(cat, []string{"T1059.001"}, nil)

	var parent, sub *Row
	for i := range m.Rows {
		switch m.Rows[i].Technique.ID {
		case "T1059":
			parent = &m.Rows[i]
		case "T1059.001":
			sub = &m.Rows[i]
		}
	}
	if sub == nil || !sub.Covered {
		t.Fatal("sub-technique T1059.001 should be covered")
	}
	if parent == nil || !parent.Covered {
		t.Fatal("parent T1059 should roll up to covered from its sub-technique")
	}
	if m.Summary.Total != cat.Len() {
		t.Fatalf("summary total %d != catalog len %d", m.Summary.Total, cat.Len())
	}
	if m.Summary.Covered < 2 {
		t.Fatalf("expected >=2 covered (sub + parent), got %d", m.Summary.Covered)
	}
}

func TestNormalizationAndDetected(t *testing.T) {
	cat := attackEmbedded(t)
	// lowercase + whitespace must still match; detected implies a separate axis.
	m := Build(cat, []string{" t1059 "}, []string{"t1059"})
	for _, r := range m.Rows {
		if r.Technique.ID == "T1059" {
			if !r.Covered || !r.Detected {
				t.Fatalf("T1059 should be covered+detected after normalization: %+v", r)
			}
			return
		}
	}
	t.Fatal("T1059 not found in catalog")
}

func TestGapsAndUnverified(t *testing.T) {
	cat := attackEmbedded(t)
	m := Build(cat, []string{"T1059"}, nil)

	// T1059 is covered but not detected -> appears in CoveredNotDetected, not Gaps.
	inGaps, inUnverified := false, false
	for _, g := range m.Gaps() {
		if g.ID == "T1059" {
			inGaps = true
		}
	}
	for _, u := range m.CoveredNotDetected() {
		if u.ID == "T1059" {
			inUnverified = true
		}
	}
	if inGaps {
		t.Error("covered technique T1059 must not be in Gaps")
	}
	if !inUnverified {
		t.Error("covered-but-undetected T1059 must be in CoveredNotDetected")
	}
	if len(m.Gaps()) == 0 {
		t.Error("expected some uncovered techniques to be gaps")
	}
}

func TestPercentAndTactics(t *testing.T) {
	cat := attackEmbedded(t)
	m := Build(cat, nil, nil)
	if m.Summary.CoveredPct != 0 {
		t.Fatalf("empty coverage should be 0%%, got %v", m.Summary.CoveredPct)
	}
	if len(m.Tactics()) == 0 {
		t.Fatal("expected per-tactic rollups")
	}
	// tactic summaries should never exceed their total
	for _, tac := range m.Tactics() {
		s := m.ByTactic[tac]
		if s.Covered > s.Total || s.Detected > s.Total {
			t.Fatalf("tactic %s rollup inconsistent: %+v", tac, s)
		}
	}
}
