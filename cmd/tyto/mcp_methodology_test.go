package main

import (
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/methodology"
	"github.com/dukotah/tyto/internal/state"
)

func TestCoverKey_Normalizes(t *testing.T) {
	if coverKey(" HTTP://X/ ", "HttpProbe") != coverKey("http://x/", "httpprobe") {
		t.Fatal("coverKey must be case/space-insensitive")
	}
	if coverKey("a", "t1") == coverKey("a", "t2") {
		t.Fatal("different tools must not collide")
	}
}

func TestPhasesWithTodo_ExcludesCovered(t *testing.T) {
	recs := methodology.Recommend(nil, nil) // empty is fine; we drive the helper directly
	_ = recs
	// Build a synthetic frontier via the public catalog so the test is stable.
	all := methodology.All()
	if len(all) == 0 {
		t.Skip("empty catalog")
	}
	// Two recs in different phases if possible.
	var r []methodology.Recommendation
	phases := map[string]bool{}
	for _, tech := range all {
		if phases[tech.Phase] {
			continue
		}
		phases[tech.Phase] = true
		r = append(r, methodology.Recommendation{Technique: tech, Target: "t-" + tech.Phase})
		if len(r) == 2 {
			break
		}
	}
	if len(r) < 2 {
		t.Skip("need two phases")
	}
	// Cover the first; it must drop out, the second must remain.
	covered := map[string]bool{coverKey(r[0].Target, r[0].Technique.Tool): true}
	got := phasesWithTodo(r, covered)
	for _, p := range got {
		if p == r[0].Technique.Phase && r[0].Technique.Phase != r[1].Technique.Phase {
			t.Errorf("covered phase %q should not appear in to-do", p)
		}
	}
	found := false
	for _, p := range got {
		if p == r[1].Technique.Phase {
			found = true
		}
	}
	if !found {
		t.Errorf("uncovered phase %q missing from to-do %v", r[1].Technique.Phase, got)
	}
}

func TestMethodologyText_RegisteredAndFullScope(t *testing.T) {
	// methodologyText reads only the registry + state, so build those directly.
	srv := &mcpServer{reg: defaultRegistry(), state: state.New()}
	out := srv.methodologyText()
	// The bridge must always surface the full-scope phases, even with no assets,
	// so the model is guided through internal/AD/post-ex — the whole point.
	for _, want := range []string{"Full-scope phases", "AD attack paths", "Lateral movement", "tyto_report"} {
		if !strings.Contains(out, want) {
			t.Errorf("methodology view missing %q\n---\n%s", want, out)
		}
	}
}
