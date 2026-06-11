package planner

import "strings"

import "testing"

func TestScratchpadRendersDoneAndDenied(t *testing.T) {
	s := NewScratchpad()
	s.Record(Attempt{Tool: "webcheck", Target: "http://x", Verdict: "allow", Outcome: "5 finding(s)"})
	s.Record(Attempt{Tool: "nmapscan", Target: "127.0.0.1", Verdict: "deny", Reason: `target "127.0.0.1" is not in scope`})
	out := s.Render()
	if !strings.Contains(out, "ALREADY DONE") || !strings.Contains(out, "webcheck on http://x => 5 finding(s)") {
		t.Errorf("done section missing:\n%s", out)
	}
	if !strings.Contains(out, "ALREADY DENIED") || !strings.Contains(out, "not in scope") {
		t.Errorf("denied section missing:\n%s", out)
	}
}

func TestScratchpadDedupsAndIsNilSafe(t *testing.T) {
	// nil scratchpad must be safe (single-cycle callers pass nil).
	var nilS *Scratchpad
	if nilS.Render() != "" {
		t.Error("nil Render should be empty")
	}
	nilS.Record(Attempt{Tool: "x", Target: "y", Verdict: "allow"}) // must not panic

	s := NewScratchpad()
	s.Record(Attempt{Tool: "webinject", Target: "http://x?q=", Verdict: "allow", Outcome: "1 finding(s)"})
	s.Record(Attempt{Tool: "webinject", Target: "http://x?q=", Verdict: "allow", Outcome: "again"}) // dup -> ignored
	if n := strings.Count(s.Render(), "webinject on"); n != 1 {
		t.Errorf("expected 1 webinject line after dedup, got %d", n)
	}
}

func TestScratchpadEmpty(t *testing.T) {
	if NewScratchpad().Render() != "" {
		t.Error("empty scratchpad should render nothing")
	}
}
