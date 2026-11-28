package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
)

func defenseState() *state.State {
	st := state.New()
	// app.test: rate limiting kicked in.
	st.ObserveDefense(state.DefenseObservation{Target: "app.test", Kind: state.DefenseRateLimit, Signal: "http/1.1 429", Tool: "dirfuzz", AfterActions: 4})
	st.ObserveDefense(state.DefenseObservation{Target: "app.test", Kind: state.DefenseRateLimit, Signal: "http/1.1 429", Tool: "dirfuzz"})
	st.AddCoverage(state.CoverageAnchor{AssetRef: "http://app.test/", Kind: state.CoverageAction, Ref: "dirfuzz"})
	// cdn.test: a WAF was fingerprinted.
	st.AddFinding(state.Finding{ID: "w1", Title: "WAF/CDN detected: Cloudflare", Target: "https://cdn.test/", Tool: "wafdetect", Description: "cf-ray header present"})
	st.AddCoverage(state.CoverageAnchor{AssetRef: "https://cdn.test/", Kind: state.CoverageAction, Ref: "webinject"})
	// legacy.test: injection + fuzzing, a negative WAF result, and no reaction at all.
	st.AddFinding(state.Finding{ID: "w2", Title: "No WAF/CDN fingerprinted", Target: "http://legacy.test:8080/", Tool: "wafdetect"})
	st.AddCoverage(state.CoverageAnchor{AssetRef: "http://legacy.test:8080/", Kind: state.CoverageAction, Ref: "webinject"})
	st.AddCoverage(state.CoverageAnchor{AssetRef: "http://legacy.test:8080/login", Kind: state.CoverageAction, Ref: "dirfuzz"})
	// quiet.test: only a quiet header check — no reaction would be expected, so it
	// must not be listed as "took attack-like activity".
	st.AddCoverage(state.CoverageAnchor{AssetRef: "http://quiet.test/", Kind: state.CoverageAction, Ref: "webcheck"})
	return st
}

func TestDefensiveControlsSection(t *testing.T) {
	eng := &engagement.Engagement{ID: "e1", Client: "c"}
	st := defenseState()
	r := Build(eng, st)

	if len(r.DefensiveControls) != 2 {
		t.Fatalf("want 2 controls (rate limit + WAF), got %+v", r.DefensiveControls)
	}
	rl := r.DefensiveControls[0]
	if rl.Target != "app.test" || rl.Control != "Rate limiting" || !strings.Contains(rl.Basis, "after 4 prior action(s)") || !strings.Contains(rl.Basis, "2 result(s)") {
		t.Fatalf("rate-limit view wrong: %+v", rl)
	}
	if waf := r.DefensiveControls[1]; waf.Target != "cdn.test" || !strings.Contains(waf.Control, "Cloudflare") {
		t.Fatalf("WAF view wrong: %+v", waf)
	}
	if len(r.Unchallenged) != 1 || r.Unchallenged[0].Target != "legacy.test" || strings.Join(r.Unchallenged[0].Tools, ",") != "dirfuzz,webinject" {
		t.Fatalf("unchallenged wrong (want only legacy.test with both tools): %+v", r.Unchallenged)
	}

	md := Render(eng, st)
	for _, want := range []string{"## Defensive controls observed", "Rate limiting", "Cloudflare", "**legacy.test** — dirfuzz, webinject", "tyto purple score"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if strings.Contains(md, "quiet.test** —") {
		t.Error("a host that only saw quiet checks must not be listed as unchallenged")
	}

	raw, err := RenderJSON(eng, st)
	if err != nil || !json.Valid(raw) || !strings.Contains(string(raw), `"defensive_controls"`) || !strings.Contains(string(raw), `"no_defensive_reaction"`) {
		t.Fatalf("json report missing defense fields: err=%v", err)
	}
	html, err := RenderHTML(eng, st)
	if err != nil || !strings.Contains(string(html), "Defensive controls observed") || !strings.Contains(string(html), "legacy.test") {
		t.Fatalf("html report missing defense section: err=%v", err)
	}
}

func TestDefenseSectionAbsentWhenNothingObserved(t *testing.T) {
	eng := &engagement.Engagement{ID: "e1", Client: "c"}
	st := state.New()
	if md := Render(eng, st); strings.Contains(md, "Defensive controls") {
		t.Fatal("an empty engagement must not print a defense section")
	}
	raw, _ := RenderJSON(eng, st)
	if strings.Contains(string(raw), "defensive_controls") {
		t.Fatal("empty defense fields must be omitted from JSON")
	}
}
