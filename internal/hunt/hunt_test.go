package hunt

import (
	"reflect"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
)

// scopeOf builds a Scope from a list of in-scope root domains.
func scopeOf(domains ...string) engagement.Scope {
	var in []engagement.Target
	for _, d := range domains {
		in = append(in, engagement.Target{Type: engagement.TargetDomain, Value: d})
	}
	return engagement.Scope{InScope: in}
}

// tools extracts the (tool, target) pairs from a plan, in order.
type tt struct{ tool, target string }

func pairs(as []action.Action) []tt {
	out := make([]tt, 0, len(as))
	for _, a := range as {
		out = append(out, tt{a.Tool, a.Target})
	}
	return out
}

func doneFrom(as []action.Action) map[string]bool {
	d := map[string]bool{}
	for _, a := range as {
		d[a.CanonicalKey()] = true
	}
	return d
}

// --- Stage 1: enumerate -----------------------------------------------------

func TestStage1_SubfinderPerRootDomain_SortedDeduped(t *testing.T) {
	sc := scopeOf("zeta.com", "alpha.com", "alpha.com") // dup + unsorted
	got := Plan(nil, sc, nil, Options{})
	want := []tt{
		{toolSubfinder, "alpha.com"},
		{toolSubfinder, "zeta.com"},
	}
	if !reflect.DeepEqual(pairs(got), want) {
		t.Fatalf("stage1 mismatch:\n got %v\nwant %v", pairs(got), want)
	}
	for _, a := range got {
		if a.Risk != action.RiskPassive {
			t.Errorf("subfinder should be passive, got %v for %s", a.Risk, a.Target)
		}
		if a.Category != action.CategoryRecon.String() {
			t.Errorf("subfinder category = %q, want recon", a.Category)
		}
	}
}

func TestStage1_SkipsNonDomainRoots(t *testing.T) {
	sc := engagement.Scope{InScope: []engagement.Target{
		{Type: engagement.TargetDomain, Value: "example.com"},
		{Type: engagement.TargetIP, Value: "10.0.0.1"},
		{Type: engagement.TargetCIDR, Value: "10.0.0.0/24"},
		{Type: engagement.TargetURL, Value: "https://app.example.com/x"},
	}}
	got := Plan(nil, sc, nil, Options{})
	if want := []tt{{toolSubfinder, "example.com"}}; !reflect.DeepEqual(pairs(got), want) {
		t.Fatalf("only domain roots are enumerable:\n got %v\nwant %v", pairs(got), want)
	}
}

func TestStage1_OutOfScopeRootDropped(t *testing.T) {
	sc := engagement.Scope{
		InScope:    []engagement.Target{{Type: engagement.TargetDomain, Value: "example.com"}},
		OutOfScope: []engagement.Target{{Type: engagement.TargetDomain, Value: "example.com"}},
	}
	if got := Plan(nil, sc, nil, Options{}); len(got) != 0 {
		t.Fatalf("out-of-scope root must not be enumerated, got %v", pairs(got))
	}
}

// --- Stage 2: liveness ------------------------------------------------------

func newState(assets ...state.Asset) *state.State {
	st := state.New()
	for i := range assets {
		a := assets[i]
		st.AddAsset(&a)
	}
	return st
}

func TestStage2_HTTPProbePerDiscoveredHost_InScopeOnly(t *testing.T) {
	st := newState(
		state.Asset{ID: "d1", Type: "domain", Value: "b.example.com"},
		state.Asset{ID: "d2", Type: "domain", Value: "a.example.com"},
		state.Asset{ID: "h1", Type: "host", Value: "1.2.3.4"},           // not in scope
		state.Asset{ID: "d3", Type: "domain", Value: "x.evil.com"},      // out of scope
		state.Asset{ID: "u1", Type: "url", Value: "https://a.example.com/p"}, // not a probe target
	)
	got := Plan(st, scopeOf("example.com"), nil, Options{})
	// Stage 1 (subfinder example.com) then stage 2 probes (sorted), then no live hosts.
	want := []tt{
		{toolSubfinder, "example.com"},
		{toolHTTPProbe, "a.example.com"},
		{toolHTTPProbe, "b.example.com"},
	}
	if !reflect.DeepEqual(pairs(got), want) {
		t.Fatalf("stage2 mismatch:\n got %v\nwant %v", pairs(got), want)
	}
}

// --- Stage 3: payable battery, breadth-first --------------------------------

func TestStage3_BreadthFirstPayableBattery(t *testing.T) {
	// Two live hosts via service assets. No domain assets => no stage-2 probes.
	st := newState(
		state.Asset{ID: "s1", Type: "service", Value: "https://h2.example.com", Attrs: map[string]string{"service": "https"}},
		state.Asset{ID: "s2", Type: "service", Value: "http://h1.example.com:80", Attrs: map[string]string{"service": "http"}},
	)
	got := Plan(st, scopeOf("example.com"), nil, Options{})
	want := []tt{
		{toolSubfinder, "example.com"},
		// breadth-first: each probe sweeps ALL hosts before the next probe
		{toolSubtakeover, "h1.example.com"}, {toolSubtakeover, "h2.example.com"},
		{toolDotgit, "h1.example.com"}, {toolDotgit, "h2.example.com"},
		{toolSecretScan, "h1.example.com"}, {toolSecretScan, "h2.example.com"},
		{toolTemplateScan, "h1.example.com"}, {toolTemplateScan, "h2.example.com"},
		{toolWebDiscover, "h1.example.com"}, {toolWebDiscover, "h2.example.com"},
	}
	if !reflect.DeepEqual(pairs(got), want) {
		t.Fatalf("stage3 breadth-first mismatch:\n got %v\nwant %v", pairs(got), want)
	}
}

func TestStage3_NoNoisyTools(t *testing.T) {
	st := newState(
		state.Asset{ID: "s1", Type: "service", Value: "https://h.example.com", Attrs: map[string]string{"service": "https"}},
	)
	got := Plan(st, scopeOf("example.com"), nil, Options{})
	banned := map[string]bool{"nmapscan": true, "ffuf": true, "dirfuzz": true, "webinject": true, "sqlmap": true, "sqliexploit": true, "ssti": true, "portscan": true}
	for _, a := range got {
		if banned[a.Tool] {
			t.Errorf("hunt must not emit noisy tool %q", a.Tool)
		}
	}
}

func TestStage3_LivenessFlaggedDomainCountsAsLive(t *testing.T) {
	st := newState(
		state.Asset{ID: "d1", Type: "domain", Value: "live.example.com", Attrs: map[string]string{"live": "true"}},
		state.Asset{ID: "d2", Type: "domain", Value: "dead.example.com"}, // not flagged live
	)
	got := Plan(st, scopeOf("example.com"), nil, Options{})
	// Both get a stage-2 probe; only the flagged one gets the payable battery.
	var subtakeoverTargets []string
	for _, a := range got {
		if a.Tool == toolSubtakeover {
			subtakeoverTargets = append(subtakeoverTargets, a.Target)
		}
	}
	if !reflect.DeepEqual(subtakeoverTargets, []string{"live.example.com"}) {
		t.Fatalf("only live-flagged host should enter battery, got %v", subtakeoverTargets)
	}
}

// --- Determinism + resumability ---------------------------------------------

func TestDeterministic(t *testing.T) {
	st := newState(
		state.Asset{ID: "s1", Type: "service", Value: "https://a.example.com", Attrs: map[string]string{"service": "https"}},
		state.Asset{ID: "s2", Type: "service", Value: "https://b.example.com", Attrs: map[string]string{"service": "https"}},
		state.Asset{ID: "d1", Type: "domain", Value: "c.example.com"},
	)
	sc := scopeOf("example.com", "other.com")
	a := Plan(st, sc, nil, Options{})
	b := Plan(st, sc, nil, Options{})
	if !reflect.DeepEqual(pairs(a), pairs(b)) {
		t.Fatalf("Plan is not deterministic:\n%v\n%v", pairs(a), pairs(b))
	}
}

func TestResumable_DoneSkips(t *testing.T) {
	st := newState(
		state.Asset{ID: "s1", Type: "service", Value: "https://a.example.com", Attrs: map[string]string{"service": "https"}},
	)
	sc := scopeOf("example.com")
	full := Plan(st, sc, nil, Options{})
	if len(full) == 0 {
		t.Fatal("expected a non-empty initial plan")
	}
	// Mark everything done; a resumed plan must be empty (exhausted).
	done := doneFrom(full)
	if again := Plan(st, sc, done, Options{}); len(again) != 0 {
		t.Fatalf("fully-done plan should be empty, got %v", pairs(again))
	}
	// Mark only the first half done; the remainder must be exactly the tail.
	half := doneFrom(full[:len(full)/2])
	rest := Plan(st, sc, half, Options{})
	if !reflect.DeepEqual(pairs(rest), pairs(full[len(full)/2:])) {
		t.Fatalf("partial resume mismatch:\n got %v\nwant %v", pairs(rest), pairs(full[len(full)/2:]))
	}
}

func TestExhaustedReturnsEmpty(t *testing.T) {
	if got := Plan(state.New(), scopeOf(), nil, Options{}); len(got) != 0 {
		t.Fatalf("empty scope+state should yield no actions, got %v", pairs(got))
	}
}

// --- Boundedness ------------------------------------------------------------

func liveServiceState(n int) (*state.State, engagement.Scope) {
	st := state.New()
	for i := 0; i < n; i++ {
		host := hostName(i)
		a := state.Asset{ID: "s" + host, Type: "service", Value: "https://" + host, Attrs: map[string]string{"service": "https"}}
		st.AddAsset(&a)
	}
	return st, scopeOf("example.com")
}

func hostName(i int) string {
	// h000.example.com ... ensures lexical order == numeric order for asserts.
	return "h" + pad(i) + ".example.com"
}

func pad(i int) string {
	s := []byte("000")
	for p := 2; p >= 0 && i > 0; p-- {
		s[p] = byte('0' + i%10)
		i /= 10
	}
	return string(s)
}

func TestCap_TruncatesAndEmitsNote(t *testing.T) {
	st, sc := liveServiceState(10)
	got := Plan(st, sc, nil, Options{MaxHosts: 3})

	// Count distinct hosts the payable battery touched.
	hosts := map[string]bool{}
	var notes int
	for _, a := range got {
		if IsNote(a) {
			notes++
			continue
		}
		if a.Tool == toolSubtakeover {
			hosts[a.Target] = true
		}
	}
	if len(hosts) != 3 {
		t.Fatalf("cap=3 should sweep 3 hosts, swept %d: %v", len(hosts), hosts)
	}
	// Swept hosts must be the deterministic first 3 (lexical order).
	wantHosts := map[string]bool{"h000.example.com": true, "h001.example.com": true, "h002.example.com": true}
	if !reflect.DeepEqual(hosts, wantHosts) {
		t.Fatalf("capped hosts not the deterministic prefix: %v", hosts)
	}
	if notes != 1 {
		t.Fatalf("expected exactly one cap note, got %d", notes)
	}
}

func TestCap_NoNoteWhenUnderCap(t *testing.T) {
	st, sc := liveServiceState(3)
	got := Plan(st, sc, nil, Options{MaxHosts: 100})
	for _, a := range got {
		if IsNote(a) {
			t.Fatalf("no note expected when under cap, got %q", a.Rationale)
		}
	}
}

func TestCap_NoteIsNotReEmittedOnResume(t *testing.T) {
	st, sc := liveServiceState(10)
	full := Plan(st, sc, nil, Options{MaxHosts: 3})
	done := doneFrom(full)
	if again := Plan(st, sc, done, Options{MaxHosts: 3}); len(again) != 0 {
		t.Fatalf("resumed capped plan should be empty (note included in done), got %v", pairs(again))
	}
}

func TestDefaultCapApplied(t *testing.T) {
	if (Options{}).maxHosts() != DefaultMaxHosts {
		t.Fatalf("zero Options should use DefaultMaxHosts=%d", DefaultMaxHosts)
	}
	if (Options{MaxHosts: -5}).maxHosts() != DefaultMaxHosts {
		t.Fatalf("non-positive MaxHosts should fall back to default")
	}
}

// --- Note routing -----------------------------------------------------------

func TestIsNote(t *testing.T) {
	if !IsNote(action.Action{Tool: NoteTool}) {
		t.Fatal("NoteTool action should be a note")
	}
	if IsNote(action.Action{Tool: toolSubfinder}) {
		t.Fatal("real tool should not be a note")
	}
}
