package main

import (
	"sort"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/engagement"
)

func TestStripWildcard(t *testing.T) {
	cases := map[string]string{
		"*.example.com":   "example.com",
		"example.com":     "example.com",
		"*.*.example.com": "example.com",
		"  *.api.foo.io ": "api.foo.io",
		"*":               "", // match-everything is rejected
		"*.":              "", // nothing left after stripping
		"":                "",
	}
	for in, want := range cases {
		if got := stripWildcard(in); got != want {
			t.Errorf("stripWildcard(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeScopeEntry(t *testing.T) {
	cases := []struct {
		name      string
		entry     scopeEntry
		wantOK    bool
		wantType  engagement.TargetType
		wantValue string
	}{
		{"wildcard domain", scopeEntry{Type: "domain", Value: "*.example.com"}, true, engagement.TargetDomain, "example.com"},
		{"wildcard auto", scopeEntry{Type: "auto", Value: "*.acme.io"}, true, engagement.TargetDomain, "acme.io"},
		// A wildcard declared as url must flatten to a suffix-matching domain, not a URL.
		{"wildcard declared url", scopeEntry{Type: "url", Value: "*.app.example.com"}, true, engagement.TargetDomain, "app.example.com"},
		{"plain domain", scopeEntry{Type: "", Value: "example.com"}, true, engagement.TargetDomain, "example.com"},
		{"full url", scopeEntry{Type: "url", Value: "https://app.example.com/login"}, true, engagement.TargetURL, "https://app.example.com/login"},
		{"ip", scopeEntry{Type: "ip", Value: "10.0.0.5"}, true, engagement.TargetIP, "10.0.0.5"},
		{"cidr", scopeEntry{Type: "cidr", Value: "192.168.1.0/24"}, true, engagement.TargetCIDR, "192.168.1.0/24"},
		{"auto cidr", scopeEntry{Type: "auto", Value: "10.0.0.0/8"}, true, engagement.TargetCIDR, "10.0.0.0/8"},
		{"empty", scopeEntry{Type: "domain", Value: "   "}, false, "", ""},
		{"bare wildcard", scopeEntry{Type: "domain", Value: "*"}, false, "", ""},
	}
	for _, c := range cases {
		got, ok := normalizeScopeEntry(c.entry)
		if ok != c.wantOK {
			t.Errorf("%s: ok = %v, want %v", c.name, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if got.Type != c.wantType || got.Value != c.wantValue {
			t.Errorf("%s: got {%s %q}, want {%s %q}", c.name, got.Type, got.Value, c.wantType, c.wantValue)
		}
	}
}

func TestToTargetsDedup(t *testing.T) {
	// A program listing the same host as a wildcard and bare domain should collapse
	// to one domain target; empties and bare wildcards are dropped.
	in := []scopeEntry{
		{Type: "domain", Value: "*.example.com"},
		{Type: "domain", Value: "example.com"},
		{Type: "auto", Value: "api.example.com"},
		{Type: "domain", Value: ""},
		{Type: "domain", Value: "*"},
	}
	got := toTargets(in)
	var vals []string
	for _, t := range got {
		vals = append(vals, t.Value)
	}
	sort.Strings(vals)
	want := []string{"api.example.com", "example.com"}
	if strings.Join(vals, ",") != strings.Join(want, ",") {
		t.Errorf("toTargets values = %v, want %v", vals, want)
	}
}

func TestNormalizeForbidden(t *testing.T) {
	cats, notes := normalizeForbidden([]string{"DoS", "social-engineering", "  ", "physical attacks", "DDoS"})
	// dos always present (default + matched); others fall to notes.
	hasDoS := false
	for _, c := range cats {
		if c == "dos" {
			hasDoS = true
		}
	}
	if !hasDoS {
		t.Errorf("expected 'dos' in forbidden categories, got %v", cats)
	}
	joined := strings.ToLower(strings.Join(notes, "|"))
	if !strings.Contains(joined, "social-engineering") || !strings.Contains(joined, "physical") {
		t.Errorf("expected non-category restrictions in notes, got %v", notes)
	}
}

func TestNormalizeForbiddenDefaultDoS(t *testing.T) {
	// Even with no forbidden text at all, dos must be forbidden on the bounty path.
	cats, _ := normalizeForbidden(nil)
	if len(cats) != 1 || cats[0] != "dos" {
		t.Errorf("default forbidden = %v, want [dos]", cats)
	}
}

func TestLooksLikePastedScope(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want bool
	}{
		{"single target", "scan example.com", false},
		{"short question", "what should I do next?", false},
		{"pentest verb", "pentest 10.0.0.5", false},
		{"multi wildcard", "Here are the targets:\n*.example.com\n*.api.example.com\n*.cdn.example.com", true},
		{"scope vocab block", "In scope:\n*.example.com\napi.example.com\nOut of scope:\nadmin.example.com", true},
		{"program rate limit", "Bug bounty program scope: *.acme.io is in scope, max 5 req/s, no DoS.", true},
		{"two wildcards inline", "targets are *.foo.com and *.bar.com under the program", true},
	}
	for _, c := range cases {
		if got := looksLikePastedScope(c.msg); got != c.want {
			t.Errorf("%s: looksLikePastedScope(%q) = %v, want %v", c.name, c.msg, got, c.want)
		}
	}
}

// TestBuildScopeEngagement_FullScope drives the deterministic engagement builder
// end-to-end (no model) and asserts the wildcard/domain/url normalization, the
// self-attested authorization, the RoE limits, and — critically — the SAFETY
// INVARIANT: in-scope wildcards match subdomains while out-of-scope always wins.
func TestBuildScopeEngagement_FullScope(t *testing.T) {
	c := &console{}
	ex := extractedScope{
		Program: "Acme",
		InScope: []scopeEntry{
			{Type: "domain", Value: "*.example.com"},
			{Type: "url", Value: "https://app.example.com/"},
			{Type: "cidr", Value: "10.0.0.0/24"},
		},
		OutOfScope: []scopeEntry{
			{Type: "domain", Value: "admin.example.com"},
		},
		Rules: scopeRules{
			MaxRPS:    3,
			Forbidden: []string{"dos", "social engineering"},
			Notes:     "No automated scanning on weekends.",
		},
	}
	eng, errMsg := c.buildScopeEngagement(ex)
	if errMsg != "" {
		t.Fatalf("buildScopeEngagement: %s", errMsg)
	}
	if err := eng.Validate(); err != nil {
		t.Fatalf("built engagement does not validate: %v", err)
	}
	if !eng.Authorization.SelfAttested() {
		t.Errorf("expected self-attested authorization, got mode %q", eng.Authorization.Mode)
	}
	if eng.RoE.MaxRPS != 3 {
		t.Errorf("MaxRPS = %g, want 3", eng.RoE.MaxRPS)
	}
	// dos must be forbidden.
	hasDoS := false
	for _, f := range eng.RoE.ForbiddenCategories {
		if f == "dos" {
			hasDoS = true
		}
	}
	if !hasDoS {
		t.Errorf("forbidden categories %v missing dos", eng.RoE.ForbiddenCategories)
	}

	// Wildcard stored as a bare domain.
	foundWildcard := false
	for _, tg := range eng.Scope.InScope {
		if tg.Type == engagement.TargetDomain && tg.Value == "example.com" {
			foundWildcard = true
		}
	}
	if !foundWildcard {
		t.Errorf("expected in-scope domain example.com (from *.example.com), got %+v", eng.Scope.InScope)
	}

	// SAFETY INVARIANT: scope behavior.
	if !eng.Scope.Contains("www.example.com") {
		t.Error("subdomain www.example.com should be in scope via wildcard suffix-match")
	}
	if !eng.Scope.Contains("10.0.0.55") {
		t.Error("10.0.0.55 should be in scope via CIDR")
	}
	if eng.Scope.Contains("admin.example.com") {
		t.Error("admin.example.com is out-of-scope and must NOT be in scope")
	}
	if eng.Scope.Contains("example.org") {
		t.Error("example.org is unrelated and must NOT be in scope")
	}
	if eng.Scope.Contains("11.0.0.1") {
		t.Error("11.0.0.1 is outside the CIDR and must NOT be in scope")
	}
}

func TestBuildScopeEngagement_NoTargets(t *testing.T) {
	c := &console{}
	_, errMsg := c.buildScopeEngagement(extractedScope{InScope: []scopeEntry{{Value: "*"}, {Value: "  "}}})
	if errMsg == "" {
		t.Error("expected an error message when no usable in-scope targets parse")
	}
}

func TestScopeSummaryPreviewsAndDoesNotLaunch(t *testing.T) {
	c := &console{}
	eng, errMsg := c.buildScopeEngagement(extractedScope{
		Program:    "Acme",
		InScope:    []scopeEntry{{Type: "domain", Value: "*.example.com"}},
		OutOfScope: []scopeEntry{{Type: "domain", Value: "admin.example.com"}},
		Rules:      scopeRules{MaxRPS: 4},
	})
	if errMsg != "" {
		t.Fatalf("build: %s", errMsg)
	}
	s := scopeSummary(eng)
	for _, want := range []string{"example.com", "admin.example.com", "In scope", "Out of scope", "yes", "no"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q:\n%s", want, s)
		}
	}
}
