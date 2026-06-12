package accesscontrol

import (
	"strings"
	"testing"
)

func TestEvaluateBAC(t *testing.T) {
	realBody := strings.Repeat("user profile name email address phone city ", 8) // > minRealBody
	cases := []struct {
		name     string
		auth     response
		anon     response
		wantFlag bool
	}{
		{
			name:     "equivalent bodies same status => flag",
			auth:     response{status: 200, body: realBody},
			anon:     response{status: 200, body: realBody},
			wantFlag: true,
		},
		{
			name:     "anonymous 401 => refute",
			auth:     response{status: 200, body: realBody},
			anon:     response{status: 401, body: "unauthorized"},
			wantFlag: false,
		},
		{
			name:     "anonymous 302 redirect to login => refute",
			auth:     response{status: 200, body: realBody},
			anon:     response{status: 302, body: ""},
			wantFlag: false,
		},
		{
			name:     "anonymous different status => refute",
			auth:     response{status: 200, body: realBody},
			anon:     response{status: 404, body: realBody},
			wantFlag: false,
		},
		{
			name:     "anonymous empty body => refute",
			auth:     response{status: 200, body: realBody},
			anon:     response{status: 200, body: ""},
			wantFlag: false,
		},
		{
			name:     "anonymous dissimilar body => refute",
			auth:     response{status: 200, body: realBody},
			anon:     response{status: 200, body: strings.Repeat("totally different content here zebra quux ", 8)},
			wantFlag: false,
		},
		{
			name:     "anonymous login page signature => refute",
			auth:     response{status: 200, body: realBody},
			anon:     response{status: 200, body: "please sign in to your account " + realBody},
			wantFlag: false,
		},
		{
			name:     "auth baseline not 2xx => refute",
			auth:     response{status: 500, body: realBody},
			anon:     response{status: 500, body: realBody},
			wantFlag: false,
		},
		{
			name:     "auth baseline trivially small => refute",
			auth:     response{status: 200, body: "ok"},
			anon:     response{status: 200, body: "ok"},
			wantFlag: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := evaluateBAC(c.auth, c.anon)
			if v.flag != c.wantFlag {
				t.Fatalf("flag = %v, want %v (reason: %s)", v.flag, c.wantFlag, v.reason)
			}
			if c.wantFlag && v.evidence == "" {
				t.Errorf("flagged verdict should carry evidence")
			}
		})
	}
}

func TestEvaluateIDOR(t *testing.T) {
	// Two distinct-but-structurally-similar records (sibling objects).
	baseObj := "id 41 name alice role member email alice@example.com city portland status active"
	sibling := "id 42 name bob role member email bob@example.com city portland status active"
	cases := []struct {
		name     string
		baseline response
		mut      response
		wantFlag bool
	}{
		{
			name:     "mutated 200 distinct valid object => flag",
			baseline: response{status: 200, body: baseObj},
			mut:      response{status: 200, body: sibling},
			wantFlag: true,
		},
		{
			name:     "mutated not-found page => refute",
			baseline: response{status: 200, body: baseObj},
			mut:      response{status: 200, body: "Error: record not found for that id"},
			wantFlag: false,
		},
		{
			name:     "mutated forbidden page => refute",
			baseline: response{status: 200, body: baseObj},
			mut:      response{status: 200, body: "403 Forbidden: access denied to this object"},
			wantFlag: false,
		},
		{
			name:     "mutated non-200 => refute",
			baseline: response{status: 200, body: baseObj},
			mut:      response{status: 404, body: sibling},
			wantFlag: false,
		},
		{
			name:     "mutated identical to baseline (same object) => refute",
			baseline: response{status: 200, body: baseObj},
			mut:      response{status: 200, body: baseObj},
			wantFlag: false,
		},
		{
			name:     "mutated empty => refute",
			baseline: response{status: 200, body: baseObj},
			mut:      response{status: 200, body: ""},
			wantFlag: false,
		},
		{
			name:     "mutated wildly unrelated page => refute (too dissimilar)",
			baseline: response{status: 200, body: baseObj},
			mut:      response{status: 200, body: strings.Repeat("zebra quux frobnicate widget gadget sprocket ", 6)},
			wantFlag: false,
		},
		{
			name:     "baseline itself not a real object => refute",
			baseline: response{status: 200, body: "x"},
			mut:      response{status: 200, body: sibling},
			wantFlag: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := evaluateIDOR(c.baseline, c.mut)
			if v.flag != c.wantFlag {
				t.Fatalf("flag = %v, want %v (reason: %s)", v.flag, c.wantFlag, v.reason)
			}
		})
	}
}

func TestMutateID(t *testing.T) {
	cases := []struct {
		name      string
		paramName string
		value     string
		wantLen   int
		wantNot   []string // must not contain
	}{
		{name: "numeric mutates", paramName: "id", value: "10", wantLen: 4, wantNot: []string{"10"}},
		{name: "numeric near zero skips negatives", paramName: "id", value: "1", wantLen: 3, wantNot: []string{"-1"}},
		{name: "uuid skipped", paramName: "id", value: "550e8400-e29b-41d4-a716-446655440000", wantLen: 0},
		{name: "opaque string skipped", paramName: "token", value: "abc123xyz", wantLen: 0},
		{name: "empty skipped", paramName: "id", value: "", wantLen: 0},
		// Pagination/filter params are numeric but NOT object ids — mutating them
		// produces IDOR false positives, so they must NOT be mutated (the bug fix).
		{name: "pagination page not mutated", paramName: "page", value: "2", wantLen: 0},
		{name: "pagination limit not mutated", paramName: "limit", value: "10", wantLen: 0},
		{name: "pagination offset not mutated", paramName: "offset", value: "20", wantLen: 0},
		{name: "filter year not mutated", paramName: "year", value: "2024", wantLen: 0},
		{name: "non-id numeric q not mutated", paramName: "count", value: "5", wantLen: 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mutateID(c.paramName, c.value, maxMutations)
			if len(got) != c.wantLen {
				t.Fatalf("got %v (len %d), want len %d", got, len(got), c.wantLen)
			}
			for _, bad := range c.wantNot {
				for _, g := range got {
					if g == bad {
						t.Errorf("mutation set must not contain %q, got %v", bad, got)
					}
				}
			}
		})
	}
}

func TestLooksLikeIDParam(t *testing.T) {
	yes := []string{"id", "user_id", "accountId", "order", "uid", "documentid"}
	no := []string{"q", "search", "lang", "page_token", "format", "page", "limit", "offset", "count", "year", "size", "per_page"}
	for _, n := range yes {
		if !looksLikeIDParam(n) {
			t.Errorf("%q should look like an id param", n)
		}
	}
	for _, n := range no {
		if looksLikeIDParam(n) {
			t.Errorf("%q should NOT look like an id param", n)
		}
	}
}

func TestSimilarity(t *testing.T) {
	if s := similarity("a b c", "a b c"); s != 1 {
		t.Errorf("identical => 1, got %v", s)
	}
	if s := similarity("", ""); s != 1 {
		t.Errorf("both empty => 1, got %v", s)
	}
	if s := similarity("a b c", ""); s != 0 {
		t.Errorf("one empty => 0, got %v", s)
	}
	if s := similarity("a b c d", "a b x y"); !(s > 0.2 && s < 0.5) {
		t.Errorf("partial overlap unexpected: %v", s)
	}
}
