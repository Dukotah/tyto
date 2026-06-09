package guard

import (
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/engagement"
)

func testEngagement() *engagement.Engagement {
	return &engagement.Engagement{
		ID:     "ENG-TEST",
		Client: "Test Co",
		Authorization: engagement.Authorization{
			AuthorizedBy: "Tester",
			AgreementRef: "REF-1",
		},
		Scope: engagement.Scope{
			InScope: []engagement.Target{
				{Type: engagement.TargetCIDR, Value: "203.0.113.0/24"},
				{Type: engagement.TargetDomain, Value: "acme.example"},
			},
			OutOfScope: []engagement.Target{
				{Type: engagement.TargetCIDR, Value: "203.0.113.200/29"},
				{Type: engagement.TargetDomain, Value: "legacy.acme.example"},
			},
		},
		RoE: engagement.RoE{
			MaxRisk:             "medium",
			AllowedCategories:   []string{"recon", "scan"},
			ForbiddenCategories: []string{"exploit", "dos"},
		},
	}
}

// testTools is the authoritative tool snapshot the guard gates on.
func testTools() map[string]ToolMeta {
	return map[string]ToolMeta{
		"portscan":      {Category: action.CategoryScan, MaxRisk: action.RiskMedium},
		"recon-passive": {Category: action.CategoryRecon, MaxRisk: action.RiskPassive},
		"exploiter":     {Category: action.CategoryExploit, MaxRisk: action.RiskHigh},
		"exploit-lite":  {Category: action.CategoryExploit, MaxRisk: action.RiskLow},
		"id-probe":      {Category: action.CategoryIdentity, MaxRisk: action.RiskLow},
	}
}

// guardAt builds a guard whose clock is fixed, so time-window checks are
// deterministic in tests.
func guardAt(e *engagement.Engagement, hhmm string) *Guard {
	g := New(e, testTools(), nil)
	t, _ := time.Parse("15:04", hhmm)
	g.now = func() time.Time {
		return time.Date(2026, 1, 1, t.Hour(), t.Minute(), 0, 0, time.UTC)
	}
	return g
}

func TestEvaluate(t *testing.T) {
	e := testEngagement()
	// Every case sets deliberately MISLEADING model-declared Category/Risk to
	// prove the guard ignores them and gates on the tool snapshot instead.
	cases := []struct {
		name      string
		act       action.Action
		wantAllow bool
	}{
		{
			name:      "in-scope scan allowed",
			act:       action.Action{Tool: "portscan", Target: "203.0.113.10", Category: "exploit", Risk: action.RiskHigh},
			wantAllow: true,
		},
		{
			name:      "in-scope domain recon allowed",
			act:       action.Action{Tool: "recon-passive", Target: "https://acme.example/login", Category: "exploit", Risk: action.RiskHigh},
			wantAllow: true,
		},
		{
			name:      "out-of-scope cidr denied even if in broader range",
			act:       action.Action{Tool: "portscan", Target: "203.0.113.201", Category: "scan", Risk: action.RiskMedium},
			wantAllow: false,
		},
		{
			name:      "out-of-scope subdomain denied",
			act:       action.Action{Tool: "recon-passive", Target: "legacy.acme.example", Category: "recon", Risk: action.RiskPassive},
			wantAllow: false,
		},
		{
			name:      "target not in any scope denied",
			act:       action.Action{Tool: "portscan", Target: "8.8.8.8", Category: "scan", Risk: action.RiskLow},
			wantAllow: false,
		},
		{
			name:      "tool risk over ceiling denied (model under-declares)",
			act:       action.Action{Tool: "exploiter", Target: "203.0.113.10", Category: "scan", Risk: action.RiskPassive},
			wantAllow: false,
		},
		{
			name:      "forbidden category denied (model claims scan)",
			act:       action.Action{Tool: "exploit-lite", Target: "203.0.113.10", Category: "scan", Risk: action.RiskPassive},
			wantAllow: false,
		},
		{
			name:      "category not in allowed list denied",
			act:       action.Action{Tool: "id-probe", Target: "203.0.113.10", Category: "scan", Risk: action.RiskLow},
			wantAllow: false,
		},
		{
			name:      "unknown tool denied",
			act:       action.Action{Tool: "ghost", Target: "203.0.113.10", Category: "scan", Risk: action.RiskPassive},
			wantAllow: false,
		},
	}

	g := New(e, testTools(), nil) // no time windows => anytime
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := g.Evaluate(tc.act)
			if got.IsAllowed() != tc.wantAllow {
				t.Fatalf("Evaluate() verdict=%s reason=%q, want allowed=%v",
					got.Verdict, got.Reason, tc.wantAllow)
			}
		})
	}
}

// TestEvaluateIgnoresModelDeclaredRisk is the regression anchor for the core
// invariant: a model that lies about its risk cannot slip past the ceiling. The
// portscan tool is RiskMedium; even when the action self-declares passive, a
// passive-ceiling engagement must DENY it.
func TestEvaluateIgnoresModelDeclaredRisk(t *testing.T) {
	e := testEngagement()
	e.RoE.MaxRisk = "passive"
	g := New(e, testTools(), nil)

	d := g.Evaluate(action.Action{
		Tool: "portscan", Target: "203.0.113.10",
		Category: "recon", Risk: action.RiskPassive, // both deliberately under-declared
	})
	if d.IsAllowed() {
		t.Fatalf("model declaring passive on a medium-risk tool must be denied, got allow")
	}
}

// TestEvaluateUnknownToolFailsClosed verifies an unregistered (e.g. hallucinated)
// tool name is denied by the guard, not silently skipped downstream.
func TestEvaluateUnknownToolFailsClosed(t *testing.T) {
	g := New(testEngagement(), testTools(), nil)
	d := g.Evaluate(action.Action{Tool: "made-up-tool", Target: "203.0.113.10"})
	if d.Verdict != VerdictDeny {
		t.Fatalf("unknown tool must be denied, got %s", d.Verdict)
	}
}

func TestEvaluateTimeWindow(t *testing.T) {
	e := testEngagement()
	e.RoE.TimeWindows = []engagement.TimeWindow{{Start: "01:00", End: "05:00"}}
	act := action.Action{Tool: "portscan", Target: "203.0.113.10"}

	if d := guardAt(e, "03:00").Evaluate(act); !d.IsAllowed() {
		t.Fatalf("inside window should allow, got deny: %s", d.Reason)
	}
	if d := guardAt(e, "12:00").Evaluate(act); d.IsAllowed() {
		t.Fatalf("outside window should deny, got allow")
	}
}

func TestEvaluateWrappingTimeWindow(t *testing.T) {
	e := testEngagement()
	e.RoE.TimeWindows = []engagement.TimeWindow{{Start: "22:00", End: "02:00"}}
	act := action.Action{Tool: "portscan", Target: "203.0.113.10"}

	if d := guardAt(e, "23:30").Evaluate(act); !d.IsAllowed() {
		t.Fatalf("23:30 inside wrapping window should allow, got: %s", d.Reason)
	}
	if d := guardAt(e, "01:00").Evaluate(act); !d.IsAllowed() {
		t.Fatalf("01:00 inside wrapping window should allow, got: %s", d.Reason)
	}
	if d := guardAt(e, "12:00").Evaluate(act); d.IsAllowed() {
		t.Fatalf("12:00 outside wrapping window should deny, got allow")
	}
}
