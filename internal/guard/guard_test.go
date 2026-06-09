package guard

import (
	"testing"
	"time"

	"github.com/dukotah/strix/internal/action"
	"github.com/dukotah/strix/internal/engagement"
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

// guardAt builds a guard whose clock is fixed, so time-window checks are
// deterministic in tests.
func guardAt(e *engagement.Engagement, hhmm string) *Guard {
	g := New(e)
	t, _ := time.Parse("15:04", hhmm)
	g.now = func() time.Time {
		return time.Date(2026, 1, 1, t.Hour(), t.Minute(), 0, 0, time.UTC)
	}
	return g
}

func TestEvaluate(t *testing.T) {
	e := testEngagement()
	cases := []struct {
		name      string
		act       action.Action
		wantAllow bool
	}{
		{
			name:      "in-scope scan allowed",
			act:       action.Action{Target: "203.0.113.10", Category: "scan", Risk: action.RiskMedium},
			wantAllow: true,
		},
		{
			name:      "in-scope domain recon allowed",
			act:       action.Action{Target: "https://acme.example/login", Category: "recon", Risk: action.RiskPassive},
			wantAllow: true,
		},
		{
			name:      "out-of-scope cidr denied even if in broader range",
			act:       action.Action{Target: "203.0.113.201", Category: "scan", Risk: action.RiskMedium},
			wantAllow: false,
		},
		{
			name:      "out-of-scope subdomain denied",
			act:       action.Action{Target: "legacy.acme.example", Category: "recon", Risk: action.RiskPassive},
			wantAllow: false,
		},
		{
			name:      "target not in any scope denied",
			act:       action.Action{Target: "8.8.8.8", Category: "scan", Risk: action.RiskLow},
			wantAllow: false,
		},
		{
			name:      "risk over ceiling denied",
			act:       action.Action{Target: "203.0.113.10", Category: "scan", Risk: action.RiskHigh},
			wantAllow: false,
		},
		{
			name:      "forbidden category denied",
			act:       action.Action{Target: "203.0.113.10", Category: "exploit", Risk: action.RiskLow},
			wantAllow: false,
		},
		{
			name:      "category not in allowed list denied",
			act:       action.Action{Target: "203.0.113.10", Category: "fuzz", Risk: action.RiskLow},
			wantAllow: false,
		},
	}

	g := New(e) // no time windows => anytime
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := g.Evaluate(tc.act)
			if got.Allowed != tc.wantAllow {
				t.Fatalf("Evaluate() allowed=%v reason=%q, want allowed=%v",
					got.Allowed, got.Reason, tc.wantAllow)
			}
		})
	}
}

func TestEvaluateTimeWindow(t *testing.T) {
	e := testEngagement()
	e.RoE.TimeWindows = []engagement.TimeWindow{{Start: "01:00", End: "05:00"}}
	act := action.Action{Target: "203.0.113.10", Category: "scan", Risk: action.RiskMedium}

	if d := guardAt(e, "03:00").Evaluate(act); !d.Allowed {
		t.Fatalf("inside window should allow, got deny: %s", d.Reason)
	}
	if d := guardAt(e, "12:00").Evaluate(act); d.Allowed {
		t.Fatalf("outside window should deny, got allow")
	}
}

func TestEvaluateWrappingTimeWindow(t *testing.T) {
	e := testEngagement()
	e.RoE.TimeWindows = []engagement.TimeWindow{{Start: "22:00", End: "02:00"}}
	act := action.Action{Target: "203.0.113.10", Category: "scan", Risk: action.RiskMedium}

	if d := guardAt(e, "23:30").Evaluate(act); !d.Allowed {
		t.Fatalf("23:30 inside wrapping window should allow, got: %s", d.Reason)
	}
	if d := guardAt(e, "01:00").Evaluate(act); !d.Allowed {
		t.Fatalf("01:00 inside wrapping window should allow, got: %s", d.Reason)
	}
	if d := guardAt(e, "12:00").Evaluate(act); d.Allowed {
		t.Fatalf("12:00 outside wrapping window should deny, got allow")
	}
}
