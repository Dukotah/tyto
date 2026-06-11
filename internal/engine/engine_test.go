package engine

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/planner"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool"
)

// fakeScanner is a deterministic tool that emits a host + http service asset,
// so the engine loop can be tested without touching the network.
type fakeScanner struct{}

func (fakeScanner) Name() string              { return "scanner" }
func (fakeScanner) Category() action.Category { return action.CategoryScan }
func (fakeScanner) MaxRisk() action.RiskLevel { return action.RiskMedium }
func (fakeScanner) Execute(_ context.Context, a action.Action) (action.Result, error) {
	return action.Result{
		ActionID: a.ID, Tool: "scanner", Success: true, Output: "scanned",
		Assets: []state.Asset{
			{ID: "h", Type: "host", Value: "h"},
			{ID: "h:80", Type: "service", Value: "h:80", Attrs: map[string]string{"port": "80", "service": "http"}},
		},
	}, nil
}

// discovered returns the assets a run actually found, excluding the ones seeded
// from the engagement scope before cycle 1 (IDs prefixed "seed:"). The seeding
// step primes the methodology frontier; these termination/resume/observe tests
// care only about what the tools discovered, so they filter it out.
func discovered(st *state.State) []*state.Asset {
	var out []*state.Asset
	for _, a := range st.Assets() {
		if !strings.HasPrefix(a.ID, "seed:") {
			out = append(out, a)
		}
	}
	return out
}

// capturingClient records every user prompt so the test can assert that the
// frontier from cycle 1 reaches the planner in cycle 2.
type capturingClient struct {
	responses []string
	prompts   []string
	i         int
}

func (c *capturingClient) Name() string { return "capture" }
func (c *capturingClient) Generate(_ context.Context, _, user string) (string, error) {
	c.prompts = append(c.prompts, user)
	r := c.responses[c.i%len(c.responses)]
	c.i++
	return r, nil
}

func TestObserveReplanLoopSurfacesDiscoveredService(t *testing.T) {
	eng := &engagement.Engagement{
		ID:     "e1",
		Client: "c",
		Scope:  engagement.Scope{InScope: []engagement.Target{{Type: engagement.TargetDomain, Value: "h"}}},
		RoE:    engagement.RoE{MaxRisk: "medium"},
	}
	reg := tool.NewRegistry()
	reg.MustRegister(fakeScanner{})

	client := &capturingClient{responses: []string{
		`{"actions":[{"tool":"scanner","category":"scan","target":"h","risk":"medium","params":{},"rationale":"enumerate"}]}`,
	}}
	g := guard.New(eng, map[string]guard.ToolMeta{"scanner": {Category: action.CategoryScan, MaxRisk: action.RiskMedium}}, nil)
	st := state.New()
	e := New(eng, g, planner.New(client), reg, st, audit.NewLog(io.Discard), io.Discard, Options{MaxCycles: 2})

	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Cycle 1 discovered a host + service asset (on top of the scope seed).
	if got := len(discovered(st)); got != 2 {
		t.Fatalf("want 2 discovered assets after the scan, got %d", got)
	}
	// Cycle 2's prompt must carry the Go-computed frontier for the discovered service.
	if len(client.prompts) < 2 {
		t.Fatalf("planner was not called a second cycle (prompts=%d)", len(client.prompts))
	}
	// The discovered service reaches cycle 2's planner via state (the observe ->
	// re-plan loop). The methodology frontier additionally recommends techniques,
	// but only for registered tools — covered by the methodology package tests.
	second := client.prompts[1]
	if !strings.Contains(second, "h:80") {
		t.Fatalf("cycle-2 prompt did not surface the discovered service:\n%s", second)
	}
}
