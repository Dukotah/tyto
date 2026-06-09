package engine

import (
	"context"
	"io"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/planner"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool"
)

// countingClient always proposes the SAME single action, and counts how many
// times the planner is invoked.
type countingClient struct{ calls int }

func (c *countingClient) Name() string { return "counting" }
func (c *countingClient) Generate(_ context.Context, _, _ string) (string, error) {
	c.calls++
	return `{"actions":[{"tool":"scanner","category":"scan","target":"h","risk":"medium","params":{},"rationale":"x"}]}`, nil
}

func termEngagement() *engagement.Engagement {
	return &engagement.Engagement{
		ID: "e1", Client: "c",
		Scope: engagement.Scope{InScope: []engagement.Target{{Type: engagement.TargetDomain, Value: "h"}}},
		RoE:   engagement.RoE{MaxRisk: "medium"},
	}
}

func termEngine(t *testing.T, client llm.Client, opts Options) (*Engine, *state.State) {
	t.Helper()
	eng := termEngagement()
	reg := tool.NewRegistry()
	reg.MustRegister(fakeScanner{})
	st := state.New()
	g := guard.New(eng, map[string]guard.ToolMeta{"scanner": {Category: action.CategoryScan, MaxRisk: action.RiskMedium}})
	return New(eng, g, planner.New(client), reg, st, audit.NewLog(io.Discard), io.Discard, opts), st
}

func TestNoProgressHalt(t *testing.T) {
	// fakeScanner returns the same host+service assets each time, so after the
	// first cycle every later cycle re-proposes a DUPLICATE action: no progress.
	client := &countingClient{}
	e, _ := termEngine(t, client, Options{MaxCycles: 10, NoProgressCycleLimit: 3})
	if err := e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// cycle 1 makes progress (new assets); cycles 2,3,4 are no-progress -> halt
	// after 3 barren cycles, well before MaxCycles=10.
	if client.calls != 4 {
		t.Fatalf("want 4 planner calls (1 productive + 3 barren), got %d", client.calls)
	}
}

func TestDuplicateActionSkipped(t *testing.T) {
	// One cycle, planner proposes the same action twice: the second is a duplicate.
	client := &llm.Mock{Responses: []string{
		`{"actions":[
			{"tool":"scanner","category":"scan","target":"h","risk":"medium","params":{},"rationale":"x"},
			{"tool":"scanner","category":"scan","target":"h","risk":"medium","params":{},"rationale":"x"}
		]}`,
	}}
	e, st := termEngine(t, client, Options{MaxCycles: 1})
	if err := e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Both proposals collapse to one canonical key, so only 2 assets exist (not 4).
	if got := len(st.Assets()); got != 2 {
		t.Fatalf("duplicate action should not double-record assets; got %d", got)
	}
}
