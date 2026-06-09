package engine

import (
	"context"
	"io"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/planner"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool"
)

func TestResumeSkipsCompletedActions(t *testing.T) {
	eng := termEngagement()
	reg := tool.NewRegistry()
	reg.MustRegister(fakeScanner{})
	g := guard.New(eng, map[string]guard.ToolMeta{"scanner": {Category: action.CategoryScan, MaxRisk: action.RiskMedium}}, nil)

	plan := `{"actions":[{"tool":"scanner","category":"scan","target":"h","risk":"medium","params":{},"rationale":"x"}]}`

	// First run: capture the completed action key.
	st1 := state.New()
	e1 := New(eng, g, planner.New(&llm.Mock{Responses: []string{plan}}), reg, st1, audit.NewLog(io.Discard), io.Discard, Options{MaxCycles: 1})
	if err := e1.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	keys := e1.CompletedActionKeys()
	if len(keys) == 0 {
		t.Fatal("expected at least one completed action key")
	}

	// Resume: same action proposed, but pre-seeded as completed -> skipped, so the
	// fresh state records no new assets.
	st2 := state.New()
	e2 := New(eng, g, planner.New(&llm.Mock{Responses: []string{plan}}), reg, st2, audit.NewLog(io.Discard), io.Discard,
		Options{MaxCycles: 1, PriorActionKeys: keys})
	if err := e2.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(st2.Assets()); got != 0 {
		t.Fatalf("resumed run should skip the completed action and record no assets, got %d", got)
	}
}
