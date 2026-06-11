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

// gaterTool implements tool.ApprovalGater and records whether it executed, so the
// test can assert the engine forces the approval gate (and fails closed without an
// approver) even when the run's global RequireApproval is off.
type gaterTool struct{ ran *bool }

func (gaterTool) Name() string                          { return "gater" }
func (gaterTool) Category() action.Category             { return action.CategoryRecon }
func (gaterTool) MaxRisk() action.RiskLevel             { return action.RiskLow }
func (gaterTool) NeedsApproval(map[string]string) bool  { return true }
func (g gaterTool) Execute(_ context.Context, a action.Action) (action.Result, error) {
	*g.ran = true
	return action.Result{ActionID: a.ID, Tool: "gater", Success: true}, nil
}

func runGater(t *testing.T, approver func(context.Context, action.Action) (bool, error)) bool {
	t.Helper()
	eng := termEngagement()
	reg := tool.NewRegistry()
	ran := false
	reg.MustRegister(gaterTool{ran: &ran})
	g := guard.New(eng, map[string]guard.ToolMeta{"gater": {Category: action.CategoryRecon, MaxRisk: action.RiskLow}}, nil)
	st := state.New()
	plan := `{"actions":[{"tool":"gater","category":"recon","target":"h","risk":"low","params":{"command":"x"},"rationale":"y"}]}`
	e := New(eng, g, planner.New(&llm.Mock{Responses: []string{plan}}), reg, st, audit.NewLog(io.Discard), io.Discard,
		Options{MaxCycles: 1, RequireApproval: false, Approver: approver})
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return ran
}

func TestApprovalGaterFailsClosedWithoutApprover(t *testing.T) {
	// NeedsApproval=true, RequireApproval=false, no approver wired → must NOT run.
	if runGater(t, nil) {
		t.Fatal("a force-approval tool executed with no approver — must fail closed (deny)")
	}
}

func TestApprovalGaterRunsWhenApproved(t *testing.T) {
	if !runGater(t, func(context.Context, action.Action) (bool, error) { return true, nil }) {
		t.Fatal("a force-approval tool did not execute despite operator approval")
	}
}

func TestApprovalGaterDeniedWhenOperatorDeclines(t *testing.T) {
	if runGater(t, func(context.Context, action.Action) (bool, error) { return false, nil }) {
		t.Fatal("a force-approval tool executed despite the operator declining")
	}
}
