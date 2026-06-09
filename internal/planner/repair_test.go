package planner

import (
	"context"
	"testing"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/state"
)

func planEngagement() *engagement.Engagement {
	return &engagement.Engagement{ID: "e", Client: "c"}
}

func TestPlanRepairsThenSucceeds(t *testing.T) {
	// Attempt 1: invalid category. Attempt 2 (repair): valid.
	m := &llm.Mock{Responses: []string{
		`{"actions":[{"tool":"portscan","category":"banana","target":"h","risk":"medium"}]}`,
		`{"actions":[{"tool":"portscan","category":"scan","target":"h","risk":"medium"}]}`,
	}}
	acts, err := New(m).Plan(context.Background(), planEngagement(), state.New(), []string{"portscan"})
	if err != nil {
		t.Fatalf("Plan should succeed after one repair: %v", err)
	}
	if len(acts) != 1 || acts[0].Category != "scan" {
		t.Fatalf("unexpected actions: %+v", acts)
	}
}

func TestPlanFailsClosedAfterRepairExhausted(t *testing.T) {
	// Always invalid: Plan must return an error and ZERO actions (never half-parsed).
	m := &llm.Mock{Responses: []string{
		`{"actions":[{"tool":"portscan","category":"banana","target":"h","risk":"medium"}]}`,
	}}
	acts, err := New(m).Plan(context.Background(), planEngagement(), state.New(), []string{"portscan"})
	if err == nil {
		t.Fatal("Plan must fail closed when output never validates")
	}
	if acts != nil {
		t.Fatalf("failed Plan must return zero actions, got %+v", acts)
	}
}
