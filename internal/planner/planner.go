// Package planner is the AI brain. It turns the engagement context and current
// state into concrete actions by prompting a local model and parsing its
// structured JSON output. The planner never executes anything and never decides
// what is permitted — that is the Scope Guard's job.
package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dukotah/strix/internal/action"
	"github.com/dukotah/strix/internal/engagement"
	"github.com/dukotah/strix/internal/planner/llm"
	"github.com/dukotah/strix/internal/state"
)

// Planner produces actions from engagement context using an LLM backend.
type Planner struct {
	llm llm.Client
}

// New builds a Planner over the given LLM client.
func New(c llm.Client) *Planner { return &Planner{llm: c} }

// proposal is the JSON shape the model is asked to emit.
type proposal struct {
	Actions []struct {
		Tool      string            `json:"tool"`
		Category  string            `json:"category"`
		Target    string            `json:"target"`
		Risk      string            `json:"risk"`
		Params    map[string]string `json:"params"`
		Rationale string            `json:"rationale"`
	} `json:"actions"`
}

// Plan asks the model for the next actions given current state and the set of
// available tool names.
func (p *Planner) Plan(ctx context.Context, eng *engagement.Engagement, st *state.State, tools []string) ([]action.Action, error) {
	raw, err := p.llm.Generate(ctx, SystemPrompt(), UserPrompt(eng, st, tools))
	if err != nil {
		return nil, fmt.Errorf("planner: llm generate: %w", err)
	}

	prop, err := parseProposal(raw)
	if err != nil {
		return nil, fmt.Errorf("planner: %w", err)
	}

	actions := make([]action.Action, 0, len(prop.Actions))
	for i, a := range prop.Actions {
		risk, err := action.ParseRiskLevel(a.Risk)
		if err != nil {
			// Unknown risk from the model: fail safe to passive so the guard
			// (not the model) remains the authority on what is allowed.
			risk = action.RiskPassive
		}
		actions = append(actions, action.Action{
			ID:        fmt.Sprintf("act-%d", i+1),
			Tool:      a.Tool,
			Category:  a.Category,
			Target:    a.Target,
			Params:    a.Params,
			Risk:      risk,
			Rationale: a.Rationale,
		})
	}
	return actions, nil
}

// parseProposal tolerates models that wrap JSON in prose or code fences.
func parseProposal(raw string) (proposal, error) {
	var prop proposal
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "{"); i > 0 {
		if j := strings.LastIndex(s, "}"); j >= i {
			s = s[i : j+1]
		}
	}
	if err := json.Unmarshal([]byte(s), &prop); err != nil {
		return proposal{}, fmt.Errorf("parse model output as JSON: %w", err)
	}
	return prop, nil
}
