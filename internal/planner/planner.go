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

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/state"
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

// maxRepairRetries is how many times the planner re-prompts the model with the
// validation error before giving up. 1 retry => 2 model calls total.
const maxRepairRetries = 1

// Plan asks the model for the next actions given current state and the set of
// available tool names. Output is grammar-constrained to the action schema (when
// the backend supports it), then validated. Invalid output triggers a bounded
// repair retry; on exhaustion Plan FAILS CLOSED (error + zero actions) so the
// engine never executes a half-parsed action.
func (p *Planner) Plan(ctx context.Context, eng *engagement.Engagement, st *state.State, tools []string) ([]action.Action, error) {
	schema := ActionSchema()
	system, user := SystemPrompt(), UserPrompt(eng, st, tools)

	var lastErr error
	for attempt := 0; attempt <= maxRepairRetries; attempt++ {
		raw, err := p.generate(ctx, system, user, schema)
		if err != nil {
			return nil, fmt.Errorf("planner: llm generate: %w", err)
		}
		actions, err := decodeActions(raw)
		if err == nil {
			return actions, nil
		}
		lastErr = err
		// Feed the validation error back so the model can correct itself.
		user = RepairPrompt(raw, err)
	}
	return nil, fmt.Errorf("planner: model output failed validation after %d repair attempt(s): %w", maxRepairRetries, lastErr)
}

// generate uses the backend's schema-constrained mode when available, else falls
// back to a plain JSON generation.
func (p *Planner) generate(ctx context.Context, system, user string, schema json.RawMessage) (string, error) {
	if sc, ok := p.llm.(llm.SchemaClient); ok {
		return sc.GenerateSchema(ctx, system, user, schema)
	}
	return p.llm.Generate(ctx, system, user)
}

// decodeActions parses and validates a proposal, failing closed. Category MUST
// parse to a member of the closed taxonomy (never silently defaulted — unlike
// risk, which fails safe to passive because the guard, not the model, is the
// authority on risk).
func decodeActions(raw string) ([]action.Action, error) {
	prop, err := parseProposal(raw)
	if err != nil {
		return nil, err
	}
	actions := make([]action.Action, 0, len(prop.Actions))
	for i, a := range prop.Actions {
		if strings.TrimSpace(a.Tool) == "" {
			return nil, fmt.Errorf("action %d: empty tool", i)
		}
		if strings.TrimSpace(a.Target) == "" {
			return nil, fmt.Errorf("action %d: empty target", i)
		}
		if _, err := action.ParseCategory(a.Category); err != nil {
			return nil, fmt.Errorf("action %d: %w", i, err)
		}
		risk, err := action.ParseRiskLevel(a.Risk)
		if err != nil {
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
