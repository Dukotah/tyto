package planner

import (
	"encoding/json"

	"github.com/dukotah/tyto/internal/action"
)

// ActionSchema is the JSON Schema for a planner proposal. It is passed to the
// backend (Ollama compiles it to a GBNF grammar) so the model literally cannot
// emit malformed JSON or an out-of-taxonomy category at the token level. The
// category/risk enums are derived from the action package, so the schema can
// never drift from the closed taxonomy the guard enforces.
func ActionSchema() json.RawMessage {
	cats := make([]string, 0)
	for _, c := range action.AllCategories() {
		cats = append(cats, c.String())
	}
	risks := make([]string, 0)
	for _, r := range action.AllRiskLevels() {
		risks = append(risks, r.String())
	}

	schema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"actions"},
		"properties": map[string]any{
			"actions": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"required":             []string{"tool", "category", "target", "risk", "rationale"},
					"properties": map[string]any{
						"tool":     map[string]any{"type": "string", "minLength": 1},
						"category": map[string]any{"type": "string", "enum": cats},
						"target":   map[string]any{"type": "string", "minLength": 1},
						"risk":     map[string]any{"type": "string", "enum": risks},
						"params": map[string]any{
							"type":                 "object",
							"additionalProperties": map[string]any{"type": "string"},
						},
						"rationale": map[string]any{"type": "string"},
					},
				},
			},
		},
	}
	b, _ := json.Marshal(schema)
	return b
}
