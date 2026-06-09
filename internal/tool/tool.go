// Package tool defines the plugin surface for capabilities that actually touch a
// target. Tools execute; they never decide whether they may — the Scope Guard
// already did. Built-in tools live under internal/tool/builtin.
package tool

import (
	"context"

	"github.com/dukotah/tyto/internal/action"
)

// Tool is a single capability the engine can invoke.
type Tool interface {
	// Name is the unique identifier the planner references.
	Name() string
	// Category is the AUTHORITATIVE category the Scope Guard enforces the
	// engagement's allowed/forbidden lists against (from the closed taxonomy).
	// The model's self-declared category is advisory only and never gates.
	Category() action.Category
	// MaxRisk is the AUTHORITATIVE ceiling this tool can reach. The guard gates
	// on max(MaxRisk, per-param classifier), never on the model's declared risk.
	MaxRisk() action.RiskLevel
	// Execute performs the action against its target.
	Execute(ctx context.Context, a action.Action) (action.Result, error)
}
