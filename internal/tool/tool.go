// Package tool defines the plugin surface for capabilities that actually touch a
// target. Tools execute; they never decide whether they may — the Scope Guard
// already did. Built-in tools live under internal/tool/builtin.
package tool

import (
	"context"

	"github.com/dukotah/strix/internal/action"
)

// Tool is a single capability the engine can invoke.
type Tool interface {
	// Name is the unique identifier the planner references.
	Name() string
	// Category groups the tool for rules-of-engagement checks (recon, scan...).
	Category() string
	// MaxRisk is the highest risk level this tool can reach. Advisory metadata
	// for the planner and registry; the guard enforces the engagement ceiling.
	MaxRisk() action.RiskLevel
	// Execute performs the action against its target.
	Execute(ctx context.Context, a action.Action) (action.Result, error)
}
