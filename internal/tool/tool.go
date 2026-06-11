// Package tool defines the plugin surface for capabilities that actually touch a
// target. Tools execute; they never decide whether they may — the Scope Guard
// already did. Built-in tools live under internal/tool/builtin.
package tool

import (
	"context"

	"github.com/dukotah/tyto/internal/action"
)

// ApprovalGater is an optional capability a Tool can implement to FORCE explicit
// operator approval for specific actions, regardless of the run's global
// RequireApproval setting. The arbitrary-command "kali" tool uses it so that any
// non-read-only command must be approved on the dashboard before it runs — the
// human stays the kill-switch for free-form arsenal access. A tool that doesn't
// implement this is gated only by the normal RequireApproval + risk path.
type ApprovalGater interface {
	// NeedsApproval reports whether THIS action (given its params) must be
	// operator-approved before execution. Returning true with no approver wired
	// fails closed (the action is denied).
	NeedsApproval(params map[string]string) bool
}

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
