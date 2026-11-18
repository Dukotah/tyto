package engine

import "github.com/dukotah/tyto/internal/action"

// Terminal reasons name why a run's plan/act loop stopped. They ride the final
// "done" event's Reason and (for the budget cases) a dedicated audit record, so a
// live UI and the audit trail agree on why the engine halted. They extend the
// existing stop conditions (empty plan, no-progress) rather than replacing them.
const (
	reasonPlannerDone = "planner proposed no further actions"
	reasonNoProgress  = "no progress for the configured number of cycles"
	reasonCycleBudget = "cycle budget exhausted"
	reasonTokenBudget = "token budget exhausted"
)

// estimateTokens approximates an LLM token count as chars/4 — the standard rough
// rule for English text. It is deliberately simple; Options.EstimateTokens swaps
// in a real tokenizer when a caller has one. Kept out of the hot path: it runs
// once per planning turn, not per byte.
func estimateTokens(s string) int {
	return (len(s) + 3) / 4
}

// budget tracks a single run's resource ceilings and consumption. A zero or
// negative ceiling means "unlimited", so an unset budget never changes behaviour —
// existing runs keep going until the planner, the no-progress contract, or the
// cycle cap stops them. The token count is approximate: it accumulates the
// estimated size of each planner prompt and response, since the engine never sees
// the model's real token usage.
type budget struct {
	maxCycles int              // hard cap on plan/act cycles (always set from the loop's resolved cap)
	maxTokens int              // approximate token ceiling across all planning (<= 0 = unlimited)
	estimate  func(string) int // token estimator (chars/4 by default; swappable)
	tokens    int              // approximate tokens consumed so far
}

// addText adds the estimated token cost of one or more prompt/response fragments
// to the running total.
func (b *budget) addText(parts ...string) {
	for _, p := range parts {
		b.tokens += b.estimate(p)
	}
}

// tokensExhausted reports whether the approximate token budget has been spent. It
// is always false when no token ceiling is set, so the default is unlimited.
func (b *budget) tokensExhausted() bool {
	return b.maxTokens > 0 && b.tokens >= b.maxTokens
}

// responseCost approximates the model's response size from the actions it yielded,
// so the token budget reflects output as well as input. It mirrors the fields the
// model actually emits (tool, category, target, risk, params, rationale) without
// needing the raw response, which the engine never sees.
func responseCost(actions []action.Action) string {
	var n int
	for i := range actions {
		a := &actions[i]
		n += len(a.Tool) + len(a.Category) + len(a.Target) + len(a.Risk.String()) + len(a.Rationale)
		for k, v := range a.Params {
			n += len(k) + len(v)
		}
	}
	// A fixed-length placeholder of the summed size; estimateTokens only reads len.
	return string(make([]byte, n))
}
