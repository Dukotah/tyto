package state

import "strings"

// fieldCap bounds how many runes of a tool-sourced typed field may enter the
// planner prompt, limiting the prompt-budget blast radius from a hostile tool.
const fieldCap = 200

// The quarantine boundary (load-bearing trifecta defense)
// -------------------------------------------------------
// Tool output is UNTRUSTED: a scanned host controls its own banners, HTTP
// bodies, and error strings, so any of that text could carry prompt-injection
// aimed at the planner. The invariant enforced here is structural: State.Summary
// — the ONLY state that reaches the planner prompt — emits exclusively the
// closed, typed projections below. Free-text fields (Finding.Description /
// Evidence, Asset.Attrs) are tagged planner:"quarantined" and have no path into
// Summary. TestFindingFieldsClassified fails closed if a new string field is
// added without a planner tag, so this can't silently regress.
//
// Operator-facing rendering (internal/report) still sees the full fields; only
// the model-facing path is constrained.

// plannerFindingView is the CLOSED set of finding fields permitted into the
// planner prompt.
type plannerFindingView struct {
	Severity Severity
	Title    string
	Target   string
}

// plannerAssetView is the closed set of asset fields permitted into the prompt.
type plannerAssetView struct {
	Type  string
	Value string
}

// plannerView is the ONLY path from a Finding into Summary().
func (f Finding) plannerView() plannerFindingView {
	return plannerFindingView{
		Severity: f.Severity,
		Title:    sanitizeField(f.Title),
		Target:   sanitizeField(f.Target),
	}
}

// plannerView is the ONLY path from an Asset into Summary().
func (a *Asset) plannerView() plannerAssetView {
	return plannerAssetView{
		Type:  sanitizeField(a.Type),
		Value: sanitizeField(a.Value),
	}
}

// sanitizeField collapses control characters / newlines / whitespace runs to a
// single space and rune-caps the result before it enters the planner prompt.
// Defense in depth: even the allowed fields (Title, Target, asset Value) are
// tool-sourced, so a tool must not be able to forge extra prompt lines or blow
// the prompt budget.
func sanitizeField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > fieldCap {
		return string(r[:fieldCap]) + "…"
	}
	return s
}
