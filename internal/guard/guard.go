// Package guard is the Scope Guard: the single, deterministic chokepoint every
// action passes through before it can execute. It is intentionally simple, has
// no I/O, and contains no AI. The planner proposes; the guard disposes. The
// model cannot disable or bypass it.
package guard

import (
	"fmt"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/engagement"
)

// Decision is the guard's verdict on a single action.
type Decision struct {
	Allowed bool
	Reason  string
}

// Allow returns an allowing decision.
func Allow() Decision { return Decision{Allowed: true} }

// Deny returns a denying decision with a human-readable reason.
func Deny(reason string) Decision { return Decision{Allowed: false, Reason: reason} }

// Guard enforces one engagement's scope and rules of engagement.
type Guard struct {
	eng *engagement.Engagement
	now func() time.Time // injectable for tests
}

// New builds a Guard for the given engagement.
func New(eng *engagement.Engagement) *Guard {
	return &Guard{eng: eng, now: time.Now}
}

// Evaluate returns whether an action is permitted. Checks run cheapest-first and
// short-circuit on the first failure.
func (g *Guard) Evaluate(a action.Action) Decision {
	// 1. Scope. Out-of-scope always wins.
	if !g.eng.Scope.Contains(a.Target) {
		return Deny(fmt.Sprintf("target %q is not in scope", a.Target))
	}

	// 2. Risk ceiling.
	maxRisk, err := g.eng.RoE.MaxRiskLevel()
	if err != nil {
		return Deny("rules of engagement have an invalid max_risk")
	}
	if a.Risk > maxRisk {
		return Deny(fmt.Sprintf("action risk %s exceeds engagement ceiling %s", a.Risk, maxRisk))
	}

	// 3. Categories. Forbidden beats allowed.
	cat := strings.ToLower(strings.TrimSpace(a.Category))
	if containsFold(g.eng.RoE.ForbiddenCategories, cat) {
		return Deny(fmt.Sprintf("category %q is forbidden by the rules of engagement", a.Category))
	}
	if len(g.eng.RoE.AllowedCategories) > 0 && !containsFold(g.eng.RoE.AllowedCategories, cat) {
		return Deny(fmt.Sprintf("category %q is not in the allowed list", a.Category))
	}

	// 4. Time window.
	if !withinWindows(g.eng.RoE.TimeWindows, g.now().UTC()) {
		return Deny("current time is outside the permitted operating window")
	}

	return Allow()
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(strings.TrimSpace(s), v) {
			return true
		}
	}
	return false
}

// withinWindows is true if there are no windows (anytime) or t is inside one.
func withinWindows(windows []engagement.TimeWindow, t time.Time) bool {
	if len(windows) == 0 {
		return true
	}
	for _, w := range windows {
		if w.Contains(t) {
			return true
		}
	}
	return false
}
