// Package guard is the Scope Guard: the single, deterministic chokepoint every
// action passes through before it can execute. It is intentionally simple, has
// no I/O, and contains no AI. The planner proposes; the guard disposes. The
// model cannot disable or bypass it — and crucially, it gates on AUTHORITATIVE
// tool metadata (category + risk ceiling snapshotted from the registry), never
// on the risk/category strings the model supplies for itself.
package guard

import (
	"fmt"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/engagement"
)

// Verdict is the guard's three-state ruling on an action.
type Verdict int

const (
	// VerdictDeny: the action is out of bounds and must not run. This is also
	// the zero value, so any unhandled/default case fails closed.
	VerdictDeny Verdict = iota
	// VerdictAllow: the action may execute.
	VerdictAllow
	// VerdictRequireApproval: the action is in-bounds but high-consequence and
	// may proceed only after an explicit, audited human sign-off. Producers are
	// added in later phases (authorization / exploitation gating); reserving the
	// state now keeps the human gate INSIDE the deterministic boundary.
	VerdictRequireApproval
)

func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "allow"
	case VerdictRequireApproval:
		return "require_approval"
	default:
		return "deny"
	}
}

// DenyCode categorizes WHY an action was denied, so a driver — the autonomous
// engine's replan loop or an external MCP client — can react programmatically
// instead of parsing the human-readable Reason string. It is purely descriptive:
// the guard still decides; the code only explains. Zero value is DenyUnspecified,
// so an unannotated deny still fails closed.
type DenyCode int

const (
	DenyUnspecified DenyCode = iota
	DenyUnknownTool
	DenyOutOfScope
	DenyInvalidRoE
	DenyRiskCeiling
	DenyCategoryForbidden
	DenyCategoryNotAllowed
	DenyAuthorization
	DenyTimeWindow
)

func (c DenyCode) String() string {
	switch c {
	case DenyUnknownTool:
		return "unknown_tool"
	case DenyOutOfScope:
		return "out_of_scope"
	case DenyInvalidRoE:
		return "invalid_roe"
	case DenyRiskCeiling:
		return "risk_ceiling"
	case DenyCategoryForbidden:
		return "category_forbidden"
	case DenyCategoryNotAllowed:
		return "category_not_allowed"
	case DenyAuthorization:
		return "authorization_required"
	case DenyTimeWindow:
		return "time_window"
	default:
		return "unspecified"
	}
}

// Decision is the guard's verdict on a single action.
type Decision struct {
	Verdict Verdict
	// Code categorizes a denial (DenyUnspecified for allow/approval). It lets a
	// driver branch on the kind of denial without parsing Reason.
	Code   DenyCode
	Reason string
}

// IsAllowed reports whether the action may execute without further gating.
func (d Decision) IsAllowed() bool { return d.Verdict == VerdictAllow }

// Allow returns an allowing decision.
func Allow() Decision { return Decision{Verdict: VerdictAllow} }

// Deny returns a denying decision with a human-readable reason and no specific
// code (DenyUnspecified).
func Deny(reason string) Decision { return Decision{Verdict: VerdictDeny, Reason: reason} }

// deny returns a denying decision tagged with its category code.
func deny(code DenyCode, reason string) Decision {
	return Decision{Verdict: VerdictDeny, Code: code, Reason: reason}
}

// RequireApproval returns a decision that gates the action behind human sign-off.
func RequireApproval(reason string) Decision {
	return Decision{Verdict: VerdictRequireApproval, Reason: reason}
}

// ToolMeta is the deterministic, read-only authority the guard gates on: a tool's
// category and risk ceiling, snapshotted from the registry at construction. The
// guard deliberately never sees a Tool's Execute, so guard code cannot run tools
// and cannot be tricked into trusting model-supplied risk/category.
type ToolMeta struct {
	Category action.Category
	MaxRisk  action.RiskLevel
}

// RiskClassifier optionally raises an action's effective risk based on its params
// (e.g. sqlmap detect=medium vs --dump=high — Phase 4 per-mode gating). It MUST
// default UP: an unrecognized param set returns the tool's ceiling, never below
// it. nil means "use the tool's MaxRisk".
type RiskClassifier func(tool string, params map[string]string) action.RiskLevel

// Guard enforces one engagement's scope and rules of engagement against the
// authoritative tool metadata.
type Guard struct {
	eng      *engagement.Engagement
	tools    map[string]ToolMeta
	grants   []engagement.VerifiedGrant
	classify RiskClassifier
	now      func() time.Time // injectable for tests
	// selfAttested mirrors the engagement's authorization mode, snapshotted at
	// construction. When true, the authorization gate is satisfied by operator
	// attestation (no signed grant) — but ONLY for in-scope targets; scope, risk,
	// category, and time-window checks all still run and still gate.
	selfAttested bool
}

// New builds a Guard for the given engagement, an immutable snapshot of the
// registered tools' authoritative category/risk, and the set of cryptographically
// verified authorization grants (nil for engagements with no high/exploit
// authorization). The guard only ever sees grants that already verified, so it
// trusts no key material itself.
func New(eng *engagement.Engagement, tools map[string]ToolMeta, grants []engagement.VerifiedGrant) *Guard {
	return &Guard{eng: eng, tools: tools, grants: grants, now: time.Now, selfAttested: eng.Authorization.SelfAttested()}
}

// WithClassifier attaches a per-param risk classifier and returns the guard.
func (g *Guard) WithClassifier(c RiskClassifier) *Guard {
	g.classify = c
	return g
}

// Evaluate returns whether an action is permitted. Checks run cheapest-first and
// short-circuit on the first failure. Risk and category are taken from the
// AUTHORITATIVE tool snapshot; the model's self-declared a.Risk / a.Category are
// never trusted for gating.
func (g *Guard) Evaluate(a action.Action) Decision {
	// 0. Resolve the tool authoritatively. Unknown tool => deny (fail closed).
	meta, ok := g.tools[a.Tool]
	if !ok {
		return deny(DenyUnknownTool, fmt.Sprintf("unknown tool %q (not registered)", a.Tool))
	}

	// 1. Scope. Out-of-scope always wins.
	if !g.eng.Scope.Contains(a.Target) {
		return deny(DenyOutOfScope, fmt.Sprintf("target %q is not in scope", a.Target))
	}

	// 2. Risk ceiling — gated on the AUTHORITATIVE effective risk (the tool's
	// ceiling, raised by the param classifier), never the model's a.Risk.
	maxRisk, err := g.eng.RoE.MaxRiskLevel()
	if err != nil {
		return deny(DenyInvalidRoE, "rules of engagement have an invalid max_risk")
	}
	effRisk := meta.MaxRisk
	if g.classify != nil {
		if r := g.classify(a.Tool, a.Params); r > effRisk {
			effRisk = r
		}
	}
	if effRisk > maxRisk {
		return deny(DenyRiskCeiling, fmt.Sprintf("action risk %s exceeds engagement ceiling %s", effRisk, maxRisk))
	}

	// 3. Categories — gated on the tool's AUTHORITATIVE category. Forbidden beats
	// allowed.
	cat := meta.Category
	if categoryIn(g.eng.RoE.ForbiddenCategories, cat) {
		return deny(DenyCategoryForbidden, fmt.Sprintf("category %q is forbidden by the rules of engagement", cat))
	}
	if len(g.eng.RoE.AllowedCategories) > 0 && !categoryIn(g.eng.RoE.AllowedCategories, cat) {
		return deny(DenyCategoryNotAllowed, fmt.Sprintf("category %q is not in the allowed list", cat))
	}

	// 3.5 Authorization. High-risk or exploit-category actions require authorization.
	// In the default client-grant mode that means a verified, client-signed grant
	// covering this target at this tier; no covering grant ⇒ deny (fail closed). In
	// self-attested mode the operator's recorded attestation stands in for the grant,
	// so the gate is satisfied — but only because the target already passed the
	// absolute scope check in step 1 (an out-of-scope target denied above never
	// reaches here). This is gated on the AUTHORITATIVE effective risk and tool
	// category, never on the model's self-declared values.
	if requiresAuthorization(meta.Category, effRisk) && !g.selfAttested && !g.authorized(a.Target, effRisk) {
		return deny(DenyAuthorization, fmt.Sprintf("action (%s, risk %s) requires a verified client authorization covering %q at this tier", cat, effRisk, a.Target))
	}

	// 4. Time window.
	if !withinWindows(g.eng.RoE.TimeWindows, g.now().UTC()) {
		return deny(DenyTimeWindow, "current time is outside the permitted operating window")
	}

	return Allow()
}

// requiresAuthorization reports whether an action is high-consequence enough to
// need a signed client grant: a high effective risk, or any exploit-category tool.
func requiresAuthorization(cat action.Category, effRisk action.RiskLevel) bool {
	return effRisk >= action.RiskHigh || cat == action.CategoryExploit
}

// authorized reports whether some verified grant covers the target at or above
// the action's tier. Coverage reuses the same scope-matching used for in-scope
// targets, so a grant can be a CIDR/domain/url just like a scope entry.
func (g *Guard) authorized(target string, tier action.RiskLevel) bool {
	for _, gr := range g.grants {
		if tier <= gr.MaxTier && (engagement.Scope{InScope: gr.Targets}).Contains(target) {
			return true
		}
	}
	return false
}

// categoryIn reports whether cat is named in a RoE category list. List entries are
// validated to known taxonomy names at engagement load, so a parse error here is
// treated as no-match (the load-time check is the real guard).
func categoryIn(list []string, cat action.Category) bool {
	for _, s := range list {
		if c, err := action.ParseCategory(s); err == nil && c == cat {
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
