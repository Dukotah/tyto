// Package respond is tyto blue's ResponseGuard: the single, deterministic gate
// every defensive response action passes through before it may execute. It is
// the blue-side mirror of tyto's offensive Scope Guard (internal/guard) and
// shares its exact decision vocabulary — the AI proposes a response, this
// deterministic guard disposes.
//
// # Principles (load-bearing — mirror the red side)
//
//   - Fail closed. The zero value of every verdict is Deny, every unhandled or
//     unknown case returns Deny, and the checks run cheapest-first and
//     short-circuit on the first failure.
//   - Authoritative metadata, never self-declared. A ResponseAction is the
//     model's PROPOSAL: its Type/Target are advisory. The guard gates on an
//     immutable per-ActionType impact snapshot (ResponseMeta, like tyto's
//     ToolMeta) taken at construction. There is deliberately no "impact" field
//     on ResponseAction for a model to lie about — impact is looked up, not
//     trusted.
//   - Scope is absolute. An action whose target is outside the defended estate
//     is denied no matter how benign its impact, exactly as an out-of-scope
//     target loses on the red side.
//   - Decide, never execute. This package performs no I/O: no network, no
//     process control, no account changes. It returns a guard.Decision and
//     nothing more. Execution is a separate, out-of-scope step that is ALSO
//     gated — see the Executor seam at the bottom of this file.
package respond

import (
	"fmt"
	"net"
	"strings"

	"github.com/dukotah/tyto/internal/guard"
)

// Impact is the AUTHORITATIVE, deterministic measure of how consequential a
// response action is on the defended estate. It is the blue-side analogue of
// red's action.RiskLevel and is the axis the guard gates on. Ordered so that a
// higher value is more consequential and comparisons (>=) are meaningful.
type Impact int

const (
	// ImpactReversible leaves the estate's operation untouched and is trivially
	// undone — e.g. notify an operator, tag/annotate an entity.
	ImpactReversible Impact = iota
	// ImpactDisruptive degrades or interrupts a flow but does not destroy state —
	// e.g. block an IP at the edge, apply a rate limit.
	ImpactDisruptive
	// ImpactDestructive takes a resource offline or revokes access in a way that
	// requires deliberate human recovery — e.g. isolate a host, kill a process,
	// disable an account. Always gated behind human approval.
	ImpactDestructive
)

func (i Impact) String() string {
	switch i {
	case ImpactReversible:
		return "reversible"
	case ImpactDisruptive:
		return "disruptive"
	case ImpactDestructive:
		return "destructive"
	default:
		return "unknown"
	}
}

// ActionType is the kind of defensive response the proposer may request. It is
// a closed vocabulary: a value outside this set is unknown and fails closed.
type ActionType string

const (
	// ActionNone is the explicit "do nothing" proposal (and the zero value of a
	// bare ActionType). It is never executable and the guard denies it so that an
	// empty/omitted type can never slip through as an allow.
	ActionNone ActionType = "none"
	// ActionNotify raises an alert/notification to an operator. Reversible.
	ActionNotify ActionType = "notify"
	// ActionBlockIP blocks a source IP at the network edge. Disruptive.
	ActionBlockIP ActionType = "block_ip"
	// ActionIsolateHost quarantines a host from the network. Destructive.
	ActionIsolateHost ActionType = "isolate_host"
	// ActionKillProcess terminates a running process. Destructive.
	ActionKillProcess ActionType = "kill_process"
	// ActionDisableAccount disables a user/service account. Destructive.
	ActionDisableAccount ActionType = "disable_account"
)

// ResponseAction is the AI's PROPOSAL for a single defensive response. Type and
// Target are model-advisory — the guard resolves the action's real impact from
// the authoritative metas keyed by Type and never trusts the proposer to
// classify its own consequence. Note the deliberate absence of any impact/risk
// field: there is nothing here for the model to self-declare.
type ResponseAction struct {
	ID     string     // proposal id (for audit + correlation)
	Type   ActionType // kind of response requested (advisory; gated via metas)
	Target string     // host / IP / account the action would affect
	Reason string     // why the proposer chose this (for audit + reports)
}

// ResponseMeta is the deterministic, read-only authority the guard gates on: the
// impact a given ActionType carries, snapshotted at construction. It is the
// blue-side mirror of guard.ToolMeta. The guard reads impact ONLY from here,
// never from the proposal, so a model cannot understate its own blast radius.
type ResponseMeta struct {
	Impact Impact
}

// DefaultMetas returns the authoritative impact snapshot for the built-in
// ActionTypes. Callers pass this (or a hardened copy) to New. ActionNone is
// intentionally absent: "do nothing" has no executable impact and is denied at
// the type check before any meta lookup.
func DefaultMetas() map[ActionType]ResponseMeta {
	return map[ActionType]ResponseMeta{
		ActionNotify:         {Impact: ImpactReversible},
		ActionBlockIP:        {Impact: ImpactDisruptive},
		ActionIsolateHost:    {Impact: ImpactDestructive},
		ActionKillProcess:    {Impact: ImpactDestructive},
		ActionDisableAccount: {Impact: ImpactDestructive},
	}
}

// Policy is the operator-set rules of engagement for the defensive side: which
// response types may ever run, the defended estate the guard may act within,
// and the impact threshold at or above which a human must sign off.
type Policy struct {
	// AllowedTypes is the allow-list of response types this deployment permits.
	// A type not named here is denied even if it is known and in-estate.
	AllowedTypes []ActionType
	// Scope is the defended estate the guard may act within: bare hosts, IPs,
	// CIDRs, or a leading-dot domain suffix (".corp.example.com"). A target that
	// matches no entry is out of scope and denied — absolutely, like the red side.
	Scope []string
	// ApprovalAtOrAbove: any action whose authoritative impact is at or above
	// this level requires human approval. (ImpactDestructive is ALWAYS gated
	// regardless of this threshold.)
	ApprovalAtOrAbove Impact
}

// allows reports whether t is named in the policy's allow-list.
func (p Policy) allows(t ActionType) bool {
	for _, a := range p.AllowedTypes {
		if a == t {
			return true
		}
	}
	return false
}

// inScope reports whether target falls within the defended estate. A target
// matches a scope entry when:
//   - the entry is a CIDR and the target's IP is inside it, OR
//   - the entry is an IP and equals the target's IP, OR
//   - the entry is a leading-dot domain suffix and the target's host ends with
//     it (".example.com" covers "a.example.com" but not "example.com"), OR
//   - the entry equals the target's host exactly (case-insensitive).
//
// Empty scope matches nothing (fail closed): an estate with no defined members
// cannot be acted upon.
func (p Policy) inScope(target string) bool {
	host := hostOf(target)
	if host == "" {
		return false
	}
	tIP := net.ParseIP(host)
	for _, entry := range p.Scope {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// CIDR entry: target must parse as an IP inside the network.
		if _, ipnet, err := net.ParseCIDR(entry); err == nil {
			if tIP != nil && ipnet.Contains(tIP) {
				return true
			}
			continue
		}
		// IP entry: exact IP match.
		if eIP := net.ParseIP(entry); eIP != nil {
			if tIP != nil && tIP.Equal(eIP) {
				return true
			}
			continue
		}
		// Leading-dot suffix entry: hostname suffix match.
		if strings.HasPrefix(entry, ".") {
			if strings.HasSuffix(strings.ToLower(host), strings.ToLower(entry)) {
				return true
			}
			continue
		}
		// Bare host entry: exact (case-insensitive) match.
		if strings.EqualFold(host, entry) {
			return true
		}
	}
	return false
}

// hostOf extracts the bare host from a target that may be a URL or host:port.
func hostOf(target string) string {
	t := strings.TrimSpace(target)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	return t
}

// ResponseGuard enforces one deployment's response Policy against the
// authoritative per-type impact snapshot. It holds no I/O handles and cannot
// execute anything — it only decides.
type ResponseGuard struct {
	policy Policy
	metas  map[ActionType]ResponseMeta
}

// New builds a ResponseGuard from a Policy and an immutable snapshot of each
// ActionType's authoritative impact. Pass DefaultMetas() unless the deployment
// overrides the impact of a type. A nil metas map is tolerated: every lookup
// then misses and the guard denies (fail closed).
func New(p Policy, metas map[ActionType]ResponseMeta) *ResponseGuard {
	return &ResponseGuard{policy: p, metas: metas}
}

// Evaluate returns the guard's three-state ruling on a proposed response action.
// It reuses guard.Allow/Deny/RequireApproval so the blue flow matches the red
// side exactly. Checks run cheapest-first, short-circuit on the first failure,
// and fail closed on anything unhandled.
//
// Decision order:
//  1. Unknown or "none" type        -> Deny (fail closed)
//  2. Type not in Policy.AllowedTypes -> Deny
//  3. Target not within Policy.Scope  -> Deny (scope is absolute)
//  4. Type absent from authoritative metas -> Deny (fail closed)
//  5. ImpactDestructive               -> RequireApproval (ALWAYS, ignores threshold)
//  6. Impact >= Policy.ApprovalAtOrAbove -> RequireApproval
//  7. otherwise                       -> Allow
func (g *ResponseGuard) Evaluate(a ResponseAction) guard.Decision {
	// 1. Type must be a known, executable response. Unknown or the explicit
	// "none" (also the empty zero value's intent) fails closed.
	if !isKnownType(a.Type) || a.Type == ActionNone {
		return guard.Deny(fmt.Sprintf("unknown or non-executable response type %q", a.Type))
	}

	// 2. Allow-list. A type the policy never permits loses here.
	if !g.policy.allows(a.Type) {
		return guard.Deny(fmt.Sprintf("response type %q is not in the policy allow-list", a.Type))
	}

	// 3. Scope. Out-of-estate targets always lose, regardless of impact.
	if !g.policy.inScope(a.Target) {
		return guard.Deny(fmt.Sprintf("target %q is not within the defended estate", a.Target))
	}

	// 4. Resolve the AUTHORITATIVE impact from the snapshot — never from the
	// proposal. A type with no registered meta fails closed.
	meta, ok := g.metas[a.Type]
	if !ok {
		return guard.Deny(fmt.Sprintf("response type %q has no authoritative impact metadata", a.Type))
	}

	// 5. Destructive actions are ALWAYS gated behind human sign-off, no matter
	// how permissive the policy's threshold is set.
	if meta.Impact == ImpactDestructive {
		return guard.RequireApproval(fmt.Sprintf("destructive response (%s on %q) always requires human approval", a.Type, a.Target))
	}

	// 6. Threshold gate on the authoritative impact.
	if meta.Impact >= g.policy.ApprovalAtOrAbove {
		return guard.RequireApproval(fmt.Sprintf("response impact %s is at or above the approval threshold %s", meta.Impact, g.policy.ApprovalAtOrAbove))
	}

	// 7. In estate, allowed type, below threshold, not destructive.
	return guard.Allow()
}

// isKnownType reports whether t is a member of the closed ActionType vocabulary
// (including ActionNone, which Evaluate then denies separately). Any other
// string is unknown and fails closed.
func isKnownType(t ActionType) bool {
	switch t {
	case ActionNone, ActionNotify, ActionBlockIP, ActionIsolateHost, ActionKillProcess, ActionDisableAccount:
		return true
	default:
		return false
	}
}

// Proposer is the read-only seam that produces response proposals from an alert.
// The AI triage brain implements this. It is deliberately decoupled from the
// guard: a Proposer only suggests, it never decides and never executes. `alert`
// is typed as any so this package takes no dependency on the event/detection
// shape; adapters pass the concrete alert through.
type Proposer interface {
	Propose(alert any) []ResponseAction
}

// Executor is the seam for the SEPARATE, out-of-scope execution step. It is
// declared here only to document the boundary: a ResponseAction is executed
// (network block, host isolation, account change) ONLY after Evaluate returned
// an allowing decision — or, for RequireApproval, after an audited human
// sign-off. This package performs NO execution and intentionally ships no real
// Executor implementation: it decides, something else disposes.
type Executor interface {
	Execute(ResponseAction) error
}
