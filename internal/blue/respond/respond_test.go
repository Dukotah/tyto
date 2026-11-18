package respond

import (
	"testing"

	"github.com/dukotah/tyto/internal/guard"
)

// basePolicy permits every built-in type across a small defended estate, with
// the approval threshold set high (destructive) so that only the "destructive
// is always gated" rule — not the threshold — can force approvals. Individual
// tests tighten or loosen as needed.
func basePolicy() Policy {
	return Policy{
		AllowedTypes: []ActionType{
			ActionNotify, ActionBlockIP, ActionIsolateHost, ActionKillProcess, ActionDisableAccount,
		},
		Scope:             []string{".corp.example.com", "10.0.0.0/8", "198.51.100.7"},
		ApprovalAtOrAbove: ImpactDestructive,
	}
}

func newGuard(p Policy) *ResponseGuard { return New(p, DefaultMetas()) }

// (a) a reversible, in-scope action is allowed.
func TestReversibleInScopeAllowed(t *testing.T) {
	g := newGuard(basePolicy())
	d := g.Evaluate(ResponseAction{
		ID: "a1", Type: ActionNotify, Target: "web01.corp.example.com", Reason: "suspicious login",
	})
	if !d.IsAllowed() {
		t.Fatalf("reversible in-scope action: want allow, got %s (%s)", d.Verdict, d.Reason)
	}
}

// (b) an out-of-scope target is denied — proving scope is absolute, like the red
// side: a trivially reversible notify still loses when the target is off-estate.
func TestOutOfScopeDenied(t *testing.T) {
	g := newGuard(basePolicy())
	d := g.Evaluate(ResponseAction{
		ID: "a2", Type: ActionNotify, Target: "attacker.evil.test", Reason: "would notify about an off-estate host",
	})
	if d.Verdict != guard.VerdictDeny {
		t.Fatalf("out-of-scope target: want deny, got %s (%s)", d.Verdict, d.Reason)
	}
}

// (c) a destructive action in-scope requires approval even when the policy
// threshold is set as high as possible — destructive is ALWAYS gated.
func TestDestructiveAlwaysRequiresApproval(t *testing.T) {
	p := basePolicy()
	p.ApprovalAtOrAbove = ImpactDestructive // highest possible threshold
	g := newGuard(p)
	for _, at := range []ActionType{ActionIsolateHost, ActionKillProcess, ActionDisableAccount} {
		d := g.Evaluate(ResponseAction{ID: "a3", Type: at, Target: "10.1.2.3"})
		if d.Verdict != guard.VerdictRequireApproval {
			t.Fatalf("destructive %s in-scope: want require_approval, got %s (%s)", at, d.Verdict, d.Reason)
		}
	}

	// Even if a misconfigured policy set the threshold ABOVE destructive, the
	// dedicated destructive rule still gates it.
	p2 := basePolicy()
	p2.ApprovalAtOrAbove = ImpactDestructive + 1 // unreachable threshold
	g2 := newGuard(p2)
	d := g2.Evaluate(ResponseAction{ID: "a3b", Type: ActionIsolateHost, Target: "10.1.2.3"})
	if d.Verdict != guard.VerdictRequireApproval {
		t.Fatalf("destructive with unreachable threshold: want require_approval, got %s (%s)", d.Verdict, d.Reason)
	}
}

// (d) an unknown ActionType is denied — fail closed.
func TestUnknownTypeDenied(t *testing.T) {
	g := newGuard(basePolicy())
	for _, at := range []ActionType{ActionType("nuke_everything"), ActionType(""), ActionNone} {
		d := g.Evaluate(ResponseAction{ID: "a4", Type: at, Target: "web01.corp.example.com"})
		if d.Verdict != guard.VerdictDeny {
			t.Fatalf("unknown/none type %q: want deny, got %s (%s)", at, d.Verdict, d.Reason)
		}
	}
}

// (e) a proposal cannot escape the authoritative metas. The ResponseAction has
// no self-declared impact field at all, so the ONLY way impact enters the
// decision is the metas snapshot. We prove the guard reads the authority — not
// the type's "natural"/expected impact — by registering metas in which an
// ordinarily benign type (notify) is authoritatively destructive: the guard
// then gates it, exactly as it would any destructive action.
func TestImpactComesFromAuthoritativeMetas(t *testing.T) {
	// Sanity: with the honest DefaultMetas, notify is allowed.
	honest := newGuard(basePolicy())
	if d := honest.Evaluate(ResponseAction{ID: "e0", Type: ActionNotify, Target: "10.0.0.5"}); !d.IsAllowed() {
		t.Fatalf("notify under honest metas: want allow, got %s (%s)", d.Verdict, d.Reason)
	}

	// Now the authoritative snapshot says notify is destructive. The proposal is
	// byte-for-byte identical to the allowed one above — it carries no impact to
	// override — yet the verdict flips, because impact is looked up, never trusted.
	hardened := map[ActionType]ResponseMeta{
		ActionNotify:  {Impact: ImpactDestructive},
		ActionBlockIP: {Impact: ImpactDisruptive},
	}
	g := New(basePolicy(), hardened)
	d := g.Evaluate(ResponseAction{ID: "e1", Type: ActionNotify, Target: "10.0.0.5"})
	if d.Verdict != guard.VerdictRequireApproval {
		t.Fatalf("notify under hardened metas: want require_approval (authoritative destructive), got %s (%s)", d.Verdict, d.Reason)
	}

	// Conversely, a type with NO authoritative meta fails closed even though it is
	// known and allow-listed.
	g2 := New(basePolicy(), map[ActionType]ResponseMeta{ActionBlockIP: {Impact: ImpactDisruptive}})
	if d := g2.Evaluate(ResponseAction{ID: "e2", Type: ActionNotify, Target: "10.0.0.5"}); d.Verdict != guard.VerdictDeny {
		t.Fatalf("type with no meta: want deny (fail closed), got %s (%s)", d.Verdict, d.Reason)
	}
}

// Supporting coverage: a known type that the policy does not allow-list is
// denied before any scope/impact consideration.
func TestTypeNotAllowListedDenied(t *testing.T) {
	p := basePolicy()
	p.AllowedTypes = []ActionType{ActionNotify} // only notify permitted
	g := newGuard(p)
	d := g.Evaluate(ResponseAction{ID: "n1", Type: ActionBlockIP, Target: "10.0.0.5"})
	if d.Verdict != guard.VerdictDeny {
		t.Fatalf("non-allow-listed type: want deny, got %s (%s)", d.Verdict, d.Reason)
	}
}

// Supporting coverage: a disruptive action below the approval threshold is
// allowed; the same action at/above threshold requires approval.
func TestDisruptiveThresholdGate(t *testing.T) {
	// Threshold at disruptive => block_ip needs approval.
	p := basePolicy()
	p.ApprovalAtOrAbove = ImpactDisruptive
	g := newGuard(p)
	if d := g.Evaluate(ResponseAction{ID: "d1", Type: ActionBlockIP, Target: "10.0.0.5"}); d.Verdict != guard.VerdictRequireApproval {
		t.Fatalf("block_ip at threshold: want require_approval, got %s (%s)", d.Verdict, d.Reason)
	}

	// Threshold at destructive => block_ip (disruptive) is below it, so allow.
	p2 := basePolicy()
	p2.ApprovalAtOrAbove = ImpactDestructive
	g2 := newGuard(p2)
	if d := g2.Evaluate(ResponseAction{ID: "d2", Type: ActionBlockIP, Target: "10.0.0.5"}); !d.IsAllowed() {
		t.Fatalf("block_ip below threshold: want allow, got %s (%s)", d.Verdict, d.Reason)
	}
}

// Supporting coverage: scope matching honors CIDR, exact IP, and leading-dot
// suffix, and rejects the look-alike suffix-confusion host.
func TestScopeMatching(t *testing.T) {
	g := newGuard(basePolicy())
	allow := []string{
		"host.corp.example.com",              // .corp.example.com suffix
		"deep.sub.corp.example.com",          // nested suffix
		"10.255.0.1",                         // inside 10.0.0.0/8
		"198.51.100.7",                       // exact IP
		"10.0.0.9:443",                       // host:port form, IP in CIDR
		"https://host.corp.example.com/path", // URL form
	}
	for _, tgt := range allow {
		if d := g.Evaluate(ResponseAction{ID: "s", Type: ActionNotify, Target: tgt}); !d.IsAllowed() {
			t.Fatalf("scope allow %q: want allow, got %s (%s)", tgt, d.Verdict, d.Reason)
		}
	}
	deny := []string{
		"corp.example.com",                // the apex is NOT covered by ".corp.example.com"
		"host.corp.example.com.evil.test", // suffix-confusion look-alike
		"11.0.0.1",                        // outside the CIDR
		"198.51.100.8",                    // not the exact IP
		"",                                // empty target
	}
	for _, tgt := range deny {
		if d := g.Evaluate(ResponseAction{ID: "s", Type: ActionNotify, Target: tgt}); d.Verdict != guard.VerdictDeny {
			t.Fatalf("scope deny %q: want deny, got %s (%s)", tgt, d.Verdict, d.Reason)
		}
	}
}

// Supporting coverage: empty scope matches nothing (fail closed).
func TestEmptyScopeDeniesAll(t *testing.T) {
	p := basePolicy()
	p.Scope = nil
	g := newGuard(p)
	if d := g.Evaluate(ResponseAction{ID: "z", Type: ActionNotify, Target: "host.corp.example.com"}); d.Verdict != guard.VerdictDeny {
		t.Fatalf("empty scope: want deny, got %s (%s)", d.Verdict, d.Reason)
	}
}

// Supporting coverage: Impact.String round-trips the known values.
func TestImpactString(t *testing.T) {
	cases := map[Impact]string{
		ImpactReversible:  "reversible",
		ImpactDisruptive:  "disruptive",
		ImpactDestructive: "destructive",
		Impact(99):        "unknown",
	}
	for imp, want := range cases {
		if got := imp.String(); got != want {
			t.Fatalf("Impact(%d).String() = %q, want %q", int(imp), got, want)
		}
	}
}
