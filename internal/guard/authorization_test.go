package guard

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/engagement"
)

// highEngagement allows exploit-category and high-risk actions, so the
// authorization gate (not the risk/category checks) is what decides.
func highEngagement() *engagement.Engagement {
	return &engagement.Engagement{
		ID: "ENG-H", Client: "Test Co",
		Authorization: engagement.Authorization{AuthorizedBy: "t", AgreementRef: "r"},
		Scope: engagement.Scope{InScope: []engagement.Target{
			{Type: engagement.TargetCIDR, Value: "203.0.113.0/24"},
		}},
		RoE: engagement.RoE{MaxRisk: "high", AllowedCategories: []string{"recon", "scan", "exploit"}},
	}
}

func signedGrant(t *testing.T, e *engagement.Engagement, covers []engagement.Target, tier string) ([]engagement.VerifiedGrant, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Authorization.ClientPublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	e.Authorization.Grants = []engagement.AuthGrant{{
		PublicKeyB64:  base64.StdEncoding.EncodeToString(pub),
		SignatureB64:  base64.StdEncoding.EncodeToString(ed25519.Sign(priv, e.CanonicalBytes())),
		CoversTargets: covers,
		MaxTier:       tier,
	}}
	grants, err := e.VerifiedGrants()
	if err != nil {
		t.Fatalf("VerifiedGrants: %v", err)
	}
	return grants, pub
}

func TestExploitDeniedWithoutGrant(t *testing.T) {
	e := highEngagement()
	g := New(e, exploitTools(), nil) // no grants
	d := g.Evaluate(action.Action{Tool: "exploiter", Target: "203.0.113.10"})
	if d.Verdict != VerdictDeny {
		t.Fatalf("exploit action without a grant must deny, got %s", d.Verdict)
	}
}

func TestExploitAllowedWithCoveringGrant(t *testing.T) {
	e := highEngagement()
	covers := []engagement.Target{{Type: engagement.TargetCIDR, Value: "203.0.113.0/24"}}
	grants, _ := signedGrant(t, e, covers, "high")
	g := New(e, exploitTools(), grants)
	d := g.Evaluate(action.Action{Tool: "exploiter", Target: "203.0.113.10"})
	if !d.IsAllowed() {
		t.Fatalf("exploit action with a covering high-tier grant should allow, got deny: %s", d.Reason)
	}
}

func TestGrantTierTooLowDenies(t *testing.T) {
	e := highEngagement()
	covers := []engagement.Target{{Type: engagement.TargetCIDR, Value: "203.0.113.0/24"}}
	grants, _ := signedGrant(t, e, covers, "medium") // below the RiskHigh exploiter
	g := New(e, exploitTools(), grants)
	d := g.Evaluate(action.Action{Tool: "exploiter", Target: "203.0.113.10"})
	if d.IsAllowed() {
		t.Fatalf("a medium-tier grant must not authorize a high-risk action")
	}
}

func TestGrantTargetNotCoveredDenies(t *testing.T) {
	e := highEngagement()
	// Grant covers a different in-scope host than the action targets.
	covers := []engagement.Target{{Type: engagement.TargetIP, Value: "203.0.113.99"}}
	grants, _ := signedGrant(t, e, covers, "high")
	g := New(e, exploitTools(), grants)
	d := g.Evaluate(action.Action{Tool: "exploiter", Target: "203.0.113.10"})
	if d.IsAllowed() {
		t.Fatalf("grant not covering the target must not authorize the action")
	}
}

func TestTamperedScopeFailsVerification(t *testing.T) {
	e := highEngagement()
	covers := []engagement.Target{{Type: engagement.TargetCIDR, Value: "203.0.113.0/24"}}
	signedGrant(t, e, covers, "high")
	// Widen the scope AFTER signing: the signature no longer matches CanonicalBytes.
	e.Scope.InScope = append(e.Scope.InScope, engagement.Target{Type: engagement.TargetCIDR, Value: "10.0.0.0/8"})
	if _, err := e.VerifiedGrants(); err == nil {
		t.Fatal("widening the scope after signing must fail grant verification")
	}
}

func TestNonExploitMediumNeedsNoGrant(t *testing.T) {
	// A scan (RiskMedium, non-exploit) on the high engagement needs no grant — the
	// authorization gate only bites high/exploit, preserving normal recon/scan.
	e := highEngagement()
	g := New(e, exploitTools(), nil)
	d := g.Evaluate(action.Action{Tool: "portscan", Target: "203.0.113.10"})
	if !d.IsAllowed() {
		t.Fatalf("a medium-risk scan should not require authorization, got: %s", d.Reason)
	}
}

func exploitTools() map[string]ToolMeta {
	return map[string]ToolMeta{
		"portscan":  {Category: action.CategoryScan, MaxRisk: action.RiskMedium},
		"exploiter": {Category: action.CategoryExploit, MaxRisk: action.RiskHigh},
	}
}
