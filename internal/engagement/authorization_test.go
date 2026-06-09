package engagement

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/dukotah/tyto/internal/action"
)

func authEngagement() *Engagement {
	return &Engagement{
		ID: "E", Client: "Acme",
		Authorization: Authorization{AuthorizedBy: "t", AgreementRef: "r"},
		Scope:         Scope{InScope: []Target{{Type: TargetCIDR, Value: "203.0.113.0/24"}}},
		RoE:           RoE{MaxRisk: "high"},
	}
}

func TestCanonicalBytesStableAndScopeSensitive(t *testing.T) {
	e := authEngagement()
	if string(e.CanonicalBytes()) != string(e.CanonicalBytes()) {
		t.Fatal("CanonicalBytes must be deterministic")
	}
	before := string(e.CanonicalBytes())
	e.Scope.InScope = append(e.Scope.InScope, Target{Type: TargetIP, Value: "198.51.100.1"})
	if string(e.CanonicalBytes()) == before {
		t.Fatal("changing scope must change the signed bytes")
	}
	// RoE knobs the operator may tighten without re-signing are NOT in the surface.
	e2 := authEngagement()
	base := string(e2.CanonicalBytes())
	e2.RoE.ForbiddenCategories = []string{"exploit"}
	e2.RoE.TimeWindows = []TimeWindow{{Start: "01:00", End: "05:00"}}
	if string(e2.CanonicalBytes()) != base {
		t.Fatal("categories/time windows must not be part of the signed surface")
	}
}

func TestVerifiedGrantsRoundTripAndRejections(t *testing.T) {
	e := authEngagement()
	if g, err := e.VerifiedGrants(); err != nil || g != nil {
		t.Fatalf("no grants should be (nil, nil), got %v / %v", g, err)
	}

	pub, priv, _ := ed25519.GenerateKey(nil)
	e.Authorization.ClientPublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	e.Authorization.Grants = []AuthGrant{{
		PublicKeyB64:  base64.StdEncoding.EncodeToString(pub),
		SignatureB64:  base64.StdEncoding.EncodeToString(ed25519.Sign(priv, e.CanonicalBytes())),
		CoversTargets: []Target{{Type: TargetCIDR, Value: "203.0.113.0/24"}},
		MaxTier:       "high",
	}}
	got, err := e.VerifiedGrants()
	if err != nil || len(got) != 1 || got[0].MaxTier != action.RiskHigh {
		t.Fatalf("valid grant should verify to one high-tier grant, got %v / %v", got, err)
	}

	// A grant signed by a different key than the pinned one is rejected.
	e2 := authEngagement()
	otherPub, _, _ := ed25519.GenerateKey(nil)
	e2.Authorization.ClientPublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	e2.Authorization.Grants = []AuthGrant{{
		PublicKeyB64: base64.StdEncoding.EncodeToString(otherPub),
		SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, e2.CanonicalBytes())),
		MaxTier:      "high",
	}}
	if _, err := e2.VerifiedGrants(); err == nil {
		t.Fatal("grant key not matching the pinned client key must be rejected")
	}
}
