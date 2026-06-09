package engagement

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/dukotah/tyto/internal/action"
)

// AuthGrant is a client-signed authorization for high-consequence actions. The
// client holds an Ed25519 keypair, gives tyto the public key out-of-band (pinned
// in Authorization.ClientPublicKeyB64), and signs the engagement's CanonicalBytes
// to produce SignatureB64. A grant authorizes actions up to MaxTier against the
// targets in CoversTargets — and only if its signature verifies, so a grant
// cannot be forged or transplanted onto a widened scope.
type AuthGrant struct {
	PublicKeyB64  string   `yaml:"public_key"`
	SignatureB64  string   `yaml:"signature"`
	CoversTargets []Target `yaml:"covers_targets"`
	MaxTier       string   `yaml:"max_tier"`
}

// VerifiedGrant is a grant whose Ed25519 signature over the canonical engagement
// verified against the pinned client key. It is the ONLY authorization shape the
// guard sees — no key material, no raw signature.
type VerifiedGrant struct {
	Targets []Target
	MaxTier action.RiskLevel
}

// CanonicalBytes is the deterministic encoding of the security-relevant surface
// the client signs: client, in/out scope, and the risk ceiling. RoE knobs the
// operator may legitimately TIGHTEN without re-signing (categories, time windows,
// rate limits) are intentionally excluded. Reordering scope entries changes these
// bytes by design: the signer and verifier must agree on the exact scope.
func (e *Engagement) CanonicalBytes() []byte {
	type canonical struct {
		Client     string   `json:"client"`
		InScope    []Target `json:"in_scope"`
		OutOfScope []Target `json:"out_of_scope"`
		MaxRisk    string   `json:"max_risk"`
	}
	b, _ := json.Marshal(canonical{
		Client:     e.Client,
		InScope:    e.Scope.InScope,
		OutOfScope: e.Scope.OutOfScope,
		MaxRisk:    e.RoE.MaxRisk,
	})
	return b
}

// ScopeHash is the hex SHA-256 of CanonicalBytes — recorded in the audit chain so
// any post-hoc widening of the signed scope becomes detectable.
func (e *Engagement) ScopeHash() string {
	sum := sha256.Sum256(e.CanonicalBytes())
	return hex.EncodeToString(sum[:])
}

// VerifiedGrants verifies every authorization grant against the pinned client
// public key and the canonical engagement bytes. It fails CLOSED: any malformed
// key/signature, a key that does not match the pinned client key, a signature
// that does not verify (tamper/wrong scope), or an invalid tier returns an error
// so the caller can refuse to run. An engagement with no grants returns (nil, nil)
// — recon/scan engagements need no key material and simply have no high/exploit
// authorization at guard time.
func (e *Engagement) VerifiedGrants() ([]VerifiedGrant, error) {
	if len(e.Authorization.Grants) == 0 {
		return nil, nil
	}
	pinned, err := base64.StdEncoding.DecodeString(e.Authorization.ClientPublicKeyB64)
	if err != nil || len(pinned) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("authorization.client_public_key must be a base64 ed25519 public key")
	}
	msg := e.CanonicalBytes()
	out := make([]VerifiedGrant, 0, len(e.Authorization.Grants))
	for i, gr := range e.Authorization.Grants {
		key, err := base64.StdEncoding.DecodeString(gr.PublicKeyB64)
		if err != nil || !bytes.Equal(key, pinned) {
			return nil, fmt.Errorf("authorization.grants[%d]: public key does not match the pinned client key", i)
		}
		sig, err := base64.StdEncoding.DecodeString(gr.SignatureB64)
		if err != nil {
			return nil, fmt.Errorf("authorization.grants[%d]: signature is not valid base64", i)
		}
		if !ed25519.Verify(ed25519.PublicKey(pinned), msg, sig) {
			return nil, fmt.Errorf("authorization.grants[%d]: signature does not verify (tampered scope or wrong key)", i)
		}
		tier, err := action.ParseRiskLevel(gr.MaxTier)
		if err != nil {
			return nil, fmt.Errorf("authorization.grants[%d].max_tier: %w", i, err)
		}
		out = append(out, VerifiedGrant{Targets: gr.CoversTargets, MaxTier: tier})
	}
	return out, nil
}
