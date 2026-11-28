// Package engagement models the contract with the client as data: scope, rules
// of engagement, objectives, and — required — an authorization record. tyto
// refuses to run without a valid engagement.
package engagement

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Authorization records who approved the test and how. Without it, no run. The
// optional cryptographic fields (ClientPublicKeyB64 + Grants) let a client
// authorize high-consequence actions in a tamper-evident, attributable way; see
// authorization.go.
type Authorization struct {
	AuthorizedBy     string `yaml:"authorized_by"`
	AuthorizedOn     string `yaml:"authorized_on"`
	AgreementRef     string `yaml:"agreement_ref"`
	EmergencyContact string `yaml:"emergency_contact"`
	// Mode is how high/exploit actions are authorized:
	//   "" / "client-grant" — the default: high-risk or exploit-category actions
	//     require a client-signed Ed25519 grant (ClientPublicKeyB64 + Grants).
	//   "self-attested" — the OPERATOR attests authorization (bug-bounty /
	//     self-directed testing where no client signs). High/exploit actions are
	//     permitted WITHOUT a signed grant, but ONLY for in-scope targets — the
	//     scope/risk/category/window checks all still gate. The attestation is still
	//     recorded (AuthorizedBy + AgreementRef remain required in both modes).
	Mode string `yaml:"mode"`
	// ClientPublicKeyB64 is the client's Ed25519 public key, pinned out-of-band.
	ClientPublicKeyB64 string `yaml:"client_public_key"`
	// Grants are client-signed authorizations for high/exploit actions.
	Grants []AuthGrant `yaml:"grants"`
}

// SelfAttested reports whether this engagement uses operator self-attestation
// instead of a client-signed grant. In self-attested mode the guard treats the
// authorization gate as satisfied for IN-SCOPE targets; scope is still absolute.
func (a Authorization) SelfAttested() bool {
	return a.Mode == "self-attested"
}

func (a Authorization) validate() error {
	if a.AuthorizedBy == "" {
		return fmt.Errorf("authorization.authorized_by is required")
	}
	if a.AgreementRef == "" {
		return fmt.Errorf("authorization.agreement_ref is required")
	}
	switch a.Mode {
	case "", "client-grant", "self-attested":
	default:
		return fmt.Errorf("authorization.mode %q is invalid (want \"client-grant\" or \"self-attested\")", a.Mode)
	}
	return nil
}

// Engagement is a complete, authorized testing engagement.
type Engagement struct {
	ID            string        `yaml:"id"`
	Client        string        `yaml:"client"`
	Description   string        `yaml:"description"`
	Objectives    []string      `yaml:"objectives"`
	Authorization Authorization `yaml:"authorization"`
	Scope         Scope         `yaml:"scope"`
	RoE           RoE           `yaml:"rules_of_engagement"`
	// ProvisionedCredentials are client-supplied test accounts for authenticated
	// testing (fed to the login tool by the engine, scoped per target).
	ProvisionedCredentials []ProvisionedCredential `yaml:"provisioned_credentials"`
}

// Load reads and validates an engagement file.
func Load(path string) (*Engagement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read engagement: %w", err)
	}
	var e Engagement
	if err := yaml.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("parse engagement: %w", err)
	}
	if err := e.Validate(); err != nil {
		return nil, fmt.Errorf("invalid engagement: %w", err)
	}
	return &e, nil
}

// Validate checks the engagement is complete enough to act on.
func (e *Engagement) Validate() error {
	if e.ID == "" {
		return fmt.Errorf("id is required")
	}
	if e.Client == "" {
		return fmt.Errorf("client is required")
	}
	if err := e.Authorization.validate(); err != nil {
		return err
	}
	if err := e.Scope.validate(); err != nil {
		return err
	}
	return e.RoE.validate()
}

// Marker returns the engagement traffic-marker header and value, or ok=false
// when the engagement turned it off. The value defaults to the engagement id,
// with any byte that is not legal in a header value replaced by '-'.
func (e *Engagement) Marker() (header, value string, ok bool) {
	m := e.RoE.TrafficMarker
	if m.Disabled {
		return "", "", false
	}
	header, value = m.Header, m.Value
	if header == "" {
		header = DefaultMarkerHeader
	}
	if value == "" {
		b := []byte(e.ID)
		for i, c := range b {
			if c < 0x20 || c > 0x7e {
				b[i] = '-'
			}
		}
		value = string(b)
	}
	return header, value, true
}
