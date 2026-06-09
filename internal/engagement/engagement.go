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
	// ClientPublicKeyB64 is the client's Ed25519 public key, pinned out-of-band.
	ClientPublicKeyB64 string `yaml:"client_public_key"`
	// Grants are client-signed authorizations for high/exploit actions.
	Grants []AuthGrant `yaml:"grants"`
}

func (a Authorization) validate() error {
	if a.AuthorizedBy == "" {
		return fmt.Errorf("authorization.authorized_by is required")
	}
	if a.AgreementRef == "" {
		return fmt.Errorf("authorization.agreement_ref is required")
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
