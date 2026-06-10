package state

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// CredentialKind classifies a recovered secret.
type CredentialKind string

const (
	CredPassword CredentialKind = "password"
	CredHash     CredentialKind = "hash"
	CredToken    CredentialKind = "token"
	CredKey      CredentialKind = "key"
)

// Credential is a secret RECOVERED during an engagement (creds/hashes/tokens/keys
// found in exposed files, responses, dumped tables, etc.). The plaintext secret
// is held for the operator's report but is treated as sensitive: it is NEVER
// emitted into the planner prompt (it has no path into State.Summary), and audit
// records must reference it via Redacted(), never the raw value.
//
// The `planner` tags keep the quarantine reflect-test honest: Secret is
// quarantined; only non-sensitive descriptors may ever be surfaced.
type Credential struct {
	ID       string         `planner:"quarantined"`
	Kind     CredentialKind `planner:"quarantined"` // enum; never to the model
	Username string         `planner:"quarantined"`
	Secret   string         `planner:"quarantined"` // plaintext/hash — sensitive, never to the model
	Source   string         `planner:"quarantined"` // where it was found (tool/url)
	Target   string         `planner:"quarantined"` // host/service it belongs to
	FoundAt  time.Time
}

// Redacted returns an audit-safe view of the credential: the username, a SHA-256
// of the secret, and its last 4 chars — never the plaintext.
func (c Credential) Redacted() map[string]any {
	sum := sha256.Sum256([]byte(c.Secret))
	last4 := c.Secret
	if len(c.Secret) > 4 {
		last4 = c.Secret[len(c.Secret)-4:]
	}
	return map[string]any{
		"kind": string(c.Kind), "username": c.Username, "target": c.Target,
		"source": c.Source, "secret_sha256": hex.EncodeToString(sum[:]), "secret_last4": last4,
	}
}

// credStore is embedded into State (separate file to keep credential handling
// self-contained). Guarded by State.mu.
type credStore struct {
	mu   sync.Mutex
	keys map[string]bool
	list []Credential
}

// AddCredential records a recovered credential, deduped by (kind, username,
// target, secret). Returns true if it was new.
func (s *State) AddCredential(c Credential) bool {
	s.creds.mu.Lock()
	defer s.creds.mu.Unlock()
	if s.creds.keys == nil {
		s.creds.keys = make(map[string]bool)
	}
	key := string(c.Kind) + "\x00" + c.Username + "\x00" + c.Target + "\x00" + c.Secret
	if s.creds.keys[key] {
		return false
	}
	s.creds.keys[key] = true
	if c.FoundAt.IsZero() {
		c.FoundAt = time.Now().UTC()
	}
	s.creds.list = append(s.creds.list, c)
	return true
}

// Credentials returns a snapshot of recovered credentials.
func (s *State) Credentials() []Credential {
	s.creds.mu.Lock()
	defer s.creds.mu.Unlock()
	out := make([]Credential, len(s.creds.list))
	copy(out, s.creds.list)
	return out
}
