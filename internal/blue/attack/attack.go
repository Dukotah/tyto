// Package attack provides a MITRE ATT&CK technique catalog used by tyto blue
// to build a detection-coverage map (techniques x {rule-covers-it?,
// proven-detected?}).
//
// The catalog can be populated from the curated offline set embedded in this
// package (see Embedded), which makes the binary work with no network, or from
// the full official machine-readable source via LoadSTIX.
//
// This product uses the MITRE ATT&CK(R) knowledge base. ATT&CK is a registered
// trademark of The MITRE Corporation. The curated data and the STIX loader are
// derived from MITRE ATT&CK content, which is provided under the ATT&CK Terms
// of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/.
// (C) 2015-present The MITRE Corporation. tyto is not affiliated with or
// endorsed by The MITRE Corporation.
package attack

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Technique is a single MITRE ATT&CK (sub-)technique.
type Technique struct {
	// ID is the ATT&CK external id, "T####" for a technique or "T####.###"
	// for a sub-technique.
	ID string
	// Name is the human-readable technique name.
	Name string
	// Tactics are the ATT&CK tactic shortnames this technique belongs to
	// (e.g. "execution", "persistence"), sorted and de-duplicated.
	Tactics []string
	// Description is a one-line summary of the technique.
	Description string
	// URL is the canonical ATT&CK technique page.
	URL string
	// IsSubtechnique reports whether ID names a sub-technique (contains a dot).
	IsSubtechnique bool
}

// Catalog is an immutable, lookup-optimized collection of techniques.
type Catalog struct {
	byID  map[string]Technique
	order []string // technique IDs, stably sorted ascending
}

// newCatalog builds a Catalog from a slice of techniques. Later entries with a
// duplicate ID overwrite earlier ones. IsSubtechnique is derived from the ID so
// callers need not set it. Tactics are normalized (trimmed, de-duplicated,
// sorted).
func newCatalog(techs []Technique) *Catalog {
	c := &Catalog{byID: make(map[string]Technique, len(techs))}
	for _, t := range techs {
		t.ID = strings.TrimSpace(t.ID)
		if t.ID == "" {
			continue
		}
		t.IsSubtechnique = strings.Contains(t.ID, ".")
		t.Tactics = normalizeTactics(t.Tactics)
		c.byID[t.ID] = t
	}
	c.order = make([]string, 0, len(c.byID))
	for id := range c.byID {
		c.order = append(c.order, id)
	}
	sort.Strings(c.order)
	return c
}

// normalizeTactics trims, drops empties, de-duplicates and sorts tactic names.
func normalizeTactics(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the technique with the given ATT&CK id and whether it exists.
func (c *Catalog) Lookup(id string) (Technique, bool) {
	if c == nil {
		return Technique{}, false
	}
	t, ok := c.byID[strings.TrimSpace(id)]
	return t, ok
}

// All returns every technique, stably sorted by ID ascending.
func (c *Catalog) All() []Technique {
	if c == nil {
		return nil
	}
	out := make([]Technique, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.byID[id])
	}
	return out
}

// Len reports the number of techniques in the catalog.
func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.byID)
}

// ByTactic returns every technique associated with the given ATT&CK tactic
// shortname (e.g. "execution"), stably sorted by ID. Matching is
// case-insensitive.
func (c *Catalog) ByTactic(tactic string) []Technique {
	if c == nil {
		return nil
	}
	want := strings.ToLower(strings.TrimSpace(tactic))
	if want == "" {
		return nil
	}
	var out []Technique
	for _, id := range c.order {
		t := c.byID[id]
		for _, tac := range t.Tactics {
			if strings.ToLower(tac) == want {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// --- STIX 2.1 bundle loading ---------------------------------------------

// stixBundle is the minimal shape of a MITRE ATT&CK STIX 2.1 bundle. Only the
// fields tyto needs are decoded; everything else is ignored.
type stixBundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type               string              `json:"type"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	Revoked            bool                `json:"revoked"`
	Deprecated         bool                `json:"x_mitre_deprecated"`
	ExternalReferences []stixExternalRef   `json:"external_references"`
	KillChainPhases    []stixKillChainPhase `json:"kill_chain_phases"`
}

type stixExternalRef struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
	URL        string `json:"url"`
}

type stixKillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// LoadSTIX parses a MITRE ATT&CK STIX 2.1 enterprise-attack bundle (the
// "objects" array form, e.g. enterprise-attack.json from
// github.com/mitre-attack/attack-stix-data) and returns a Catalog.
//
// Only objects of type "attack-pattern" are considered; revoked and deprecated
// techniques are skipped, as are objects lacking a mitre-attack external id.
// Use LoadSTIX to replace the curated offline set (see Embedded) with the full
// official bundle.
func LoadSTIX(r io.Reader) (*Catalog, error) {
	var bundle stixBundle
	dec := json.NewDecoder(r)
	if err := dec.Decode(&bundle); err != nil {
		return nil, fmt.Errorf("attack: decode STIX bundle: %w", err)
	}

	techs := make([]Technique, 0, len(bundle.Objects))
	for _, o := range bundle.Objects {
		if o.Type != "attack-pattern" {
			continue
		}
		if o.Revoked || o.Deprecated {
			continue
		}
		id, url := attackRef(o.ExternalReferences)
		if id == "" {
			continue
		}
		techs = append(techs, Technique{
			ID:          id,
			Name:        strings.TrimSpace(o.Name),
			Tactics:     phaseNames(o.KillChainPhases),
			Description: firstLine(o.Description),
			URL:         url,
		})
	}
	return newCatalog(techs), nil
}

// attackRef returns the mitre-attack external_id and URL from a STIX object's
// external references, if present.
func attackRef(refs []stixExternalRef) (id, url string) {
	for _, ref := range refs {
		if ref.SourceName == "mitre-attack" {
			return strings.TrimSpace(ref.ExternalID), strings.TrimSpace(ref.URL)
		}
	}
	return "", ""
}

// phaseNames extracts the mitre-attack kill-chain phase_names (ATT&CK tactic
// shortnames) from a STIX object.
func phaseNames(phases []stixKillChainPhase) []string {
	var out []string
	for _, p := range phases {
		if p.KillChainName == "mitre-attack" {
			out = append(out, strings.TrimSpace(p.PhaseName))
		}
	}
	return out
}

// firstLine collapses a (possibly multi-paragraph) STIX description to a single
// trimmed line.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
