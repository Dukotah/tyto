package state

import (
	"sort"
	"strings"
	"time"
)

// Coverage anchors
// ----------------
// A coverage anchor records that an action or a finding TOUCHED an asset. It is
// the raw material for "what's been tested vs untested": the engine and the
// report can ask whether an asset (and which of its technique directions) has
// been exercised yet, instead of guessing from the finding list.
//
// Anchors are keyed by a free-form asset reference (AssetRef) — the identifier
// the toucher already has (a target string, a flat Asset.ID, or a graph Key).
// The index normalizes that reference so a service touched as "10.0.0.1:443"
// answers the same as an asset whose Value is "10.0.0.1:443".
//
// Quarantine: only Kind and Direction are planner-safe (controlled vocabulary /
// program-generated), and the frontier surfaces coverage as booleans and
// sanitized direction strings — never the quarantined AssetRef/Ref free text.

// CoverageKind says what kind of touch an anchor records.
type CoverageKind string

const (
	CoverageAction  CoverageKind = "action"  // an executed action targeted the asset
	CoverageFinding CoverageKind = "finding" // a finding was raised against the asset
)

// CoverageAnchor is one "X touched asset Y" record.
type CoverageAnchor struct {
	AssetRef  string       `planner:"quarantined"` // which asset was touched (target/id/graph key)
	Kind      CoverageKind `planner:"safe"`         // action | finding
	Ref       string       `planner:"quarantined"` // tool/action key or finding id — tool-controlled
	Direction string       `planner:"safe"`         // optional technique direction this covers
	At        time.Time
}

// AddCoverage records a coverage anchor, deduplicated by
// (AssetRef, Kind, Ref, Direction) so re-touching an asset does not inflate the
// record. It returns true if the anchor was new.
func (s *State) AddCoverage(c CoverageAnchor) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addCoverageLocked(c)
}

// addCoverageLocked is the already-locked body, shared with AddFinding's
// auto-anchor so a finding's target is marked covered without a second lock.
func (s *State) addCoverageLocked(c CoverageAnchor) bool {
	if s.coverageKeys == nil {
		s.coverageKeys = make(map[string]bool)
		s.coveredRefs = make(map[string]bool)
		s.coveredDirs = make(map[string]map[string]bool)
	}
	key := string(c.Kind) + "\x00" + c.AssetRef + "\x00" + c.Ref + "\x00" + c.Direction
	if s.coverageKeys[key] {
		return false
	}
	s.coverageKeys[key] = true
	if c.At.IsZero() {
		c.At = time.Now().UTC()
	}
	s.coverage = append(s.coverage, c)

	ref := normalizeRef(c.AssetRef)
	s.coveredRefs[ref] = true
	if d := normalizeRef(c.Direction); d != "" {
		if s.coveredDirs[ref] == nil {
			s.coveredDirs[ref] = make(map[string]bool)
		}
		s.coveredDirs[ref][d] = true
	}
	return true
}

// Coverage returns a snapshot of all coverage anchors.
func (s *State) Coverage() []CoverageAnchor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CoverageAnchor, len(s.coverage))
	copy(out, s.coverage)
	return out
}

// Covered reports whether any anchor has touched the asset identified by ref
// (matched after normalization).
func (s *State) Covered(ref string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.coveredRefs[normalizeRef(ref)]
}

// coveredLocked / coveredDirLocked are the already-locked lookups the frontier
// uses while it holds the read lock.
func (s *State) coveredLocked(ref string) bool { return s.coveredRefs[normalizeRef(ref)] }

func (s *State) coveredDirLocked(ref, direction string) bool {
	set := s.coveredDirs[normalizeRef(ref)]
	return set != nil && set[normalizeRef(direction)]
}

// normalizeRef canonicalizes an asset reference / direction for index lookups:
// lowercase, trimmed, trailing FQDN dot stripped. It must mirror how the frontier
// derives its lookup candidates.
func normalizeRef(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// CoverageSummary counts, per hierarchy-agnostic asset reference, how many
// anchors touched it, for the report's tested-vs-untested rollup. Keys are the
// normalized references; the slice is sorted for determinism.
func (s *State) CoverageSummary() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	refs := make([]string, 0, len(s.coveredRefs))
	for r := range s.coveredRefs {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	return refs
}
