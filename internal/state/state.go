// Package state is the engagement's memory: discovered assets and findings.
// The planner reads it every cycle to decide what to do next, which is what
// turns a sequence of tool runs into an adaptive engagement.
package state

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Asset is something discovered during the engagement (a host, service, URL...).
// planner tags classify each exported string field for the quarantine boundary
// (see quarantine.go): Attrs holds tool-controlled free text and is quarantined.
type Asset struct {
	ID        string            `planner:"quarantined"`
	Type      string            `planner:"safe"` // host | service | url
	Value     string            `planner:"safe"`
	Attrs     map[string]string // quarantined: not a string field; never enters Summary
	FirstSeen time.Time
}

// State is the concurrent-safe knowledge store for one engagement.
type State struct {
	mu       sync.RWMutex
	assets   map[string]*Asset
	findings []Finding
}

// New returns an empty State.
func New() *State {
	return &State{assets: make(map[string]*Asset)}
}

// AddAsset records (or replaces) an asset by ID.
func (s *State) AddAsset(a *Asset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.FirstSeen.IsZero() {
		a.FirstSeen = time.Now().UTC()
	}
	s.assets[a.ID] = a
}

// Assets returns a snapshot of known assets.
func (s *State) Assets() []*Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Asset, 0, len(s.assets))
	for _, a := range s.assets {
		out = append(out, a)
	}
	return out
}

// AddFinding records a finding.
func (s *State) AddFinding(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.FoundAt.IsZero() {
		f.FoundAt = time.Now().UTC()
	}
	s.findings = append(s.findings, f)
}

// Findings returns a snapshot of all findings.
func (s *State) Findings() []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Finding, len(s.findings))
	copy(out, s.findings)
	return out
}

// Summary renders a compact view of current state for the planner prompt.
func (s *State) Summary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.assets) == 0 && len(s.findings) == 0 {
		return "  (nothing discovered yet — this is the start of the engagement)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  assets: %d, findings: %d\n", len(s.assets), len(s.findings))
	// Only the closed, typed planner projections reach the prompt — never raw
	// tool output. See quarantine.go.
	for _, a := range s.assets {
		v := a.plannerView()
		fmt.Fprintf(&b, "  - asset %s %s\n", v.Type, v.Value)
	}
	for _, f := range s.findings {
		v := f.plannerView()
		fmt.Fprintf(&b, "  - finding [%s] %s (%s)\n", v.Severity, v.Title, v.Target)
	}
	return b.String()
}
