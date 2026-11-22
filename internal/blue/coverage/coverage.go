// Package coverage builds tyto blue's MITRE ATT&CK coverage matrix: for every
// technique in the catalog, is there a detection rule that covers it, and has an
// attack against it been proven-detected by the purple loop?
//
// It is deliberately decoupled from the detection engine: inputs are plain
// technique-ID sets (the detect package contributes the IDs its loaded rules
// tag; the purple loop contributes the IDs it proved detected), so coverage
// depends only on the ATT&CK catalog.
//
// Sub-technique rollup: a covered/detected sub-technique (e.g. T1059.001) also
// marks its parent technique (T1059) covered/detected, so the parent row of the
// grid reflects partial coverage underneath it.
package coverage

import (
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/blue/attack"
)

// Row is one technique's coverage status.
type Row struct {
	Technique attack.Technique
	Covered   bool // a detection rule is tagged with this technique (or a sub-technique of it)
	Detected  bool // the purple loop has proven an attack on this technique was detected
}

// Summary is the rolled-up headline for a matrix.
type Summary struct {
	Total        int
	Covered      int
	Detected     int
	CoveredPct   float64 // Covered / Total * 100
	DetectedPct  float64 // Detected / Total * 100
}

// Matrix is the full coverage view plus its summary and per-tactic rollups.
type Matrix struct {
	Rows      []Row
	Summary   Summary
	ByTactic  map[string]Summary // tactic shortname -> summary over techniques in that tactic
}

// normID trims and upper-cases a technique id so "t1059 " and "T1059" match.
func normID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// parentID returns the parent technique id for a sub-technique ("T1059.001" ->
// "T1059"), or "" if the id is not a sub-technique.
func parentID(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return ""
}

// expand returns the set of ids plus, for every sub-technique id, its parent id,
// so parent rows roll up coverage from their children.
func expand(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids)*2)
	for _, raw := range ids {
		id := normID(raw)
		if id == "" {
			continue
		}
		set[id] = true
		if p := parentID(id); p != "" {
			set[p] = true
		}
	}
	return set
}

// Build computes the coverage matrix over the whole catalog. coveredIDs are the
// technique ids some loaded detection rule is tagged with; detectedIDs are the
// technique ids the purple loop has proven detected. Either may be nil.
func Build(cat *attack.Catalog, coveredIDs, detectedIDs []string) Matrix {
	covered := expand(coveredIDs)
	detected := expand(detectedIDs)

	all := cat.All() // already stable-sorted by ID
	rows := make([]Row, 0, len(all))
	byTactic := map[string]*Summary{}

	var s Summary
	for _, t := range all {
		id := normID(t.ID)
		r := Row{Technique: t, Covered: covered[id], Detected: detected[id]}
		rows = append(rows, r)

		s.Total++
		if r.Covered {
			s.Covered++
		}
		if r.Detected {
			s.Detected++
		}
		for _, tac := range t.Tactics {
			ts := byTactic[tac]
			if ts == nil {
				ts = &Summary{}
				byTactic[tac] = ts
			}
			ts.Total++
			if r.Covered {
				ts.Covered++
			}
			if r.Detected {
				ts.Detected++
			}
		}
	}
	finalize(&s)

	bt := make(map[string]Summary, len(byTactic))
	for k, v := range byTactic {
		finalize(v)
		bt[k] = *v
	}
	return Matrix{Rows: rows, Summary: s, ByTactic: bt}
}

func finalize(s *Summary) {
	if s.Total > 0 {
		s.CoveredPct = float64(s.Covered) / float64(s.Total) * 100
		s.DetectedPct = float64(s.Detected) / float64(s.Total) * 100
	}
}

// Gaps returns techniques with no detection rule coverage at all, stable-sorted
// by ID — the "what we're blind to" list that the purple loop targets first.
func (m Matrix) Gaps() []attack.Technique {
	var out []attack.Technique
	for _, r := range m.Rows {
		if !r.Covered {
			out = append(out, r.Technique)
		}
	}
	return out
}

// CoveredNotDetected returns techniques a rule claims to cover but that the
// purple loop has NOT yet proven detected — the "unverified coverage" list.
func (m Matrix) CoveredNotDetected() []attack.Technique {
	var out []attack.Technique
	for _, r := range m.Rows {
		if r.Covered && !r.Detected {
			out = append(out, r.Technique)
		}
	}
	return out
}

// Tactics returns the tactic shortnames present in the matrix, sorted.
func (m Matrix) Tactics() []string {
	out := make([]string, 0, len(m.ByTactic))
	for k := range m.ByTactic {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
