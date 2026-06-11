// Package triage turns the raw finding stream into a trustworthy, submission-grade
// projection. Autonomous scans produce two kinds of dross: duplicates (the same
// issue observed on many hosts) and noise (low-signal informational hits a scanner
// reports on almost anything). triage collapses the duplicates and flags the noise
// — deterministically, with no model calls — without ever destroying evidence:
// every raw finding still lives in state.State; this is a read-only projection.
package triage

import (
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/state"
)

// TargetEvidence is one host's view of a deduped issue: the original target plus
// the per-target evidence we must not lose when we correlate across hosts.
type TargetEvidence struct {
	Target    string
	Evidence  string
	Tool      string
	Validated bool
}

// Group is one logical issue, correlated across every target it was seen on.
// It keys by (normalized title + tool + severity), so "TLS 1.0 enabled" on ten
// hosts becomes a single Group whose Targets lists all ten — with each host's
// evidence preserved under Evidence.
type Group struct {
	Title    string
	Severity state.Severity
	Tool     string
	// Targets is the full set of affected targets, sorted and de-duplicated.
	Targets []string
	// Evidence holds the per-target evidence aggregated from every member
	// finding, so correlating across hosts never discards a host's proof.
	Evidence []TargetEvidence
	// Representative fields carried from the first member finding for rendering
	// (these are issue-level, not target-level): the description, repro, impact
	// and CVSS vector are properties of the issue, not of a single host.
	Description string
	Repro       string
	Impact      string
	CVSS        string
	// Validated is true if ANY member finding was directly observed — a single
	// confirmed instance makes the correlated issue actionable.
	Validated bool
	// Noise is true when the heuristic judges this issue to be low-signal /
	// likely a false positive (see IsNoise). It is FLAGGED, never dropped, so a
	// report can foreground actionable findings without losing the audit trail.
	Noise bool
}

// Count is the number of distinct affected targets for the group.
func (g Group) Count() int { return len(g.Targets) }

// Result is the triaged projection: actionable issues separated from flagged
// noise, with every original finding accounted for in exactly one bucket.
type Result struct {
	// Actionable are the issues worth a human's attention, sorted by severity
	// (high first) then by breadth (more affected targets first).
	Actionable []Group
	// Noise are issues flagged as likely-informational / false-positive. They are
	// retained (not dropped) so nothing is silently swallowed.
	Noise []Group
}

// All returns actionable issues followed by noise — the full deduped set.
func (r Result) All() []Group {
	out := make([]Group, 0, len(r.Actionable)+len(r.Noise))
	out = append(out, r.Actionable...)
	out = append(out, r.Noise...)
	return out
}

// key correlates findings into one logical issue. Title is normalized
// (case-folded, whitespace-collapsed) so cosmetic differences don't split a
// group; tool and severity round out the identity so genuinely different issues
// that happen to share a title stay separate.
func key(f state.Finding) string {
	return normalizeTitle(f.Title) + "\x00" + f.Tool + "\x00" + f.Severity.String()
}

// normalizeTitle case-folds and collapses whitespace so "TLS 1.0  Enabled" and
// "tls 1.0 enabled" correlate into the same issue.
func normalizeTitle(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// Triage deduplicates and correlates a finding snapshot into logical issues,
// flags likely-noise distinctly from actionable findings, and returns the
// projection. Input order is preserved for the first-seen representative fields;
// output is deterministically sorted. The input slice is never mutated and no
// finding is dropped — every finding lands in exactly one Group.
func Triage(findings []state.Finding) Result {
	order := []string{} // first-seen key order, for deterministic grouping
	groups := map[string]*Group{}
	// seenTarget guards against double-counting the same target within an issue
	// (e.g. the same check re-run on one host).
	seenTarget := map[string]map[string]bool{}

	for _, f := range findings {
		k := key(f)
		g, ok := groups[k]
		if !ok {
			g = &Group{
				Title:       f.Title,
				Severity:    f.Severity,
				Tool:        f.Tool,
				Description: f.Description,
				Repro:       f.Repro,
				Impact:      f.Impact,
				CVSS:        f.CVSS,
			}
			groups[k] = g
			order = append(order, k)
			seenTarget[k] = map[string]bool{}
		}
		// Backfill issue-level rendering fields from later members if the first
		// member left them blank — don't lose a populated CVSS/repro/impact just
		// because the first occurrence omitted it.
		if g.Description == "" {
			g.Description = f.Description
		}
		if g.Repro == "" {
			g.Repro = f.Repro
		}
		if g.Impact == "" {
			g.Impact = f.Impact
		}
		if g.CVSS == "" {
			g.CVSS = f.CVSS
		}
		if f.Validated {
			g.Validated = true
		}
		if !seenTarget[k][f.Target] {
			seenTarget[k][f.Target] = true
			g.Targets = append(g.Targets, f.Target)
		}
		// Per-target evidence is always aggregated (never collapsed away), even
		// when a target repeats, so we keep every distinct proof.
		g.Evidence = append(g.Evidence, TargetEvidence{
			Target:    f.Target,
			Evidence:  f.Evidence,
			Tool:      f.Tool,
			Validated: f.Validated,
		})
	}

	var res Result
	for _, k := range order {
		g := groups[k]
		sort.Strings(g.Targets)
		g.Noise = IsNoise(g.Severity, g.Title)
		if g.Noise {
			res.Noise = append(res.Noise, *g)
		} else {
			res.Actionable = append(res.Actionable, *g)
		}
	}

	sortGroups(res.Actionable)
	sortGroups(res.Noise)
	return res
}

// sortGroups orders by severity (high first), then breadth (more affected
// targets first), then title — a stable, deterministic submission order.
func sortGroups(gs []Group) {
	sort.SliceStable(gs, func(i, j int) bool {
		if gs[i].Severity != gs[j].Severity {
			return gs[i].Severity > gs[j].Severity
		}
		if gs[i].Count() != gs[j].Count() {
			return gs[i].Count() > gs[j].Count()
		}
		return gs[i].Title < gs[j].Title
	})
}

// noisePatterns are substrings (matched case-insensitively against the
// normalized title) of findings a scanner reports on almost any host and that
// rarely represent a real, submittable issue on their own — classic nuclei-style
// info-level chatter (protocol/version detections, generic banners). These are
// flagged, NOT dropped.
var noisePatterns = []string{
	"ikev2",
	"snmpv3",
	"snmp detect",
	"ssh server",
	"ssh detect",
	"tls version",
	"ssl version",
	"http version",
	"server version disclosed",
	"banner",
	"favicon",
	"robots.txt",
	"http missing security headers",
	"waf detect",
	"cdn detect",
	"dns detect",
	"openssh detect",
	"weak cipher detect",
	"technology detect",
	"wappalyzer",
	"detected",
}

// IsNoise reports whether an issue is likely informational / a false positive
// and should be foregrounded separately from actionable findings. The heuristic
// is intentionally conservative: only info-severity findings whose title matches
// a known low-signal pattern are flagged, so nothing severity-bearing is ever
// pushed below the fold. It only marks; the caller must never drop on this basis.
func IsNoise(sev state.Severity, title string) bool {
	if sev != state.SeverityInfo {
		return false
	}
	n := normalizeTitle(title)
	for _, p := range noisePatterns {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}
