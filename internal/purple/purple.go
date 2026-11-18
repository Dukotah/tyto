// Package purple is tyto's purple loop: it drives an attack, checks whether the
// blue detection engine caught it, scores the result on the MITRE ATT&CK
// coverage grid, and for every attacked technique that went undetected it drafts
// a starter Sigma rule from the telemetry that should have fired.
//
// This is the differentiator — an open, local-model version of what commercial
// breach-and-attack-simulation platforms do. The Attacker interface is the seam
// where tyto's real offensive engine plus a telemetry sensor (Sysmon/Suricata
// watching the lab host during the attack window) plug in; the scoring, gap
// analysis and rule-drafting below are real and exercised by tests with a
// fixture attacker.
package purple

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/blue/attack"
	"github.com/dukotah/tyto/internal/blue/coverage"
	"github.com/dukotah/tyto/internal/blue/detect"
	"github.com/dukotah/tyto/internal/blue/event"
)

// Step is one attack action tagged with the ATT&CK technique it exercises and
// the telemetry events it produced during its window. In a live run the events
// come from the sensor; in tests they are fixtures.
type Step struct {
	Technique string
	Name      string
	Events    []event.Event
}

// Attacker runs the attack and returns the steps it executed with their
// telemetry. A live implementation wraps a tyto engagement + a log sensor.
type Attacker interface {
	Run(ctx context.Context) ([]Step, error)
}

// DraftRule is a starter Sigma rule generated for an undetected technique.
type DraftRule struct {
	Technique string
	Title     string
	YAML      string
}

// Report is the outcome of one purple-loop run.
type Report struct {
	Attacked   []string        // distinct techniques the attack exercised (sorted)
	Detected   []string        // attacked techniques a detection fired on (sorted)
	Missed     []string        // attacked techniques with NO detection — the gaps (sorted)
	FiredRules []string        // rule IDs that fired (sorted, deduped)
	Events     int             // telemetry events evaluated
	Matrix     coverage.Matrix // full ATT&CK coverage grid
	Drafts     []DraftRule     // starter rules for the misses
}

// Engine runs purple loops against a detector + ATT&CK catalog.
type Engine struct {
	det *detect.Detector
	cat *attack.Catalog
}

func New(det *detect.Detector, cat *attack.Catalog) *Engine {
	return &Engine{det: det, cat: cat}
}

func normID(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// Run executes the attacker, evaluates every emitted event against the detection
// engine, and scores detection coverage of the exercised techniques.
func (e *Engine) Run(ctx context.Context, atk Attacker) (Report, error) {
	steps, err := atk.Run(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("attacker run: %w", err)
	}

	attackedSet := map[string]bool{}
	detectedSet := map[string]bool{}
	firedRules := map[string]bool{}
	// first undetected event per technique, for rule drafting
	missExemplar := map[string]event.Event{}
	events := 0

	for _, st := range steps {
		tech := normID(st.Technique)
		if tech != "" {
			attackedSet[tech] = true
		}
		stepFired := false
		for _, ev := range st.Events {
			events++
			for _, d := range e.det.Eval(ev) {
				if !d.Matched {
					continue
				}
				firedRules[d.RuleID] = true
				dt := normID(d.Technique)
				if dt != "" {
					detectedSet[dt] = true
				}
				if dt == tech {
					stepFired = true
				}
			}
		}
		// If this step's own technique never fired, remember an exemplar event
		// so we can draft a rule for it.
		if tech != "" && !stepFired {
			if _, ok := missExemplar[tech]; !ok && len(st.Events) > 0 {
				missExemplar[tech] = st.Events[0]
			}
		}
	}

	attacked := sortedKeys(attackedSet)
	var detected, missed []string
	for _, t := range attacked {
		if detectedSet[t] {
			detected = append(detected, t)
		} else {
			missed = append(missed, t)
		}
	}

	// coverage: "covered" = techniques some loaded rule is tagged with;
	// "detected" = techniques actually proven detected in THIS run.
	covered := ruleTechniques(e.det)
	m := coverage.Build(e.cat, covered, detected)

	var drafts []DraftRule
	for _, t := range missed {
		ev, ok := missExemplar[t]
		if !ok {
			continue // nothing to draft from
		}
		drafts = append(drafts, draftFromEvent(t, ev))
	}

	return Report{
		Attacked:   attacked,
		Detected:   detected,
		Missed:     missed,
		FiredRules: sortedKeys(firedRules),
		Events:     events,
		Matrix:     m,
		Drafts:     drafts,
	}, nil
}

// ruleTechniques collects the distinct ATT&CK technique ids the detector's
// loaded rules are tagged with.
func ruleTechniques(det *detect.Detector) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range det.Rules() {
		id := normID(r.Technique)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// draftFromEvent synthesizes a minimal Sigma rule that WOULD have caught the
// given event, keyed on its most distinctive fields, tagged with the technique.
// It is a starting point for an analyst to refine, not a finished detection.
func draftFromEvent(technique string, ev event.Event) DraftRule {
	tech := normID(technique)
	var sel []string
	if ev.Class != "" {
		sel = append(sel, fmt.Sprintf("    Class: '%s'", ev.Class))
	}
	if p := lastPathSegment(ev.Process); p != "" {
		sel = append(sel, fmt.Sprintf("    Image|endswith: '%s'", p))
	}
	if tok := distinctiveToken(ev.CommandLine); tok != "" {
		sel = append(sel, fmt.Sprintf("    CommandLine|contains: '%s'", tok))
	}
	if ev.DstPort != 0 {
		sel = append(sel, fmt.Sprintf("    DstPort: '%d'", ev.DstPort))
	}
	if len(sel) == 0 {
		// fall back to a message substring so we always produce something usable
		if tok := distinctiveToken(ev.Message); tok != "" {
			sel = append(sel, fmt.Sprintf("    Message|contains: '%s'", tok))
		} else {
			sel = append(sel, "    Class: '"+ev.Class+"'")
		}
	}

	title := fmt.Sprintf("DRAFT: detect %s via %s", tech, ev.Class)
	var b strings.Builder
	fmt.Fprintf(&b, "title: %s\n", title)
	fmt.Fprintf(&b, "id: draft-%s\n", strings.ToLower(tech))
	b.WriteString("status: experimental\n")
	fmt.Fprintf(&b, "description: >\n  Auto-drafted by the tyto purple loop for an undetected attack on %s.\n  Review and tighten before use.\n", tech)
	b.WriteString("author: tyto blue purple\n")
	b.WriteString("level: medium\n")
	b.WriteString("tags:\n")
	fmt.Fprintf(&b, "  - attack.%s\n", strings.ToLower(tech))
	b.WriteString("detection:\n")
	b.WriteString("  selection:\n")
	b.WriteString(strings.Join(sel, "\n"))
	b.WriteString("\n  condition: selection\n")

	return DraftRule{Technique: tech, Title: title, YAML: b.String()}
}

func lastPathSegment(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\\", "/")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	// strip trailing args if the field was a full command line
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	return s
}

// distinctiveToken picks the longest alphanumeric-ish token from s (lowercased),
// a crude but deterministic "most specific substring" for a draft selector.
func distinctiveToken(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	})
	best := ""
	for _, f := range fields {
		if len(f) > len(best) {
			best = f
		}
	}
	if len(best) < 4 { // too short to be distinctive
		return ""
	}
	return best
}
