package purple

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const tsLayout = "2006-01-02 15:04:05Z"

func ts(t time.Time) string { return t.UTC().Format(tsLayout) }

func techIDs(a Activity) string {
	ids := make([]string, len(a.Techniques))
	for i, t := range a.Techniques {
		ids[i] = t.ID
	}
	return strings.Join(ids, ", ")
}

// cell makes a value safe inside a Markdown table cell. Targets and alert names
// are attacker- or SIEM-controlled text, so pipes and newlines are neutralized.
func cell(s string) string {
	s = strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "`", "'").Replace(s)
	if s == "" {
		return "—"
	}
	return s
}

func dur(sec float64) string {
	d := time.Duration(sec * float64(time.Second)).Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return d.String()
}

func writeHeader(b *strings.Builder, tl Timeline) {
	if tl.EngagementID != "" {
		fmt.Fprintf(b, "**Engagement:** %s", tl.EngagementID)
		if tl.Client != "" {
			fmt.Fprintf(b, " (%s)", tl.Client)
		}
		b.WriteString("  \n")
	}
	if !tl.Start.IsZero() {
		fmt.Fprintf(b, "**Activity window (UTC):** %s → %s  \n", ts(tl.Start), ts(tl.End))
	}
	if tl.Source != "" {
		fmt.Fprintf(b, "**Test traffic source:** %s  \n", tl.Source)
	}
	if tl.Marker != nil {
		fmt.Fprintf(b, "**Traffic marker:** native HTTP requests to in-scope hosts carried `%s: %s`  \n", tl.Marker.Header, tl.Marker.Value)
	}
	if tl.ChainVerified {
		b.WriteString("**Audit chain:** verified intact\n\n")
	} else {
		fmt.Fprintf(b, "**Audit chain:** ⚠ BROKEN — %s. Do not treat this document as evidence.\n\n", tl.ChainError)
	}
}

// RenderTimelineMarkdown is the SOC-facing attack timeline: what was done, when,
// to what, and where it should have been visible.
func RenderTimelineMarkdown(tl Timeline) string {
	var b strings.Builder
	b.WriteString("# Attack timeline\n\n")
	writeHeader(&b, tl)
	if len(tl.Activities) == 0 {
		b.WriteString("No executed actions were found in the audit log.\n")
		return b.String()
	}
	b.WriteString("Each row is one action tyto executed. Times are UTC, from the tyto host's clock; the window runs from when the action was admitted to when its result was recorded, so the traffic falls inside it.\n\n")
	b.WriteString("| # | Start | End | Target | Tool | ATT&CK | Where to look |\n|---|---|---|---|---|---|---|\n")
	for _, a := range tl.Activities {
		where := strings.Join(a.Telemetry, "; ")
		switch {
		case a.OffTarget:
			where = "off-target (no traffic to client systems)"
		case !a.Mapped:
			where = "free-form command — see the audit log for what ran"
		}
		end := ts(a.End)
		if a.Incomplete {
			end = "interrupted"
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s | %s |\n",
			a.Seq, ts(a.Start), end, cell(a.Target), cell(a.Tool), cell(techIDs(a)), cell(where))
	}
	if len(tl.Defenses) > 0 {
		b.WriteString("\n## Defensive reactions tyto observed\n\n| Time | Target | Reaction | After |\n|---|---|---|---|\n")
		for _, d := range tl.Defenses {
			after := "—"
			if d.AfterActions > 0 {
				after = fmt.Sprintf("%d action(s)", d.AfterActions)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", ts(d.Time), cell(d.Target), cell(d.Kind), after)
		}
	}
	return b.String()
}

// RenderTimelineCSV is the timeline as CSV, for import into a SIEM lookup table
// or a spreadsheet.
func RenderTimelineCSV(tl Timeline) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"seq", "start_utc", "end_utc", "source", "target", "host", "tool", "attack_ids", "attack_names", "tactics", "expected_telemetry", "off_target", "success", "findings"})
	for _, a := range tl.Activities {
		var names, tactics []string
		for _, t := range a.Techniques {
			names = append(names, t.Name)
			tactics = append(tactics, t.Tactic)
		}
		_ = w.Write([]string{
			fmt.Sprint(a.Seq), a.Start.UTC().Format(time.RFC3339), a.End.UTC().Format(time.RFC3339),
			tl.Source, a.Target, a.Host, a.Tool, strings.ReplaceAll(techIDs(a), ", ", ";"),
			strings.Join(names, ";"), strings.Join(dedupe(tactics), ";"), strings.Join(a.Telemetry, "; "),
			fmt.Sprint(a.OffTarget), fmt.Sprint(a.Success), fmt.Sprint(a.Findings),
		})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// RenderScoreMarkdown is the detection-coverage report.
func RenderScoreMarkdown(sc Scorecard) string {
	var b strings.Builder
	b.WriteString("# Detection coverage\n\n")
	writeHeader(&b, sc.Timeline)

	fmt.Fprintf(&b, "## Result\n\n**%d of %d** attacker actions were detected (**%.0f%%**).\n\n", sc.Detected, sc.Scored, sc.CoveragePct)
	fmt.Fprintf(&b, "- Detected (an alert naming the target fired): %d\n", sc.Detected)
	fmt.Fprintf(&b, "- Weak (an alert fired in the window but named no target): %d\n", sc.Weak)
	fmt.Fprintf(&b, "- Missed (nothing fired): %d\n", sc.Missed)
	if sc.NotScored > 0 {
		fmt.Fprintf(&b, "- Not scored (off-target activity no client sensor could see): %d\n", sc.NotScored)
	}
	if sc.MedianTimeToDetectSec != nil {
		fmt.Fprintf(&b, "- Median time to detect: %s\n", dur(*sc.MedianTimeToDetectSec))
	}
	fmt.Fprintf(&b, "- Alerts loaded: %d (%d unattributed, %d outside the engagement window)\n", sc.AlertsLoaded, len(sc.Unattributed), sc.OutsideWindow)
	fmt.Fprintf(&b, "\nCorrelation: an alert is credited to one action if it fired between %s before the action started and %s after it ended, and (when the alert names a target) names that action's host.\n\n", sc.Skew, sc.Grace)

	if len(sc.ByTechnique) > 0 {
		b.WriteString("## Coverage by ATT&CK technique\n\n| Technique | Name | Tactic | Exercised | Detected | Weak | Missed |\n|---|---|---|---|---|---|---|\n")
		for _, t := range sc.ByTechnique {
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %d |\n", t.ID, cell(t.Name), cell(t.Tactic), t.Exercised, t.Detected, t.Weak, t.Exercised-t.Detected-t.Weak)
		}
		b.WriteString("\n")
	}
	if len(sc.ByHost) > 0 {
		b.WriteString("## Coverage by target\n\n| Target | Exercised | Detected | Weak | Time to first detection |\n|---|---|---|---|---|\n")
		for _, h := range sc.ByHost {
			ttd := "never detected"
			if h.TimeToFirstDetectSec != nil {
				ttd = dur(*h.TimeToFirstDetectSec)
			}
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %s |\n", cell(h.Host), h.Exercised, h.Detected, h.Weak, ttd)
		}
		b.WriteString("\n")
	}

	// Gaps first: the missed actions are the actionable part of this report.
	var missed []ActivityResult
	for _, r := range sc.Results {
		if r.Status == StatusMissed {
			missed = append(missed, r)
		}
	}
	if len(missed) > 0 {
		b.WriteString("## Detection gaps\n\nThese actions ran and produced no alert. Each row says where the activity should be visible.\n\n| # | Start | Target | Tool | ATT&CK | Where to look |\n|---|---|---|---|---|---|\n")
		for _, r := range missed {
			where := strings.Join(r.Telemetry, "; ")
			if !r.Mapped {
				where = "free-form command — see the audit log for what ran"
			}
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s |\n", r.Seq, ts(r.Start), cell(r.Target), cell(r.Tool), cell(techIDs(r.Activity)), cell(where))
		}
		b.WriteString("\n")
	}

	b.WriteString("## All actions\n\n| # | Start | Target | Tool | ATT&CK | Status | First alert | Time to detect |\n|---|---|---|---|---|---|---|---|\n")
	for _, r := range sc.Results {
		first, ttd := "—", "—"
		if len(r.Alerts) > 0 {
			first = cell(r.Alerts[0].Name)
		}
		if r.TimeToDetectSec != nil {
			ttd = dur(*r.TimeToDetectSec)
		}
		status := r.Status
		if r.TechniqueConfirmed {
			status += " (technique matched)"
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s | %s | %s |\n", r.Seq, ts(r.Start), cell(r.Target), cell(r.Tool), cell(techIDs(r.Activity)), status, first, ttd)
	}

	if len(sc.Unattributed) > 0 {
		b.WriteString("\n## Unattributed alerts\n\nThese fired during the engagement but match no tyto action. They are either false positives or activity that was not this test — review each one.\n\n| Time | Alert | Source | Target |\n|---|---|---|---|\n")
		for _, al := range sc.Unattributed {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", ts(al.Time), cell(al.Name), cell(al.Source), cell(al.Target))
		}
	}
	if len(sc.Timeline.Defenses) > 0 {
		b.WriteString("\n## Preventive controls that reacted\n\nSeparate from alerting: these are reactions tyto itself ran into.\n\n| Time | Target | Reaction |\n|---|---|---|\n")
		for _, d := range sc.Timeline.Defenses {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", ts(d.Time), cell(d.Target), cell(d.Kind))
		}
	}
	return b.String()
}

// navigator layer types (MITRE ATT&CK Navigator layer format 4.x).
type navLayer struct {
	Name        string            `json:"name"`
	Versions    map[string]string `json:"versions"`
	Domain      string            `json:"domain"`
	Description string            `json:"description"`
	Techniques  []navTechnique    `json:"techniques"`
	Gradient    navGradient       `json:"gradient"`
	LegendItems []navLegend       `json:"legendItems"`
}

type navTechnique struct {
	TechniqueID       string `json:"techniqueID"`
	Score             int    `json:"score"`
	Color             string `json:"color,omitempty"`
	Comment           string `json:"comment,omitempty"`
	ShowSubtechniques bool   `json:"showSubtechniques"`
}

type navGradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

type navLegend struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

const (
	navRed     = "#e06666"
	navAmber   = "#ffd966"
	navGreen   = "#93c47d"
	navNeutral = "#9fc5e8"
)

// RenderNavigatorLayer builds an ATT&CK Navigator layer. With a scorecard the
// layer is colored by detection coverage (red = exercised and never detected,
// amber = partly detected, green = always detected) and scored 0–100. With only
// a timeline (sc nil) it shows which techniques were exercised and how often.
func RenderNavigatorLayer(tl Timeline, sc *Scorecard) ([]byte, error) {
	name := "tyto"
	if tl.EngagementID != "" {
		name = "tyto — " + tl.EngagementID
	}
	layer := navLayer{
		Versions: map[string]string{"layer": "4.5", "navigator": "4.9.1"},
		Domain:   "enterprise-attack",
	}
	if sc != nil {
		layer.Name = name + " — detection coverage"
		layer.Description = fmt.Sprintf("Detection coverage of the techniques exercised in this engagement: %d of %d actions detected (%.0f%%). Score is the percentage of actions per technique that raised a target-confirmed alert.", sc.Detected, sc.Scored, sc.CoveragePct)
		layer.Gradient = navGradient{Colors: []string{navRed, navAmber, navGreen}, MinValue: 0, MaxValue: 100}
		layer.LegendItems = []navLegend{{"exercised, never detected", navRed}, {"partly detected", navAmber}, {"always detected", navGreen}}
		for _, t := range sc.ByTechnique {
			score := 0
			if t.Exercised > 0 {
				score = 100 * t.Detected / t.Exercised
			}
			color := navAmber
			switch {
			case t.Detected == 0:
				color = navRed
			case t.Detected == t.Exercised:
				color = navGreen
			}
			layer.Techniques = append(layer.Techniques, navTechnique{
				TechniqueID: t.ID, Score: score, Color: color, ShowSubtechniques: true,
				Comment: fmt.Sprintf("exercised %d, detected %d, weak %d, missed %d", t.Exercised, t.Detected, t.Weak, t.Exercised-t.Detected-t.Weak),
			})
		}
	} else {
		layer.Name = name + " — techniques exercised"
		layer.Description = "ATT&CK techniques exercised in this engagement. Score is the number of actions per technique."
		counts := map[string]int{}
		tools := map[string][]string{}
		max := 1
		for _, a := range tl.Activities {
			if a.OffTarget {
				continue
			}
			for _, t := range a.Techniques {
				counts[t.ID]++
				tools[t.ID] = append(tools[t.ID], a.Tool)
				if counts[t.ID] > max {
					max = counts[t.ID]
				}
			}
		}
		ids := make([]string, 0, len(counts))
		for id := range counts {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		layer.Gradient = navGradient{Colors: []string{"#ffffff", navNeutral}, MinValue: 0, MaxValue: max}
		layer.LegendItems = []navLegend{{"exercised", navNeutral}}
		for _, id := range ids {
			used := dedupe(tools[id])
			sort.Strings(used)
			layer.Techniques = append(layer.Techniques, navTechnique{
				TechniqueID: id, Score: counts[id], ShowSubtechniques: true,
				Comment: fmt.Sprintf("%d action(s) via %s", counts[id], strings.Join(used, ", ")),
			})
		}
	}
	if layer.Techniques == nil {
		layer.Techniques = []navTechnique{}
	}
	return json.MarshalIndent(layer, "", "  ")
}
