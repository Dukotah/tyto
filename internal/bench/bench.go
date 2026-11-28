// Package bench scores a tyto run against the benchmark lab's answer key, so a
// change to the tooling — or to the model driving it — can be judged by numbers:
// how many planted vulnerabilities were found, how many were proven, how many
// false positives were raised, and what it cost in actions.
//
// It scores two ordinary tyto artifacts and nothing else: the JSON report
// (what was claimed) and, optionally, the audit log (what it took). That keeps it
// independent of how the run was driven — scripted, a local model, or an external
// agent over MCP all produce the same two files.
package bench

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/bench/lab"
)

// Finding is the subset of a report finding the scorer reads. It matches the
// JSON report's finding objects.
type Finding struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Target      string `json:"target"`
	Tool        string `json:"tool"`
	Validated   bool   `json:"validated"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Repro       string `json:"repro"`
}

func (f Finding) text() string {
	return strings.Join([]string{f.Title, f.Target, f.Description, f.Evidence, f.Repro}, "\n")
}

// ParseReport extracts the findings from a tyto JSON report (--report-format json).
func ParseReport(data []byte) ([]Finding, error) {
	var r struct {
		Findings []Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("bench: not a tyto JSON report: %w", err)
	}
	return r.Findings, nil
}

// ItemResult is the outcome for one planted vulnerability.
type ItemResult struct {
	ID       string `json:"id"`
	Tier     string `json:"tier"`
	Title    string `json:"title"`
	Location string `json:"location"`
	Found    bool   `json:"found"`
	// Validated is true when at least one crediting finding was directly observed
	// by a tool (Finding.Validated) rather than inferred or operator-asserted.
	Validated bool     `json:"validated"`
	Tools     []string `json:"tools,omitempty"`
	Evidence  []string `json:"evidence,omitempty"` // titles of the crediting findings
}

// FalsePositive is a finding that claims a vulnerability in a decoy.
type FalsePositive struct {
	Decoy   string `json:"decoy"`
	About   string `json:"about"`
	Tool    string `json:"tool"`
	Finding string `json:"finding"`
	Target  string `json:"target"`
}

// TierScore is recall within one tier.
type TierScore struct {
	Tier      string `json:"tier"`
	Planted   int    `json:"planted"`
	Found     int    `json:"found"`
	Validated int    `json:"validated"`
}

// Effort is what the run cost, read from the audit log.
type Effort struct {
	Executed        int     `json:"actions_executed"`
	Denied          int     `json:"actions_denied"`
	DurationSeconds float64 `json:"duration_seconds"`
	// ActionsPerFound is executed actions per planted item found — lower is a more
	// efficient operator. Zero when nothing was found.
	ActionsPerFound float64        `json:"actions_per_found"`
	ByTool          map[string]int `json:"by_tool,omitempty"`
}

// Result is a scored benchmark run.
type Result struct {
	Label      string    `json:"label"`
	LabVersion int       `json:"lab_version"`
	ScoredAt   time.Time `json:"scored_at"`

	Planted   int `json:"planted"`
	Found     int `json:"found"`
	Validated int `json:"validated"`
	// RecallPct is found / planted. ValidatedRecallPct counts only items backed by
	// a directly-observed finding.
	RecallPct          float64 `json:"recall_pct"`
	ValidatedRecallPct float64 `json:"validated_recall_pct"`
	// PrecisionPct is found / (found + decoys hit): of the distinct things the run
	// claimed about the lab's testable endpoints, how many were real.
	PrecisionPct float64 `json:"precision_pct"`
	DecoysHit    int     `json:"decoys_hit"`

	Tiers          []TierScore     `json:"tiers"`
	Items          []ItemResult    `json:"items"`
	FalsePositives []FalsePositive `json:"false_positives,omitempty"`
	// Unmatched are non-informational findings that correspond to neither a
	// planted item nor a decoy. They are not scored either way — review them: they
	// are either noise or a real observation the answer key does not list.
	Unmatched     []string `json:"unmatched,omitempty"`
	FindingsTotal int      `json:"findings_total"`
	Effort        *Effort  `json:"effort,omitempty"`
}

// Score grades findings against the lab answer key. entries may be nil when no
// audit log is available (effort is then omitted).
func Score(label string, findings []Finding, entries []audit.Entry) Result {
	res := Result{Label: label, LabVersion: lab.Version, ScoredAt: time.Now().UTC(), FindingsTotal: len(findings)}
	answers := lab.Answers()
	items := make(map[string]*ItemResult, len(answers))
	for _, p := range answers {
		items[p.ID] = &ItemResult{ID: p.ID, Tier: p.Tier, Title: p.Title, Location: p.Location}
	}
	decoyTitle := map[string]string{}
	for _, d := range lab.Decoys() {
		decoyTitle[d.ID] = d.Title + " — " + d.Location
	}

	decoysHit := map[string]bool{}
	for _, f := range findings {
		decoy, ids := lab.Classify(f.text())
		switch {
		case decoy != "":
			// An informational note about a decoy ("tested, not vulnerable") is not a
			// claim; only a finding that carries a severity counts against the run.
			if f.Severity == "info" {
				continue
			}
			decoysHit[decoy] = true
			res.FalsePositives = append(res.FalsePositives, FalsePositive{
				Decoy: decoy, About: decoyTitle[decoy], Tool: f.Tool, Finding: f.Title, Target: f.Target,
			})
		case len(ids) > 0:
			for _, id := range ids {
				it := items[id]
				it.Found = true
				it.Validated = it.Validated || f.Validated
				if !contains(it.Tools, f.Tool) {
					it.Tools = append(it.Tools, f.Tool)
				}
				if len(it.Evidence) < 3 {
					it.Evidence = append(it.Evidence, f.Title)
				}
			}
		case f.Severity != "info" && f.Severity != "":
			res.Unmatched = append(res.Unmatched, fmt.Sprintf("[%s] %s (%s) — %s", f.Severity, f.Title, f.Tool, f.Target))
		}
	}
	res.DecoysHit = len(decoysHit)

	tiers := map[string]*TierScore{}
	for _, tier := range []string{lab.TierSurface, lab.TierInjection, lab.TierChain} {
		tiers[tier] = &TierScore{Tier: tier}
		res.Tiers = append(res.Tiers, TierScore{})
	}
	for _, p := range answers {
		it := items[p.ID]
		sort.Strings(it.Tools)
		res.Items = append(res.Items, *it)
		res.Planted++
		ts := tiers[p.Tier]
		ts.Planted++
		if it.Found {
			res.Found++
			ts.Found++
		}
		if it.Found && it.Validated {
			res.Validated++
			ts.Validated++
		}
	}
	for i, tier := range []string{lab.TierSurface, lab.TierInjection, lab.TierChain} {
		res.Tiers[i] = *tiers[tier]
	}
	if res.Planted > 0 {
		res.RecallPct = pct(res.Found, res.Planted)
		res.ValidatedRecallPct = pct(res.Validated, res.Planted)
	}
	if claims := res.Found + res.DecoysHit; claims > 0 {
		res.PrecisionPct = pct(res.Found, claims)
	}
	sort.Strings(res.Unmatched)

	if len(entries) > 0 {
		res.Effort = effort(entries, res.Found)
	}
	return res
}

func effort(entries []audit.Entry, found int) *Effort {
	e := &Effort{ByTool: map[string]int{}}
	for _, en := range entries {
		switch en.Kind {
		case "action":
			e.Executed++
			if t, _ := en.Data["tool"].(string); t != "" {
				e.ByTool[t]++
			}
		case "decision":
			if allowed, ok := en.Data["allowed"].(bool); ok && !allowed {
				e.Denied++
			}
		}
	}
	e.DurationSeconds = entries[len(entries)-1].Time.Sub(entries[0].Time).Seconds()
	if found > 0 {
		e.ActionsPerFound = float64(e.Executed) / float64(found)
	}
	return e
}

func pct(n, d int) float64 { return float64(int(1000*float64(n)/float64(d)+0.5)) / 10 }

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func mark(ok bool) string {
	if ok {
		return "yes"
	}
	return "—"
}

// RenderMarkdown is the human-readable scorecard.
func RenderMarkdown(r Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Benchmark result — %s\n\n", r.Label)
	fmt.Fprintf(&b, "Lab answer key v%d · scored %s\n\n", r.LabVersion, r.ScoredAt.Format("2006-01-02 15:04Z"))
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Planted vulnerabilities found | **%d of %d (%.0f%%)** |\n", r.Found, r.Planted, r.RecallPct)
	fmt.Fprintf(&b, "| …of which proven by a tool | %d (%.0f%%) |\n", r.Validated, r.ValidatedRecallPct)
	fmt.Fprintf(&b, "| False positives (decoys reported) | %d of %d decoys |\n", r.DecoysHit, len(lab.Decoys()))
	fmt.Fprintf(&b, "| Precision | %.0f%% |\n", r.PrecisionPct)
	if e := r.Effort; e != nil {
		fmt.Fprintf(&b, "| Actions executed | %d (%d denied by the guard) |\n", e.Executed, e.Denied)
		if e.ActionsPerFound > 0 {
			fmt.Fprintf(&b, "| Actions per vulnerability found | %.1f |\n", e.ActionsPerFound)
		}
		fmt.Fprintf(&b, "| Duration | %s |\n", time.Duration(e.DurationSeconds*float64(time.Second)).Round(time.Second))
	}
	b.WriteString("\n## By tier\n\n| Tier | Found | Proven |\n|---|---|---|\n")
	for _, t := range r.Tiers {
		fmt.Fprintf(&b, "| %s | %d of %d | %d |\n", t.Tier, t.Found, t.Planted, t.Validated)
	}
	b.WriteString("\n## Planted vulnerabilities\n\n| Tier | Vulnerability | Where | Found | Proven | By |\n|---|---|---|---|---|---|\n")
	for _, it := range r.Items {
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s | %s |\n", it.Tier, it.Title, it.Location, mark(it.Found), mark(it.Found && it.Validated), strings.Join(it.Tools, ", "))
	}
	if len(r.FalsePositives) > 0 {
		b.WriteString("\n## False positives\n\nThese findings claim a vulnerability in an endpoint that is correctly implemented.\n\n| Decoy | Tool | Finding |\n|---|---|---|\n")
		for _, fp := range r.FalsePositives {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", fp.About, fp.Tool, strings.ReplaceAll(fp.Finding, "|", "\\|"))
		}
	}
	if len(r.Unmatched) > 0 {
		fmt.Fprintf(&b, "\n## Unscored findings (%d)\n\nNot in the answer key and not a decoy. Review: each is either noise or a real observation the key does not list.\n\n", len(r.Unmatched))
		for _, u := range r.Unmatched {
			fmt.Fprintf(&b, "- %s\n", strings.ReplaceAll(u, "\n", " "))
		}
	}
	return b.String()
}

// Compare renders what changed between a baseline result and a new one.
func Compare(base, cur Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Benchmark comparison — %s → %s\n\n", base.Label, cur.Label)
	if base.LabVersion != cur.LabVersion {
		fmt.Fprintf(&b, "**Warning:** these runs used different answer keys (v%d vs v%d); the numbers are not directly comparable.\n\n", base.LabVersion, cur.LabVersion)
	}
	delta := func(a, c float64, unit string) string {
		d := c - a
		switch {
		case d > 0:
			return fmt.Sprintf("+%.4g%s", d, unit)
		case d < 0:
			return fmt.Sprintf("%.4g%s", d, unit)
		}
		return "no change"
	}
	b.WriteString("| Metric | " + base.Label + " | " + cur.Label + " | Change |\n|---|---|---|---|\n")
	fmt.Fprintf(&b, "| Found | %d of %d | %d of %d | %s |\n", base.Found, base.Planted, cur.Found, cur.Planted, delta(float64(base.Found), float64(cur.Found), ""))
	fmt.Fprintf(&b, "| Proven by a tool | %d | %d | %s |\n", base.Validated, cur.Validated, delta(float64(base.Validated), float64(cur.Validated), ""))
	fmt.Fprintf(&b, "| False positives | %d | %d | %s |\n", base.DecoysHit, cur.DecoysHit, delta(float64(base.DecoysHit), float64(cur.DecoysHit), ""))
	fmt.Fprintf(&b, "| Precision | %.0f%% | %.0f%% | %s |\n", base.PrecisionPct, cur.PrecisionPct, delta(base.PrecisionPct, cur.PrecisionPct, " pts"))
	for i := range base.Tiers {
		if i < len(cur.Tiers) {
			bt, ct := base.Tiers[i], cur.Tiers[i]
			fmt.Fprintf(&b, "| Found — %s | %d of %d | %d of %d | %s |\n", bt.Tier, bt.Found, bt.Planted, ct.Found, ct.Planted, delta(float64(bt.Found), float64(ct.Found), ""))
		}
	}
	if base.Effort != nil && cur.Effort != nil {
		fmt.Fprintf(&b, "| Actions executed | %d | %d | %s |\n", base.Effort.Executed, cur.Effort.Executed, delta(float64(base.Effort.Executed), float64(cur.Effort.Executed), ""))
	}

	was := map[string]ItemResult{}
	for _, it := range base.Items {
		was[it.ID] = it
	}
	var gained, lost, proven []string
	for _, it := range cur.Items {
		prev, ok := was[it.ID]
		if !ok {
			continue
		}
		switch {
		case it.Found && !prev.Found:
			gained = append(gained, fmt.Sprintf("%s (%s, `%s`)", it.Title, it.Tier, it.Location))
		case !it.Found && prev.Found:
			lost = append(lost, fmt.Sprintf("%s (%s, `%s`)", it.Title, it.Tier, it.Location))
		case it.Found && it.Validated && !prev.Validated:
			proven = append(proven, it.Title)
		}
	}
	list := func(heading string, xs []string) {
		if len(xs) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n## %s\n\n", heading)
		for _, x := range xs {
			fmt.Fprintf(&b, "- %s\n", x)
		}
	}
	list("Newly found", gained)
	list("Regressions (found before, missed now)", lost)
	list("Newly proven (was only claimed before)", proven)
	if len(gained)+len(lost)+len(proven) == 0 {
		b.WriteString("\nNo planted vulnerability changed status.\n")
	}
	return b.String()
}
