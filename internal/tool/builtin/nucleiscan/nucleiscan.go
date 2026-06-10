// Package nucleiscan is a runtime-detected shell-out adapter that drives the
// real ProjectDiscovery Nuclei engine (the ~10k community-template scanner)
// against an authorized HTTP/HTTPS target. tyto ships an embedded, pure-Go
// template engine (see internal/templates / the templatescan tool) so it stays
// a single offline binary by default; this adapter is the OPT-IN bridge to the
// full Nuclei template corpus when an operator has the nuclei binary installed.
//
// If nuclei is not on PATH it DEGRADES GRACEFULLY: a single info finding and
// Success=true, never an error. The live shell-out path is only taken when the
// operator has nuclei present, so it is exercised in the field, not in CI.
//
// It is CategoryScan / RiskMedium (active vulnerability scanning), so the Scope
// Guard gates it against the engagement ceiling before Execute is reached.
package nucleiscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool implements an external Nuclei vulnerability-scanning adapter.
type Tool struct{}

// New returns a nucleiscan Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "nucleiscan" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk implements tool.Tool. Nuclei sends active probes, so RiskMedium.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

// maxOutput caps captured combined output (~4 MiB). A full nuclei run against a
// broad target can emit many JSONL lines; this bounds memory while leaving room
// for a couple thousand findings before the cap clips the tail.
const maxOutput = 4 << 20

// maxFindings caps how many parsed findings we retain from one scan.
const maxFindings = 200

// descMax truncates a finding description to keep reports/state compact.
const descMax = 200

// Execute detects the nuclei binary and, when present, runs a JSONL scan against
// the target and parses each line into a state.Finding. With nuclei absent it
// degrades to a single info finding and Success=true.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	bin := adapter.Detect("nuclei")
	if bin == "" {
		res.Findings = append(res.Findings, adapter.Missing("nuclei", a.Target, "apt install nuclei"))
		res.Success = true
		res.Output = "nuclei not installed; skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Honor cancellation before launching the external process.
	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	// -jsonl: one JSON object per finding per line; -silent: no banner/progress
	// noise on stdout; -nc: no ANSI color codes (keeps JSON clean to parse).
	args := []string{"-u", a.Target, "-jsonl", "-silent", "-nc"}
	if v := strings.TrimSpace(a.Params["severity"]); v != "" {
		args = append(args, "-severity", v)
	}
	if v := strings.TrimSpace(a.Params["templates"]); v != "" {
		args = append(args, "-t", v)
	}
	if v := strings.TrimSpace(a.Params["tags"]); v != "" {
		args = append(args, "-tags", v)
	}

	// nuclei may exit non-zero yet still print useful JSONL; parse regardless.
	out, runErr := adapter.Run(ctx, bin, args, maxOutput)

	findings := parseNucleiJSONL(out)
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%s-%d", a.ID, i)
		findings[i].Tool = t.Name()
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = time.Now().UTC()
		}
	}
	res.Findings = append(res.Findings, findings...)

	summary := fmt.Sprintf("nuclei: %d finding(s)", len(findings))
	if runErr != nil {
		summary += fmt.Sprintf(" — tool exit: %v", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// nucleiResult mirrors the subset of nuclei's -jsonl object we consume. nuclei
// emits hyphenated keys (template-id, matched-at) so the json tags are explicit.
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Matched    string `json:"matched"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Description    string `json:"description"`
		Classification struct {
			CVSSMetrics string   `json:"cvss-metrics"`
			CVEID       cveField `json:"cve-id"`
		} `json:"classification"`
	} `json:"info"`
}

// cveField tolerates nuclei emitting cve-id as either a string or a string
// array depending on template/version. It decodes to the first id as a string.
type cveField string

func (c *cveField) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 || string(b) == "null" {
		*c = ""
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		if len(arr) > 0 {
			*c = cveField(arr[0])
		}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*c = cveField(s)
	return nil
}

// parseNucleiJSONL parses nuclei -jsonl output (one JSON object per line) into
// findings. It is deliberately tolerant — malformed lines are skipped — and
// pure (no IDs/timestamps stamped) so it is unit-testable on a captured sample
// without the nuclei binary present. Output is capped at maxFindings.
func parseNucleiJSONL(out string) []state.Finding {
	var findings []state.Finding
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r nucleiResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue // skip malformed line
		}
		if r.TemplateID == "" && r.Info.Name == "" {
			continue
		}

		target := r.MatchedAt
		if target == "" {
			target = r.Matched
		}

		title := r.Info.Name
		if title == "" {
			title = r.TemplateID
		} else if r.TemplateID != "" {
			title = r.Info.Name + " (" + r.TemplateID + ")"
		}

		desc := r.Info.Description
		if cve := strings.TrimSpace(string(r.Info.Classification.CVEID)); cve != "" {
			if desc != "" {
				desc = cve + ": " + desc
			} else {
				desc = cve
			}
		}
		if len(desc) > descMax {
			desc = desc[:descMax]
		}

		findings = append(findings, state.Finding{
			Title:       title,
			Severity:    parseSeverity(r.Info.Severity),
			Target:      target,
			Description: desc,
			Evidence:    line,
			CVSS:        strings.TrimSpace(r.Info.Classification.CVSSMetrics),
			Validated:   true, // nuclei confirms by matching, not by inference
		})
		if len(findings) >= maxFindings {
			break
		}
	}
	return findings
}

// parseSeverity maps nuclei's info.severity string to a state.Severity, with
// anything unrecognized (incl. "unknown") falling back to info.
func parseSeverity(s string) state.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return state.SeverityCritical
	case "high":
		return state.SeverityHigh
	case "medium":
		return state.SeverityMedium
	case "low":
		return state.SeverityLow
	default:
		return state.SeverityInfo
	}
}
