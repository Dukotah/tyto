// Package whatweb is a runtime-detected shell-out adapter that drives the real
// WhatWeb technology-fingerprinting scanner against an authorized HTTP/HTTPS
// target. WhatWeb identifies web servers, frameworks, CMSes, JS libraries, and
// other technologies from response signatures. tyto stays a single offline
// binary by default; this adapter is the OPT-IN bridge to WhatWeb when an
// operator has the whatweb binary installed.
//
// If whatweb is not on PATH it DEGRADES GRACEFULLY: a single info finding and
// Success=true, never an error. The live shell-out path is only taken when the
// operator has whatweb present, so it is exercised in the field, not in CI.
//
// It is CategoryRecon / RiskPassive (signature-based fingerprinting from normal
// HTTP requests), so the Scope Guard gates it against the engagement ceiling
// before Execute is reached.
package whatweb

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool implements an external WhatWeb fingerprinting adapter.
type Tool struct{}

// New returns a whatweb Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "whatweb" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryRecon }

// MaxRisk implements tool.Tool. WhatWeb only makes normal HTTP requests and
// matches response signatures, so RiskPassive.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskPassive }

// maxOutput caps captured combined output (~1 MiB) to bound memory.
const maxOutput = 1 << 20

// maxFindings caps how many technology findings we retain from one scan.
const maxFindings = 60

// evidenceMax truncates per-finding evidence to keep reports/state compact.
const evidenceMax = 120

// pluginListCap caps how many plugin names are joined into the asset attr.
const pluginListCap = 30

// Execute detects the whatweb binary and, when present, runs a JSON scan against
// the target and parses each plugin hit into a state.Finding plus an endpoint
// asset. With whatweb absent it degrades to a single info finding and
// Success=true.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	bin := adapter.Detect("whatweb")
	if bin == "" {
		res.Findings = append(res.Findings, adapter.Missing("whatweb", a.Target, "apt install whatweb"))
		res.Success = true
		res.Output = "whatweb not installed; skipped (graceful degrade)"
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

	// --log-json=-: emit a JSON array of target objects to stdout; --color=never:
	// no ANSI codes; -a 3: aggression level 3 (more plugins, still passive-ish).
	args := []string{"--log-json=-", "--color=never", "-a", "3", a.Target}

	// whatweb may exit non-zero yet still print useful JSON; parse regardless.
	out, runErr := adapter.Run(ctx, bin, args, maxOutput)

	findings, assets := parseWhatweb(out)
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%s-%d", a.ID, i)
		findings[i].Tool = t.Name()
		if findings[i].Target == "" {
			findings[i].Target = a.Target
		}
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = time.Now().UTC()
		}
	}
	res.Findings = append(res.Findings, findings...)
	res.Assets = append(res.Assets, assets...)

	summary := fmt.Sprintf("whatweb: %d technology fingerprint(s)", len(findings))
	if runErr != nil {
		summary += fmt.Sprintf(" — tool exit: %v", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// whatwebTarget mirrors the subset of a whatweb --log-json target object we
// consume. plugins is a map of plugin name -> detail; each detail may carry
// version/string/module string arrays (whatweb wraps scalars in arrays).
type whatwebTarget struct {
	Target     string                       `json:"target"`
	HTTPStatus int                          `json:"http_status"`
	Plugins    map[string]whatwebPluginInfo `json:"plugins"`
}

// whatwebPluginInfo is a single plugin's detail. Fields are string arrays;
// whatweb emits e.g. {"version":["1.18.0"],"string":["..."]}.
type whatwebPluginInfo struct {
	Version []string `json:"version"`
	String  []string `json:"string"`
	Module  []string `json:"module"`
}

// parseWhatweb parses whatweb --log-json output (a JSON array of target objects)
// into Info findings (one per detected plugin) plus one endpoint asset per
// target. It is deliberately tolerant — malformed input yields no findings — and
// pure (no IDs/timestamps stamped) so it is unit-testable on a captured sample
// without the whatweb binary present. Findings are capped at maxFindings.
func parseWhatweb(jsonOut string) ([]state.Finding, []state.Asset) {
	var findings []state.Finding
	var assets []state.Asset

	out := strings.TrimSpace(jsonOut)
	if out == "" {
		return findings, assets
	}

	var targets []whatwebTarget
	if err := json.Unmarshal([]byte(out), &targets); err != nil {
		return findings, assets
	}

	for _, tgt := range targets {
		if len(tgt.Plugins) == 0 {
			continue
		}

		// Sort plugin names for deterministic output (maps iterate randomly).
		names := make([]string, 0, len(tgt.Plugins))
		for name := range tgt.Plugins {
			names = append(names, name)
		}
		sort.Strings(names)

		var server string
		pluginList := make([]string, 0, len(names))

		for _, name := range names {
			info := tgt.Plugins[name]
			pluginList = append(pluginList, name)

			version := strings.Join(nonEmpty(info.Version), ", ")
			// Capture the server banner for the asset attrs if present.
			if strings.EqualFold(name, "HTTPServer") || strings.EqualFold(name, "Server") {
				if s := firstNonEmpty(info.String); s != "" {
					server = s
				} else if version != "" {
					server = name + " " + version
				}
			}

			if len(findings) >= maxFindings {
				continue
			}

			title := "Technology: " + name
			if version != "" {
				title += " " + version
			}

			// Evidence is the joined version + string values, truncated.
			evParts := append(nonEmpty(info.Version), nonEmpty(info.String)...)
			evidence := strings.Join(evParts, " | ")
			if len(evidence) > evidenceMax {
				evidence = evidence[:evidenceMax]
			}

			desc := "WhatWeb detected " + name + " on " + tgt.Target
			if version != "" {
				desc += " (version " + version + ")"
			}

			findings = append(findings, state.Finding{
				Title:       title,
				Severity:    state.SeverityInfo,
				Target:      tgt.Target,
				Description: desc,
				Evidence:    evidence,
				Validated:   true, // whatweb confirms by signature match, not inference
			})
		}

		// One endpoint asset per target carrying notable tech in attrs.
		attrs := map[string]string{}
		if server != "" {
			attrs["server"] = server
		}
		if tgt.HTTPStatus != 0 {
			attrs["http_status"] = fmt.Sprintf("%d", tgt.HTTPStatus)
		}
		if len(pluginList) > pluginListCap {
			pluginList = pluginList[:pluginListCap]
		}
		if len(pluginList) > 0 {
			attrs["plugins"] = strings.Join(pluginList, ",")
		}
		assets = append(assets, state.Asset{
			ID:    "endpoint:" + tgt.Target,
			Type:  "endpoint",
			Value: tgt.Target,
			Attrs: attrs,
		})
	}

	return findings, assets
}

// nonEmpty returns the slice with empty/whitespace-only entries dropped and the
// rest trimmed.
func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// firstNonEmpty returns the first non-empty trimmed entry, or "".
func firstNonEmpty(in []string) string {
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}
