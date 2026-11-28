// Package templatescan runs tyto's embedded Nuclei-style detection templates
// against an authorized HTTP target. It is the offline, single-binary answer to
// "detection breadth": a curated, operator-extensible template set evaluated by
// a pure-Go engine (internal/templates), no external Nuclei binary or template
// repo required.
package templatescan

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/templates"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (t *Tool) Name() string              { return "templatescan" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	base := normalizeURL(a.Target)

	tmpls, err := templates.LoadEmbedded()
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}

	// Augment the embedded pack with operator-supplied templates from disk. The
	// dir is resolved in precedence order; a missing/empty dir is a no-op. Disk
	// templates are deduped by ID with the embedded pack winning ties.
	var fromDisk, skipped int
	if dir := templatesDir(a); dir != "" {
		extra, sk, derr := templates.LoadDir(dir)
		skipped = sk
		if derr == nil {
			have := make(map[string]bool, len(tmpls))
			for _, t := range tmpls {
				have[t.ID] = true
			}
			for _, et := range extra {
				if et.ID == "" || have[et.ID] {
					continue
				}
				have[et.ID] = true
				tmpls = append(tmpls, et)
				fromDisk++
			}
		}
	}

	hits := templates.RunAll(ctx, t.http, base, tmpls)
	for _, h := range hits {
		res.Findings = append(res.Findings, state.Finding{
			ID:          "TPL-" + a.ID + "-" + h.TemplateID,
			Title:       h.Name,
			Severity:    parseSeverity(h.Severity),
			Target:      h.URL,
			Description: h.Description,
			Evidence:    "matched template " + h.TemplateID,
			Tool:        t.Name(),
			Validated:   true,
		})
	}

	res.Success = true
	res.Output = fmt.Sprintf(
		"%s: ran %d templates (%d from disk, %d skipped as unsupported); %d matched",
		base, len(tmpls), fromDisk, skipped, len(hits),
	)
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// templatesDir resolves the directory of extra templates to load, in precedence
// order: the action's "templates" param, then $TYTO_TEMPLATES, then the default
// ~/.tyto/templates (only if it exists). Returns "" when none apply.
func templatesDir(a action.Action) string {
	if d := strings.TrimSpace(a.Params["templates"]); d != "" {
		return d
	}
	if d := strings.TrimSpace(os.Getenv("TYTO_TEMPLATES")); d != "" {
		return d
	}
	// The large on-disk pack (e.g. the cloned nuclei-templates) is OPT-IN via the
	// param or TYTO_TEMPLATES — auto-loading thousands of templates would make every
	// run fire ~10k requests. Default to the fast embedded pack only.
	return ""
}

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

func normalizeURL(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	if strings.HasSuffix(target, ":443") || strings.HasSuffix(target, ":8443") {
		return "https://" + target
	}
	return "http://" + target
}

// WrapTransport implements tool.TransportWrapper: it lets the engine layer a
// RoundTripper (engagement traffic marker, evidence capture) under this tool's
// HTTP client without the tool knowing about it.
func (t *Tool) WrapTransport(wrap func(http.RoundTripper) http.RoundTripper) {
	t.http.Transport = wrap(t.http.Transport)
}
