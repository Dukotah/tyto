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
	res.Output = fmt.Sprintf("%s: %d template(s) matched of %d", base, len(hits), len(tmpls))
	res.FinishedAt = time.Now().UTC()
	return res, nil
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
