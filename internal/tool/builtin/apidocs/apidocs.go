// Package apidocs discovers exposed API documentation (Swagger/OpenAPI, API
// blueprints). Public API docs aren't a vuln by themselves, but they hand an
// attacker the full endpoint + parameter map — a major attack-surface expansion
// and a frequent first step toward auth/IDOR bugs. Content-validated so a
// catch-all 200 isn't mistaken for a spec.
package apidocs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "apidocs" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const maxBody = 64 << 10

// candidates are common API-doc mount points and the marker that confirms each.
var candidates = []string{
	"/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
	"/api-docs", "/swagger/v1/swagger.json", "/openapi.yaml",
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	base := strings.TrimRight(normalizeURL(a.Target), "/")

	for _, p := range candidates {
		if ctx.Err() != nil {
			break
		}
		url := base + p
		body, ok := t.fetch(ctx, url, a.Cookie)
		if !ok || !isSpec(body) {
			continue
		}
		res.Findings = append(res.Findings, state.Finding{
			ID:       "APIDOCS-" + a.ID,
			Title:    "Exposed API documentation at " + p,
			Severity: state.SeverityLow,
			Target:   url,
			Description: "a machine-readable API specification (Swagger/OpenAPI) is publicly served, exposing the full " +
				"endpoint and parameter map; restrict it to authenticated/internal access and use it to drive deeper testing",
			Evidence:  truncate(body, 160),
			Tool:      t.Name(),
			Validated: true,
			FoundAt:   time.Now().UTC(),
		})
		res.Assets = append(res.Assets, state.Asset{ID: url, Type: "endpoint", Value: url, Attrs: map[string]string{"kind": "api-spec"}})
		res.Success = true
		res.Output = fmt.Sprintf("%s: API docs exposed at %s", base, p)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	res.Findings = append(res.Findings, state.Finding{
		ID: "APIDOCS-" + a.ID, Title: "No exposed API documentation", Severity: state.SeverityInfo,
		Target: base, Description: "no Swagger/OpenAPI spec found at the common paths", Tool: t.Name(), Validated: true, FoundAt: time.Now().UTC(),
	})
	res.Success = true
	res.Output = base + ": no API docs found"
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// isSpec confirms the body is actually an API spec (not catch-all HTML).
func isSpec(body string) bool {
	s := strings.ToLower(body)
	return strings.Contains(s, "\"swagger\"") || strings.Contains(s, "\"openapi\"") ||
		(strings.Contains(s, "swagger:") || strings.Contains(s, "openapi:")) && !strings.Contains(s, "<html")
}

func (t *Tool) fetch(ctx context.Context, url, cookie string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "tyto-apidocs")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return string(body), true
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
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
