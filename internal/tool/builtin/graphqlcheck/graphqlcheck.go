// Package graphqlcheck discovers GraphQL endpoints and tests whether schema
// introspection is enabled — an exposed schema hands an attacker the full API
// map (types, queries, mutations), which is a real attack-surface leak and a
// frequent precursor to access-control bugs. Content-validated: we confirm the
// response actually returns a GraphQL schema, not just any 200.
package graphqlcheck

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

func (t *Tool) Name() string              { return "graphqlcheck" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const maxBody = 64 << 10

// candidatePaths are the common GraphQL mount points.
var candidatePaths = []string{"/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"}

// introQuery is a minimal introspection probe.
const introQuery = `{"query":"{__schema{queryType{name}}}"}`

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	base := strings.TrimRight(normalizeURL(a.Target), "/")

	for _, p := range candidatePaths {
		if ctx.Err() != nil {
			break
		}
		url := base + p
		body, ok := t.probe(ctx, url, a.Cookie)
		if !ok {
			continue
		}
		// The endpoint speaks GraphQL. Did introspection succeed?
		if strings.Contains(body, "__schema") || strings.Contains(body, "\"queryType\"") {
			res.Findings = append(res.Findings, state.Finding{
				ID:       "GQL-" + a.ID,
				Title:    "GraphQL introspection enabled at " + p,
				Severity: state.SeverityMedium,
				Target:   url,
				Description: "the GraphQL endpoint answers __schema introspection, exposing the full type/query/" +
					"mutation map; disable introspection in production and review per-field authorization",
				Evidence:  truncate(body, 200),
				CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
				Tool:      t.Name(),
				Validated: true,
				FoundAt:   time.Now().UTC(),
			})
			res.Assets = append(res.Assets, state.Asset{ID: url, Type: "endpoint", Value: url, Attrs: map[string]string{"kind": "graphql"}})
			res.Success = true
			res.Output = fmt.Sprintf("%s: GraphQL introspection ENABLED at %s", base, p)
			res.FinishedAt = time.Now().UTC()
			return res, nil
		}
		// Endpoint exists but introspection is off — still worth recording.
		res.Findings = append(res.Findings, state.Finding{
			ID: "GQL-" + a.ID, Title: "GraphQL endpoint at " + p + " (introspection disabled)", Severity: state.SeverityInfo,
			Target: url, Description: "a GraphQL endpoint is present; introspection appears disabled (good)", Tool: t.Name(), Validated: true, FoundAt: time.Now().UTC(),
		})
		res.Assets = append(res.Assets, state.Asset{ID: url, Type: "endpoint", Value: url, Attrs: map[string]string{"kind": "graphql"}})
		res.Success = true
		res.Output = fmt.Sprintf("%s: GraphQL at %s, introspection off", base, p)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	res.Findings = append(res.Findings, state.Finding{
		ID: "GQL-" + a.ID, Title: "No GraphQL endpoint found", Severity: state.SeverityInfo,
		Target: base, Description: "none of the common GraphQL paths responded with a GraphQL payload", Tool: t.Name(), Validated: true, FoundAt: time.Now().UTC(),
	})
	res.Success = true
	res.Output = base + ": no GraphQL endpoint"
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// probe POSTs the introspection query and reports the body + whether the response
// is actually GraphQL (a JSON object carrying "data" or "errors" — not arbitrary HTML).
func (t *Tool) probe(ctx context.Context, url, cookie string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(introQuery))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tyto-graphqlcheck")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	s := strings.TrimSpace(string(body))
	// GraphQL responses are JSON with "data" or "errors". Require that shape so a
	// catch-all HTML 200 isn't mistaken for a GraphQL endpoint.
	looksGraphQL := strings.HasPrefix(s, "{") && (strings.Contains(s, "\"data\"") || strings.Contains(s, "\"errors\""))
	return s, looksGraphQL
}

func truncate(s string, n int) string {
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
