// Package redircheck detects open-redirect vulnerabilities on an authorized
// URL's query parameters. It sets candidate parameters to an off-site canary
// and observes whether the server issues a 3xx whose Location points back at
// the canary host. Redirects are NOT followed (CheckRedirect returns
// http.ErrUseLastResponse) so we inspect the first hop directly. The probe is
// a single benign GET per parameter — detection, not exploitation — so the
// tool is RiskLow.
package redircheck

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{
		Timeout: 8 * time.Second,
		// Do not follow redirects: we want to inspect the first-hop Location.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (t *Tool) Name() string              { return "redircheck" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

// canary is the off-site URL we inject; an open redirect sends the client here.
const canary = "https://tyto-evil.example/"

// redirParams are the conventional parameter names that carry a redirect target.
var redirParams = map[string]bool{
	"url":          true,
	"next":         true,
	"redirect":     true,
	"redir":        true,
	"return":       true,
	"returnurl":    true,
	"return_url":   true,
	"dest":         true,
	"destination":  true,
	"continue":     true,
	"redirect_uri": true,
	"callback":     true,
	"target":       true,
	"goto":         true,
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	base, err := url.Parse(normalizeURL(a.Target))
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}
	q := base.Query()

	names := make([]string, 0, len(q))
	for n := range q {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic order

	if len(names) == 0 {
		res.Findings = append(res.Findings, state.Finding{
			ID: "REDIR-" + a.ID, Title: "No redirect parameters to test", Severity: state.SeverityInfo,
			Target: base.String(), Description: "the target URL has no query parameters; supply a parameterized endpoint (e.g. from webcrawl)",
			Tool: t.Name(), Validated: true,
		})
		res.Success = true
		res.Output = base.String() + ": no parameters"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Prefer the conventional redirect parameter names. If none of them are
	// present but other params exist, fall back to testing every parameter —
	// some apps use generic names for the redirect target.
	tested := make([]string, 0, len(names))
	for _, n := range names {
		if redirParams[strings.ToLower(n)] {
			tested = append(tested, n)
		}
	}
	if len(tested) == 0 {
		tested = names
	}

	var hits int
	add := func(sev state.Severity, title, detail, evidence, target string) {
		hits++
		res.Findings = append(res.Findings, state.Finding{
			ID: fmt.Sprintf("REDIR-%s-%d", a.ID, hits), Title: title, Severity: sev,
			Target: target, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true,
		})
	}

	for _, name := range tested {
		if ctx.Err() != nil {
			res.Err = ctx.Err().Error()
			res.FinishedAt = time.Now().UTC()
			return res, ctx.Err()
		}

		loc, u, err := t.probe(ctx, base, name)
		if err != nil {
			res.Err = err.Error()
			res.Output = u + ": " + err.Error()
			res.FinishedAt = time.Now().UTC()
			return res, nil
		}
		if loc != "" && (strings.HasPrefix(loc, "https://tyto-evil.example") || strings.HasPrefix(loc, "//tyto-evil.example")) {
			add(state.SeverityMedium, "Open redirect via parameter "+name,
				"the parameter's value is used as a redirect target without validation; an attacker can send victims off-site",
				"Location: "+loc, u)
		}
	}

	res.Success = true
	res.Output = fmt.Sprintf("%s: tested %d param(s), %d issue(s)", base.String(), len(tested), hits)
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// probe sets one parameter to the canary, fetches WITHOUT following redirects,
// and returns the Location header (empty if not a 3xx) plus the request URL.
func (t *Tool) probe(ctx context.Context, base *url.URL, name string) (string, string, error) {
	u := *base
	q := u.Query()
	q.Set(name, canary)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", u.String(), err
	}
	req.Header.Set("User-Agent", "tyto-redircheck")
	resp, err := t.http.Do(req)
	if err != nil {
		return "", u.String(), err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", u.String(), nil
	}
	return resp.Header.Get("Location"), u.String(), nil
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
