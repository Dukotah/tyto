// Package jsmine mines a web app's JavaScript for attack surface the HTML
// crawler can't see: API routes, parameter names, and exposed secrets baked into
// bundles. Modern SPAs (React/Next/Vue) ship their whole API map inside JS, so
// this is where the testable endpoints actually live. jsmine fetches the page +
// its same-host scripts, extracts paths/params/secrets, and emits `endpoint`
// assets (URL + Attrs["params"]) in exactly the shape webinject/ssti/sqliexploit
// consume — so mined params flow straight into the injection loop.
//
// It is a passive GET-only discovery tool (CategoryRecon / RiskLow); the Scope
// Guard has already authorized anything that reaches Execute. Mined values are
// untrusted and only land in Finding/Asset fields the quarantine boundary keeps
// out of the planner prompt.
package jsmine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "jsmine" }
func (t *Tool) Category() action.Category { return action.CategoryRecon }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const (
	maxScripts     = 12        // cap external JS files fetched per run
	maxBody        = 512 << 10 // per-document read cap
	maxEndpoints   = 50        // cap emitted endpoint assets
	maxParamsPerEP = 8         // cap synthesized params on one endpoint
	maxSecretFinds = 20        // cap secret findings (avoid flooding on a minified bundle)
)

// scriptSrcRe pulls <script src="..."> URLs out of the host page.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// inlineScriptRe captures inline <script> bodies.
var inlineScriptRe = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)

// rootRefRe matches root-relative reference literals, INCLUDING an optional query
// string ("/api/users", '/api/orders?id=1&status=open') — so a param-bearing
// fetch() URL is captured whole, not truncated at the '?'.
var rootRefRe = regexp.MustCompile(`["'` + "`" + `](/[a-zA-Z0-9_\-/.]{1,120}(?:\?[a-zA-Z0-9_\-/.=&%]{0,160})?)["'` + "`" + `]`)

// absURLRe matches absolute http(s) URLs in literals (same-host filtered later).
var absURLRe = regexp.MustCompile(`https?://[a-zA-Z0-9.\-:]+/[a-zA-Z0-9_\-/.?=&%]{1,160}`)

// paramRe captures query-parameter NAMES from any "?name=" / "&name=" in JS.
var paramRe = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_\-.]{0,40})=`)

// staticExtRe flags non-testable static assets we drop from the path set.
var staticExtRe = regexp.MustCompile(`(?i)\.(js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|json|txt|xml|mp4|webm)(\?|$)`)

// secretPats are HIGH-PRECISION secret signatures (anchored, low false-positive)
// so jsmine doesn't repeat the "report page chrome as a leak" failure mode. Each
// has a severity and a human label.
var secretPats = []struct {
	re    *regexp.Regexp
	label string
	sev   state.Severity
}{
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS access key id", state.SeverityHigh},
	{regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`), "GitHub personal access token", state.SeverityHigh},
	{regexp.MustCompile(`xox[baprs]-[0-9A-Za-z]{10,48}`), "Slack token", state.SeverityHigh},
	{regexp.MustCompile(`sk_live_[0-9A-Za-z]{16,}`), "Stripe live secret key", state.SeverityHigh},
	{regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), "Google API key", state.SeverityMedium},
	{regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}`), "JSON Web Token", state.SeverityMedium},
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	base, err := url.Parse(normalizeURL(a.Target))
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}

	page, err := t.get(ctx, base.String(), a.Cookie)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: could not fetch page (%v)", base.String(), err)
		res.FinishedAt = time.Now().UTC()
		return res, nil // a fetch failure is not a tool error
	}

	// Gather JS: inline blocks + same-host external scripts (bounded).
	var blobs []string
	for _, m := range inlineScriptRe.FindAllStringSubmatch(page, -1) {
		if s := strings.TrimSpace(m[1]); s != "" {
			blobs = append(blobs, s)
		}
	}
	scriptCount := 0
	for _, m := range scriptSrcRe.FindAllStringSubmatch(page, -1) {
		if scriptCount >= maxScripts {
			break
		}
		ref, perr := base.Parse(m[1])
		if perr != nil || !sameHost(ref, base) {
			continue
		}
		if body, gerr := t.get(ctx, ref.String(), a.Cookie); gerr == nil {
			blobs = append(blobs, body)
			scriptCount++
		}
	}
	// Always include the page body itself (inline handlers, data attributes).
	blobs = append(blobs, page)

	paths := map[string]bool{}
	params := map[string]bool{}
	paramURLs := map[string]bool{} // discovered URLs that already carry params
	for _, js := range blobs {
		collectPaths(js, base, paths, paramURLs)
		for _, pm := range paramRe.FindAllStringSubmatch(js, -1) {
			params[pm[1]] = true
		}
	}

	// Build the param-name list (sorted, capped) used to make bare paths testable.
	paramList := sortedKeys(params)
	if len(paramList) > maxParamsPerEP {
		paramList = paramList[:maxParamsPerEP]
	}

	// Assemble endpoint assets: real param-bearing URLs first, then bare API paths
	// made testable with the mined param names.
	emitted := map[string]bool{}
	add := func(ep string, names []string) {
		if len(res.Assets) >= maxEndpoints || ep == "" || emitted[ep] {
			return
		}
		emitted[ep] = true
		res.Assets = append(res.Assets, state.Asset{
			ID: ep, Type: "endpoint", Value: ep, Attrs: map[string]string{"params": strings.Join(names, ",")},
		})
	}
	for _, u := range sortedKeys(paramURLs) {
		pu, perr := url.Parse(u)
		if perr != nil {
			continue
		}
		add(u, queryNames(pu))
	}
	if len(paramList) > 0 {
		for _, p := range sortedKeys(paths) {
			ref, perr := base.Parse(p)
			if perr != nil {
				continue
			}
			q := ref.Query()
			for _, n := range paramList {
				q.Set(n, "test")
			}
			ref.RawQuery = q.Encode()
			add(ref.String(), paramList)
		}
	}

	// Secret scan over the gathered JS (high-precision, deduped, redacted).
	secrets := 0
	seenSecret := map[string]bool{}
	for _, js := range blobs {
		for _, p := range secretPats {
			for _, hit := range p.re.FindAllString(js, -1) {
				if secrets >= maxSecretFinds || seenSecret[hit] {
					continue
				}
				seenSecret[hit] = true
				secrets++
				res.Findings = append(res.Findings, state.Finding{
					ID:          fmt.Sprintf("JSMINE-SECRET-%s-%d", a.ID, secrets),
					Title:       "Exposed secret in JavaScript: " + p.label,
					Severity:    p.sev,
					Target:      base.String(),
					Description: "a " + p.label + " was found embedded in client-side JavaScript; verify it is live and rotate if so",
					Evidence:    redact(hit),
					Tool:        t.Name(),
					Validated:   false, // string match — needs human confirmation it is live
					FoundAt:     time.Now().UTC(),
				})
			}
		}
	}

	res.Findings = append(res.Findings, state.Finding{
		ID:       "JSMINE-" + a.ID,
		Title:    fmt.Sprintf("JS mining: %d endpoint(s), %d parameter(s), %d secret(s) across %d script(s)", len(res.Assets), len(params), secrets, scriptCount),
		Severity: state.SeverityInfo,
		Target:   base.String(),
		Tool:     t.Name(),
		Validated: true,
	})
	res.Success = true
	res.Output = fmt.Sprintf("%s: %d endpoints, %d params, %d secrets from %d script(s)", base.String(), len(res.Assets), len(params), secrets, scriptCount)
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// collectPaths extracts same-host references into either paths (bare, testable
// once params are attached) or paramURLs (already carry a query). Static assets
// are dropped from both. Root-relative and absolute references route the same way.
func collectPaths(js string, base *url.URL, paths, paramURLs map[string]bool) {
	route := func(ref *url.URL) {
		if ref == nil || !sameHost(ref, base) {
			return
		}
		if ref.RawQuery != "" {
			if !staticExtRe.MatchString(ref.Path) {
				paramURLs[ref.String()] = true
			}
			return
		}
		if ref.Path != "" && ref.Path != "/" && !staticExtRe.MatchString(ref.Path) {
			paths[ref.Path] = true
		}
	}
	for _, m := range rootRefRe.FindAllStringSubmatch(js, -1) {
		g := m[1]
		if strings.HasPrefix(g, "//") || strings.Contains(g, "${") {
			continue
		}
		if ref, err := base.Parse(g); err == nil {
			route(ref)
		}
	}
	for _, u := range absURLRe.FindAllString(js, -1) {
		if ref, err := url.Parse(u); err == nil {
			route(ref)
		}
	}
}

func (t *Tool) get(ctx context.Context, u, cookie string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "tyto-jsmine")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return string(body), nil
}

func sameHost(a, b *url.URL) bool {
	return a != nil && b != nil && strings.EqualFold(a.Hostname(), b.Hostname())
}

func queryNames(u *url.URL) []string { return sortedKeys(setOf(u.Query())) }

func setOf(q url.Values) map[string]bool {
	m := map[string]bool{}
	for k := range q {
		m[k] = true
	}
	return m
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// redact keeps a secret recognizable in a report without printing it in full.
func redact(s string) string {
	if len(s) <= 8 {
		return fmt.Sprintf("%s…(len %d)", s[:2], len(s))
	}
	return fmt.Sprintf("%s…(len %d)", s[:6], len(s))
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
