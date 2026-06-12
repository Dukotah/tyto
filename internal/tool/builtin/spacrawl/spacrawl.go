// Package spacrawl is a headless-browser crawler for JavaScript single-page apps
// (React/Vue/Angular/Next). The static crawlers (webcrawl/jsmine) only ever see
// the server's initial HTML; in a SPA that's an almost-empty shell whose real
// attack surface — the links, forms, and XHR/fetch endpoints — only exists AFTER
// the framework has rendered the DOM in a browser. spacrawl drives a real
// headless Chrome via chromedp, lets the page settle, then extracts the
// POST-render attack surface and emits it as `endpoint` assets in exactly the
// shape jsmine/webcrawl use — so SPA-only routes flow straight into the
// injection loop that webinject/ssti/sqliexploit consume.
//
// It is a passive, navigate-only discovery tool (CategoryRecon / RiskLow); the
// Scope Guard has already authorized anything that reaches Execute. Extracted
// values are untrusted and only land in Finding/Asset fields the quarantine
// boundary keeps out of the planner prompt.
//
// GRACEFUL DEGRADE: if no Chrome/Chromium binary can be launched (none installed
// in the environment), spacrawl returns a single honest info finding instead of
// crashing — so it is safe to register everywhere, even where Chrome is absent.
// The DOM-extraction logic is a PURE function over a rendered-HTML string
// (extractSurface), so the whole parsing/asset-emission path is unit-testable
// without ever launching a browser.
package spacrawl

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool implements a headless-browser SPA crawler. renderer is the browser
// abstraction; in production it is the chromedp-backed chromeRenderer, but a test
// can substitute a fake so the extraction/asset path is exercised without Chrome.
type Tool struct {
	render renderer
}

// New returns a spacrawl Tool bound to the real chromedp renderer. Constructing
// it launches NO browser — Chrome is only started inside Execute, on demand — so
// registering/listing the tool is free even where Chrome isn't installed.
func New() *Tool { return &Tool{render: chromeRenderer{}} }

func (t *Tool) Name() string              { return "spacrawl" }
func (t *Tool) Category() action.Category { return action.CategoryRecon }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const (
	defaultMaxPages = 10               // cap pages we navigate+render per run
	defaultMaxDepth = 2                // cap link-follow depth from the start URL
	maxEndpoints    = 50               // cap emitted endpoint assets
	settleDefault   = 1500 * time.Millisecond // post-load wait for JS to render
	settleMax       = 10 * time.Second
	pageTimeout     = 20 * time.Second // per-page navigate+render budget
	runTimeout      = 90 * time.Second // whole-run ceiling
)

// renderer abstracts "navigate to a URL in a browser and hand back the rendered
// DOM HTML". The production implementation drives chromedp; tests fake it. It
// returns the outer HTML of the document AFTER the SPA has rendered + settled.
type renderer interface {
	// render navigates to u, waits for the body and the settle delay, and returns
	// the rendered document HTML. A non-nil error means the browser could not be
	// started or the navigation failed.
	render(ctx context.Context, u string, settle time.Duration, cookie string) (string, error)
}

// surface is the structured attack surface extracted from one rendered page.
type surface struct {
	links     []string // raw href/route strings discovered in the DOM
	endpoints []string // absolute, same-host URLs that carry query params (testable)
	forms     []formInfo
}

type formInfo struct {
	action string
	method string
	inputs []string
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	start, err := url.Parse(normalizeURL(a.Target))
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}

	maxPages := intParam(a.Params["max_pages"], defaultMaxPages)
	maxDepth := intParam(a.Params["max_depth"], defaultMaxDepth)
	settle := settleDefault
	if d, perr := time.ParseDuration(strings.TrimSpace(a.Params["settle"])); perr == nil && d > 0 {
		if d > settleMax {
			d = settleMax
		}
		settle = d
	}

	// Bound the whole run so a misbehaving SPA can't hang the engagement.
	runCtx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	type queued struct {
		u     string
		depth int
	}
	visited := map[string]bool{}
	endpoints := map[string]bool{} // dedup testable endpoint URLs (carry params)
	queue := []queued{{u: start.String(), depth: 0}}
	rendered := 0       // pages the browser actually rendered
	browserDown := false // set if Chrome could not be launched at all

	for len(queue) > 0 && len(visited) < maxPages {
		if runCtx.Err() != nil {
			break
		}
		cur := queue[0]
		queue = queue[1:]
		if visited[cur.u] {
			continue
		}
		visited[cur.u] = true

		pageCtx, pcancel := context.WithTimeout(runCtx, pageTimeout)
		dom, rerr := t.render.render(pageCtx, cur.u, settle, a.Cookie)
		pcancel()
		if rerr != nil {
			// A first-page failure with zero successful renders means the browser
			// itself is unavailable — degrade gracefully rather than error out.
			if rendered == 0 && len(queue) == 0 {
				browserDown = true
			}
			continue
		}
		rendered++

		curURL, _ := url.Parse(cur.u)
		if curURL == nil {
			curURL = start
		}
		// The page itself may have navigated to a param-bearing URL.
		if curURL.RawQuery != "" {
			endpoints[cur.u] = true
		}

		s := extractSurface(dom, curURL, start)
		for _, ep := range s.endpoints {
			endpoints[ep] = true
		}
		// Follow same-host links to the next depth, capped.
		if cur.depth < maxDepth {
			for _, href := range s.links {
				ref, perr := curURL.Parse(href)
				if perr != nil || !sameHost(ref, start) {
					continue
				}
				ref.Fragment = ""
				nu := ref.String()
				if ref.RawQuery != "" {
					endpoints[nu] = true
				}
				if !visited[nu] && len(visited)+len(queue) < maxPages {
					queue = append(queue, queued{u: nu, depth: cur.depth + 1})
				}
			}
		}
	}

	if browserDown {
		res.Findings = append(res.Findings, state.Finding{
			ID:          "SPACRAWL-NOCHROME-" + a.ID,
			Title:       "headless browser unavailable: SPA crawl skipped",
			Severity:    state.SeverityInfo,
			Target:      start.String(),
			Description: "spacrawl requires a Chrome/Chromium binary to render JavaScript single-page apps; none could be launched in this environment, so the post-render attack surface was not collected (install: apt install chromium)",
			Tool:        t.Name(),
			Validated:   false,
		})
		res.Success = true
		res.Output = fmt.Sprintf("%s: headless browser unavailable (graceful degrade)", start.String())
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Emit endpoint assets (sorted for determinism) for downstream injection.
	eps := sortedKeys(endpoints)
	if len(eps) > maxEndpoints {
		eps = eps[:maxEndpoints]
	}
	for _, ep := range eps {
		u, _ := url.Parse(ep)
		params := ""
		if u != nil {
			params = strings.Join(paramNames(u), ",")
		}
		res.Assets = append(res.Assets, state.Asset{
			ID: ep, Type: "endpoint", Value: ep, Attrs: map[string]string{"params": params},
		})
	}

	if rendered == 0 {
		res.Success = false
		res.Output = fmt.Sprintf("%s: no page rendered (target unreachable)", start.String())
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	res.Findings = append(res.Findings, state.Finding{
		ID:        "SPACRAWL-" + a.ID,
		Title:     fmt.Sprintf("SPA crawl: rendered %d page(s), found %d post-render endpoint(s)", rendered, len(eps)),
		Severity:  state.SeverityInfo,
		Target:    start.String(),
		Tool:      t.Name(),
		Validated: true,
	})
	res.Success = true
	res.Output = fmt.Sprintf("%s: %d pages rendered, %d endpoints", start.String(), rendered, len(eps))
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// xhrRefRe pulls root-relative and absolute URL literals out of inline <script>
// bodies — fetch("/api/x?y=1"), axios.get('https://host/api'), so XHR/fetch
// endpoints discoverable in inline JS join the surface alongside DOM links.
var xhrRefRe = regexp.MustCompile(`["'` + "`" + `](https?://[^"'` + "`" + `\s]{1,200}|/[a-zA-Z0-9_\-/.]{1,160}(?:\?[a-zA-Z0-9_\-/.=&%]{0,200})?)["'` + "`" + `]`)

// staticExtRe flags non-testable static assets we drop from the endpoint set.
var staticExtRe = regexp.MustCompile(`(?i)\.(js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|mp4|webm)(\?|$)`)

// extractSurface is the PURE core of spacrawl: given the rendered DOM HTML, the
// URL the DOM was rendered at (curURL, for resolving relative refs), and the
// engagement start URL (for same-host scoping), it returns the discovered links,
// same-host parameterized endpoints, and forms. It launches NO browser and has no
// I/O, so the entire extraction + asset-shaping path is unit-testable on a static
// HTML string. Endpoints are absolute, same-host, query-bearing URLs plus GET
// forms turned into testable endpoints — the exact shape webinject consumes.
func extractSurface(dom string, curURL, start *url.URL) surface {
	var s surface
	links, forms := parseDOM(dom)
	s.forms = forms

	addEndpoint := func(ref *url.URL) {
		if ref == nil || !sameHost(ref, start) {
			return
		}
		if ref.RawQuery == "" || staticExtRe.MatchString(ref.Path) {
			return
		}
		ref.Fragment = ""
		s.endpoints = append(s.endpoints, ref.String())
	}

	for _, href := range links {
		s.links = append(s.links, href)
		if ref, err := curURL.Parse(href); err == nil {
			addEndpoint(ref)
		}
	}

	// GET forms become testable endpoints (inputs → placeholder query params).
	for _, f := range forms {
		if ep := formEndpoint(curURL, f); ep != "" {
			if ref, err := url.Parse(ep); err == nil {
				addEndpoint(ref)
			}
		}
	}

	// XHR/fetch endpoints baked into inline <script> bodies (and the whole DOM, to
	// catch data-* attributes and inline handlers).
	for _, m := range xhrRefRe.FindAllStringSubmatch(dom, -1) {
		g := m[1]
		if strings.HasPrefix(g, "//") || strings.Contains(g, "${") {
			continue
		}
		ref, err := curURL.Parse(g)
		if err != nil {
			continue
		}
		s.links = append(s.links, g)
		addEndpoint(ref)
	}

	// Dedup + sort for deterministic output.
	s.links = dedupSorted(s.links)
	s.endpoints = dedupSorted(s.endpoints)
	return s
}

// parseDOM tokenizes rendered HTML into anchor hrefs and form descriptors. It
// mirrors webcrawl's parser so SPA-rendered markup is read the same way.
func parseDOM(dom string) (links []string, forms []formInfo) {
	z := html.NewTokenizer(strings.NewReader(dom))
	var cur *formInfo
	for {
		switch z.Next() {
		case html.ErrorToken:
			if cur != nil {
				forms = append(forms, *cur)
			}
			return links, forms
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			switch tok.Data {
			case "a":
				if href := attr(tok, "href"); href != "" {
					links = append(links, href)
				}
			case "form":
				if cur != nil {
					forms = append(forms, *cur)
				}
				cur = &formInfo{action: attr(tok, "action"), method: strings.ToLower(attr(tok, "method"))}
			case "input", "textarea", "select":
				if cur != nil {
					if n := attr(tok, "name"); n != "" {
						cur.inputs = append(cur.inputs, n)
					}
				}
			}
		case html.EndTagToken:
			if tok := z.Token(); tok.Data == "form" && cur != nil {
				forms = append(forms, *cur)
				cur = nil
			}
		}
	}
}

func attr(t html.Token, key string) string {
	for _, a := range t.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// formEndpoint builds a testable GET endpoint from a form (GET forms only; POST
// fuzzing is a later increment). Inputs become query params with a placeholder.
func formEndpoint(base *url.URL, f formInfo) string {
	if f.method != "" && f.method != "get" {
		return ""
	}
	if len(f.inputs) == 0 {
		return ""
	}
	act := f.action
	if act == "" {
		act = base.String()
	}
	u, err := base.Parse(act)
	if err != nil {
		return ""
	}
	q := u.Query()
	for _, in := range f.inputs {
		q.Set(in, "test")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func sameHost(a, b *url.URL) bool {
	return a != nil && b != nil && strings.EqualFold(a.Hostname(), b.Hostname())
}

func paramNames(u *url.URL) []string {
	var out []string
	for n := range u.Query() {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func dedupSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func intParam(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
		if n > 1000 { // sane upper bound; ignore absurd caps
			return def
		}
	}
	if n <= 0 {
		return def
	}
	return n
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
