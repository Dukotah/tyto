// Package webcrawl discovers an HTTP service's attack surface: it follows
// same-host links and parses forms to a bounded depth, emitting "endpoint"
// assets for URLs that carry query parameters (and GET forms). Those endpoints
// are what webinject tests for XSS/SQLi. Same-host only, page-capped, low risk.
package webcrawl

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "webcrawl" }
func (t *Tool) Category() action.Category { return action.CategoryRecon }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const (
	maxPages = 20
	maxBody  = 512 << 10
)

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	start, err := url.Parse(normalizeURL(a.Target))
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}

	visited := map[string]bool{}
	endpoints := map[string]bool{} // dedup endpoint URLs (carry query params)
	queue := []string{start.String()}
	fetched := 0 // pages that actually returned a response (not just attempted)

	for len(queue) > 0 && len(visited) < maxPages {
		if ctx.Err() != nil {
			res.Err = ctx.Err().Error()
			res.FinishedAt = time.Now().UTC()
			return res, ctx.Err()
		}
		cur := queue[0]
		queue = queue[1:]
		if visited[cur] {
			continue
		}
		visited[cur] = true

		links, forms, err := t.fetch(ctx, cur, a.Cookie)
		if err != nil {
			continue
		}
		fetched++
		curURL, _ := url.Parse(cur)
		// If the page itself carries query params, it's a testable endpoint.
		if curURL != nil && curURL.RawQuery != "" {
			endpoints[cur] = true
		}
		for _, href := range links {
			ref, err := curURL.Parse(href)
			if err != nil || !sameHost(ref, start) {
				continue
			}
			ref.Fragment = ""
			u := ref.String()
			if ref.RawQuery != "" {
				endpoints[u] = true
			}
			if !visited[u] && len(visited)+len(queue) < maxPages {
				queue = append(queue, u)
			}
		}
		for _, f := range forms {
			if ep := formEndpoint(curURL, f); ep != "" {
				endpoints[ep] = true
			}
		}
	}

	// Emit endpoint assets (sorted for determinism) for downstream injection.
	eps := keys(endpoints)
	sort.Strings(eps)
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

	// If not a single page actually responded, the target was unreachable — report
	// that honestly instead of claiming a successful crawl of "1 page" (which
	// counts the attempted start URL even when its fetch failed).
	if fetched == 0 {
		res.Success = false
		res.Output = fmt.Sprintf("%s: no HTTP response (target unreachable)", start.String())
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	res.Findings = append(res.Findings, state.Finding{
		ID: "CRAWL-" + a.ID, Title: fmt.Sprintf("Crawled %d page(s), found %d parameterized endpoint(s)", fetched, len(eps)),
		Severity: state.SeverityInfo, Target: start.String(), Tool: t.Name(), Validated: true,
	})
	res.Success = true
	res.Output = fmt.Sprintf("%s: %d pages, %d endpoints", start.String(), fetched, len(eps))
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// fetch GETs a page and extracts hrefs and GET-form descriptors.
func (t *Tool) fetch(ctx context.Context, u, cookie string) (links []string, forms []formInfo, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "tyto-webcrawl")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "html") {
		return nil, nil, nil
	}
	return parseHTML(io.LimitReader(resp.Body, maxBody))
}

type formInfo struct {
	action string
	method string
	inputs []string
}

func parseHTML(r io.Reader) (links []string, forms []formInfo, err error) {
	z := html.NewTokenizer(r)
	var cur *formInfo
	for {
		switch z.Next() {
		case html.ErrorToken:
			if cur != nil {
				forms = append(forms, *cur)
			}
			return links, forms, nil
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
			if t := z.Token(); t.Data == "form" && cur != nil {
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

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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
