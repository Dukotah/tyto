// Package ssti performs inline Server-Side Template Injection detection on an
// authorized URL's query parameters. It injects template expressions that
// evaluate a unique arithmetic product (1337*1337 = 1787569) across the major
// template engines; a response that contains the RESULT (not the literal
// expression) proves the expression was evaluated server-side. A control
// request sending the literal `1337*1337` guards against false positives from
// servers that merely echo arithmetic text. Detection, not exploitation — so
// this is RiskMedium and the guard gates it.
package ssti

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool. cookie holds the session cookie for the current Execute (set from
// a.Cookie); the engine invokes Execute sequentially per run, so this is safe.
type Tool struct {
	http   *http.Client
	cookie string
}

func New() *Tool {
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "ssti" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

const maxBody = 256 << 10

// The unique factor pair and their product. 1337*1337 is distinctive enough
// that an incidental occurrence of the result in a normal response is highly
// unlikely, which keeps false positives down.
const (
	sstiExpr   = "1337*1337" // the literal arithmetic, also used as the control
	sstiResult = "1787569"   // 1337 * 1337
)

// payload pairs each engine-specific template wrapper with the human-readable
// engine(s) whose syntax it exercises. The {{...}} form is tried first because
// it covers the most common engines (Jinja2/Twig).
var sstiPayloads = []struct {
	template string // wraps sstiExpr in an engine's expression delimiters
	engine   string
}{
	{"{{" + sstiExpr + "}}", "Jinja2/Twig"},
	{"${" + sstiExpr + "}", "FreeMarker/JSP-EL/Thymeleaf"},
	{"#{" + sstiExpr + "}", "Ruby/JSF"},
	{"<%= " + sstiExpr + " %>", "ERB"},
	{"{" + sstiExpr + "}", "generic single-brace"},
	{"*{" + sstiExpr + "}", "Thymeleaf selection"},
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	t.cookie = a.Cookie // replay any established session on every injected request
	base, err := url.Parse(normalizeURL(a.Target))
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}
	q := base.Query()
	if len(q) == 0 {
		res.Findings = append(res.Findings, state.Finding{
			ID: "SSTI-" + a.ID, Title: "No parameters to test for SSTI", Severity: state.SeverityInfo,
			Target: base.String(), Description: "the target URL has no query parameters; supply a parameterized endpoint (e.g. from webcrawl)",
			Tool: t.Name(), Validated: true,
		})
		res.Success = true
		res.Output = base.String() + ": no parameters"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	names := make([]string, 0, len(q))
	for n := range q {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic order

	var hits int
	add := func(sev state.Severity, title, detail, evidence, target, cvss string) {
		hits++
		res.Findings = append(res.Findings, state.Finding{
			ID: fmt.Sprintf("SSTI-%s-%d", a.ID, hits), Title: title, Severity: sev,
			Target: target, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true, CVSS: cvss,
		})
	}

	for _, name := range names {
		if ctx.Err() != nil {
			res.Err = ctx.Err().Error()
			res.FinishedAt = time.Now().UTC()
			return res, ctx.Err()
		}

		// Control: send the LITERAL arithmetic. If the response already contains
		// the result, the server is just echoing math text (or otherwise computes
		// it without template injection) — any later "hit" on this param would be a
		// false positive, so skip it. A connection error on the control aborts the
		// whole run via res.Err.
		ctrlBody, _, err := t.inject(ctx, base, name, sstiExpr)
		if err != nil {
			res.Err = err.Error()
			res.Output = "request error: " + err.Error()
			res.FinishedAt = time.Now().UTC()
			return res, nil
		}
		if strings.Contains(ctrlBody, sstiResult) {
			// The literal already yields the result; cannot distinguish injection.
			continue
		}

		for _, p := range sstiPayloads {
			if ctx.Err() != nil {
				res.Err = ctx.Err().Error()
				res.FinishedAt = time.Now().UTC()
				return res, ctx.Err()
			}
			body, u, err := t.inject(ctx, base, name, p.template)
			if err != nil {
				res.Err = err.Error()
				res.Output = "request error: " + err.Error()
				res.FinishedAt = time.Now().UTC()
				return res, nil
			}
			// Confirmed SSTI: the payload's response contains the evaluated result
			// while the control (literal) response did not.
			if strings.Contains(body, sstiResult) {
				add(state.SeverityHigh, "Server-Side Template Injection in parameter "+name,
					"the template expression "+p.template+" was evaluated server-side "+
						"(response contains "+sstiResult+", the product of "+sstiExpr+"), while the "+
						"literal control did not — confirming template injection in the "+p.engine+" family",
					"payload "+p.template+" -> reflected result "+sstiResult, u,
					"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
				break // stop testing this param after the first confirmed hit
			}
		}
	}

	res.Success = true
	res.Output = fmt.Sprintf("%s: tested %d param(s), %d SSTI issue(s)", base.String(), len(names), hits)
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// inject sets one parameter to payload, fetches, and returns the body + the
// request URL used (for evidence).
func (t *Tool) inject(ctx context.Context, base *url.URL, name, payload string) (string, string, error) {
	u := *base
	q := u.Query()
	q.Set(name, payload)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", u.String(), err
	}
	req.Header.Set("User-Agent", "tyto-ssti")
	if t.cookie != "" {
		req.Header.Set("Cookie", t.cookie)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return "", u.String(), err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return string(body), u.String(), nil
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
