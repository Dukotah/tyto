// Package webinject performs active injection testing on an authorized URL's
// query parameters: reflected XSS (unencoded marker reflection) and error-based
// SQL injection (database error signatures). Payloads are deliberately benign
// (alert(1), a single quote) — detection, not exploitation. This is the core of
// web-app testing and is intentionally RiskMedium so the guard gates it.
package webinject

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

func (t *Tool) Name() string              { return "webinject" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

const maxBody = 256 << 10

// sqlErrRe matches common database error signatures that indicate error-based
// SQL injection when they appear only after injecting a quote.
var sqlErrRe = regexp.MustCompile(`(?i)(SQL syntax|mysql_fetch|valid MySQL result|mysqli?_|ORA-\d{5}|PostgreSQL.{0,40}ERROR|SQLite3?::|sqlite_error|Unclosed quotation mark|quoted string not properly terminated|Microsoft OLE DB|ODBC SQL Server|System\.Data\.SQLite)`)

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	base, err := url.Parse(normalizeURL(a.Target))
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}
	q := base.Query()
	if len(q) == 0 {
		res.Findings = append(res.Findings, state.Finding{
			ID: "INJ-" + a.ID, Title: "No query parameters to test", Severity: state.SeverityInfo,
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
	add := func(sev state.Severity, title, detail, evidence, target string) {
		hits++
		res.Findings = append(res.Findings, state.Finding{
			ID: fmt.Sprintf("INJ-%s-%d", a.ID, hits), Title: title, Severity: sev,
			Target: target, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true,
		})
	}

	for _, name := range names {
		if ctx.Err() != nil {
			res.Err = ctx.Err().Error()
			res.FinishedAt = time.Now().UTC()
			return res, ctx.Err()
		}

		// Reflected XSS: inject a distinctive unencoded marker; vulnerable iff it
		// comes back verbatim (not HTML-encoded).
		xss := "tytoxss" + name + `"><svg/onload=alert(1)>`
		if body, u, err := t.inject(ctx, base, name, xss); err == nil && strings.Contains(body, xss) {
			add(state.SeverityHigh, "Reflected XSS in parameter "+name,
				"the parameter's value is reflected into the response unencoded; a script payload executes",
				"payload reflected verbatim: "+xss, u)
		}

		// Error-based SQLi: a quote that surfaces a DB error indicates injection.
		base2 := q.Get(name) + "'"
		if body, u, err := t.inject(ctx, base, name, base2); err == nil {
			if m := sqlErrRe.FindString(body); m != "" {
				add(state.SeverityHigh, "SQL injection (error-based) in parameter "+name,
					"injecting a single quote surfaced a database error, indicating unsanitized SQL",
					"db error signature: "+m, u)
			}
		}
	}

	res.Success = true
	res.Output = fmt.Sprintf("%s: tested %d param(s), %d issue(s)", base.String(), len(names), hits)
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
	req.Header.Set("User-Agent", "tyto-webinject")
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
