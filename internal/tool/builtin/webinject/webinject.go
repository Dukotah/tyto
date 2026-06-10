// Package webinject performs active injection testing on an authorized URL's
// query parameters: reflected XSS (unencoded marker reflection), error-based
// and boolean-based SQL injection, path traversal / LFI, and OS command
// injection. Payloads are deliberately benign (alert(1), a single quote,
// /etc/passwd, the unix `id` command) — detection, not exploitation. This is
// the core of web-app testing and is intentionally RiskMedium so the guard
// gates it.
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

// Tool. cookie holds the session cookie for the current Execute (set from
// a.Cookie); the engine invokes Execute sequentially per run, so this is safe.
type Tool struct {
	http   *http.Client
	cookie string
}

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

// passwdRe matches the canonical first line of a unix /etc/passwd file (the
// root entry). Its appearance after a traversal payload indicates the parameter
// is used to read an arbitrary local file.
var passwdRe = regexp.MustCompile(`root:.*:0:0:`)

// idOutputRe matches the output of the unix `id` command (e.g. "uid=0(root)").
// Its appearance after an injected `id` indicates OS command injection.
var idOutputRe = regexp.MustCompile(`uid=\d+\(`)

// boolLenThreshold is the minimum byte difference between the TRUE and FALSE
// boolean-SQLi responses that we treat as a meaningful behavioral change.
const boolLenThreshold = 16

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
	add := func(sev state.Severity, title, detail, evidence, target, cvss string) {
		hits++
		res.Findings = append(res.Findings, state.Finding{
			ID: fmt.Sprintf("INJ-%s-%d", a.ID, hits), Title: title, Severity: sev,
			Target: target, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true, CVSS: cvss,
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
				"payload reflected verbatim: "+xss, u, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
		}

		// Error-based SQLi: a quote that surfaces a DB error indicates injection.
		errBased := false
		base2 := q.Get(name) + "'"
		if body, u, err := t.inject(ctx, base, name, base2); err == nil {
			if m := sqlErrRe.FindString(body); m != "" {
				errBased = true
				add(state.SeverityHigh, "SQL injection (error-based) in parameter "+name,
					"injecting a single quote surfaced a database error, indicating unsanitized SQL",
					"db error signature: "+m, u, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
			}
		}

		// Path traversal / LFI: try a plain and a URL-encoded traversal sequence
		// reaching /etc/passwd; vulnerable iff the root entry comes back.
		for _, trav := range []string{
			"../../../../../../etc/passwd",
			"..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
		} {
			if body, u, err := t.inject(ctx, base, name, trav); err == nil {
				if m := passwdRe.FindString(body); m != "" {
					add(state.SeverityHigh, "Path traversal in parameter "+name,
						"injecting a directory-traversal sequence returned the contents of /etc/passwd",
						"matched passwd entry: "+m, u, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
					break
				}
			}
		}

		// OS command injection: append shell metacharacters + `id` to the value;
		// vulnerable iff the command's output (uid=...) appears in the response.
		orig := q.Get(name)
		for _, cmd := range []string{orig + ";id", orig + "|id", orig + "`id`"} {
			if body, u, err := t.inject(ctx, base, name, cmd); err == nil {
				if m := idOutputRe.FindString(body); m != "" {
					add(state.SeverityCritical, "Command injection in parameter "+name,
						"appending a shell command to the value executed it; the response contains `id` output",
						"matched command output: "+m, u, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
					break
				}
			}
		}

		// Boolean-based SQLi: a TRUE and a FALSE condition that both succeed but
		// yield materially different response bodies suggest the value reaches a
		// SQL WHERE clause. Only reported when the error-based check did NOT
		// already flag this parameter, to avoid duplicate findings.
		if !errBased {
			bodyT, uT, errT := t.inject(ctx, base, name, orig+"' AND '1'='1")
			bodyF, _, errF := t.inject(ctx, base, name, orig+"' AND '1'='2")
			if errT == nil && errF == nil {
				diff := len(bodyT) - len(bodyF)
				if diff < 0 {
					diff = -diff
				}
				if diff > boolLenThreshold {
					add(state.SeverityMedium, "Possible boolean-based SQL injection in parameter "+name,
						"a TRUE vs FALSE SQL condition produced response bodies differing in length, "+
							"suggesting the value is interpolated into a SQL query",
						fmt.Sprintf("true-condition body %d bytes, false-condition body %d bytes (delta %d)",
							len(bodyT), len(bodyF), diff), uT, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N")
				}
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
