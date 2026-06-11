// Package cookieaudit inspects the Set-Cookie headers a web app issues and flags
// session-cookie hardening gaps (missing Secure / HttpOnly / SameSite). These are
// low-noise, directly observed findings — we only report on cookies the server
// actually set, so there is no false-positive guesswork.
package cookieaudit

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (t *Tool) Name() string              { return "cookieaudit" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

// sessionish flags cookie names that look session-bearing, so a missing flag on
// them is rated MEDIUM rather than LOW.
func sessionish(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"sess", "sid", "token", "auth", "jwt", "login", "csrf"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	url := normalizeURL(a.Target)
	isHTTPS := strings.HasPrefix(url, "https://")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}
	req.Header.Set("User-Agent", "tyto-cookieaudit")
	if a.Cookie != "" {
		req.Header.Set("Cookie", a.Cookie)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", url, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		res.Findings = append(res.Findings, state.Finding{
			ID: "COOKIE-" + a.ID, Title: "No cookies set", Severity: state.SeverityInfo,
			Target: url, Description: "the response set no cookies to audit", Tool: t.Name(), Validated: true, FoundAt: time.Now().UTC(),
		})
		res.Success = true
		res.Output = url + ": no cookies"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	n := 0
	for _, c := range cookies {
		var gaps []string
		if isHTTPS && !c.Secure {
			gaps = append(gaps, "Secure")
		}
		if !c.HttpOnly {
			gaps = append(gaps, "HttpOnly")
		}
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == http.SameSiteDefaultMode {
			gaps = append(gaps, "SameSite")
		}
		if len(gaps) == 0 {
			continue
		}
		sev := state.SeverityLow
		if sessionish(c.Name) {
			sev = state.SeverityMedium
		}
		n++
		res.Findings = append(res.Findings, state.Finding{
			ID:          fmt.Sprintf("COOKIE-%s-%d", a.ID, n),
			Title:       fmt.Sprintf("Cookie %q missing flags: %s", c.Name, strings.Join(gaps, ", ")),
			Severity:    sev,
			Target:      url,
			Description: "the cookie lacks " + strings.Join(gaps, "/") + " — increasing theft (XSS), interception, or CSRF risk",
			Evidence:    "Set-Cookie: " + c.Name + "=… (flags present: " + flagsOf(c) + ")",
			Tool:        t.Name(),
			Validated:   true,
			FoundAt:     time.Now().UTC(),
		})
	}
	if n == 0 {
		res.Findings = append(res.Findings, state.Finding{
			ID: "COOKIE-" + a.ID, Title: "Cookies are properly flagged", Severity: state.SeverityInfo,
			Target: url, Description: fmt.Sprintf("all %d cookie(s) carry appropriate Secure/HttpOnly/SameSite flags", len(cookies)), Tool: t.Name(), Validated: true, FoundAt: time.Now().UTC(),
		})
	}
	res.Success = true
	res.Output = fmt.Sprintf("%s: %d of %d cookie(s) under-flagged", url, n, len(cookies))
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

func flagsOf(c *http.Cookie) string {
	var f []string
	if c.Secure {
		f = append(f, "Secure")
	}
	if c.HttpOnly {
		f = append(f, "HttpOnly")
	}
	switch c.SameSite {
	case http.SameSiteLaxMode:
		f = append(f, "SameSite=Lax")
	case http.SameSiteStrictMode:
		f = append(f, "SameSite=Strict")
	}
	if len(f) == 0 {
		return "none"
	}
	return strings.Join(f, ",")
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
