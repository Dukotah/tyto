// Package login authenticates to an authorized web application and ESTABLISHES A
// SESSION the engine can replay to later actions against the same host. It is an
// IDENTITY-tier tool: the operator supplies the credentials (recovered earlier,
// or known-valid test creds), so this is not a brute forcer — it performs a
// single authentication attempt and reports whether a session was established.
//
// Two modes are supported. In "form" mode it POSTs an
// application/x-www-form-urlencoded login form and treats a Set-Cookie (or a 3xx
// redirect away from the login page) as success; the captured cookie pairs are
// returned as the reusable session. In "basic" mode it issues a GET with HTTP
// Basic auth and treats status < 400 as success (no cookie session). On success
// the supplied credential is echoed back as a recovered Credential so the report
// and planner follow-ups can use it; the plaintext secret lives only in the
// quarantined Credential and never reaches the model.
package login

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{
		Timeout: 8 * time.Second,
		// Do not follow redirects: a 3xx away from the login page is itself a
		// success signal we want to observe directly.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (t *Tool) Name() string              { return "login" }
func (t *Tool) Category() action.Category { return action.CategoryIdentity }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	user := a.Params["username"]
	pass := a.Params["password"]

	// login_url defaults to the action's target.
	loginURL := a.Params["login_url"]
	if loginURL == "" {
		loginURL = a.Target
	}
	loginURL = normalizeURL(loginURL)

	userField := a.Params["user_field"]
	if userField == "" {
		userField = "username"
	}
	passField := a.Params["pass_field"]
	if passField == "" {
		passField = "password"
	}
	mode := a.Params["mode"]
	if mode == "" {
		mode = "form"
	}

	host := hostOf(loginURL)

	add := func(title, detail, evidence string) {
		res.Findings = append(res.Findings, state.Finding{
			ID: fmt.Sprintf("LOGIN-%s-%d", a.ID, len(res.Findings)), Title: title,
			Severity: state.SeverityInfo, Target: loginURL, Description: detail,
			Evidence: evidence, Tool: t.Name(), Validated: true,
		})
	}

	switch mode {
	case "basic":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
		if err != nil {
			res.Err = err.Error()
			res.FinishedAt = time.Now().UTC()
			return res, err
		}
		req.Header.Set("User-Agent", "tyto-login")
		req.SetBasicAuth(user, pass)

		resp, err := t.http.Do(req)
		if err != nil {
			res.Err = err.Error()
			res.Output = fmt.Sprintf("%s: no HTTP response (%v)", loginURL, err)
			res.FinishedAt = time.Now().UTC()
			return res, nil
		}
		code := resp.StatusCode
		resp.Body.Close()

		if code < 400 {
			// Basic-mode success: no cookie session — the engine re-supplies creds
			// per request, so Cookie is left empty.
			res.Session = &action.Session{Host: host, Cookie: ""}
			res.Credentials = append(res.Credentials, state.Credential{
				Kind: state.CredPassword, Username: user, Secret: pass,
				Source: "login", Target: host,
			})
			add("Authenticated session established for "+host,
				"HTTP Basic authentication succeeded; the supplied credentials are valid for this host",
				fmt.Sprintf("HTTP %d for Basic %s", code, user))
			res.Success = true
			res.Output = fmt.Sprintf("%s: basic auth succeeded (HTTP %d)", loginURL, code)
			res.FinishedAt = time.Now().UTC()
			return res, nil
		}

		add("Login failed (credentials rejected or no session)",
			"HTTP Basic authentication did not succeed (status >= 400)",
			fmt.Sprintf("HTTP %d for Basic %s", code, user))
		res.Success = true
		res.Output = fmt.Sprintf("%s: basic auth failed (HTTP %d)", loginURL, code)
		res.FinishedAt = time.Now().UTC()
		return res, nil

	default: // "form"
		form := url.Values{}
		form.Set(userField, user)
		form.Set(passField, pass)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(form.Encode()))
		if err != nil {
			res.Err = err.Error()
			res.FinishedAt = time.Now().UTC()
			return res, err
		}
		req.Header.Set("User-Agent", "tyto-login")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := t.http.Do(req)
		if err != nil {
			res.Err = err.Error()
			res.Output = fmt.Sprintf("%s: no HTTP response (%v)", loginURL, err)
			res.FinishedAt = time.Now().UTC()
			return res, nil
		}
		code := resp.StatusCode
		cookie := cookiePairs(resp.Cookies())
		// A redirect away from the login page is success only when it points
		// somewhere other than the login URL itself.
		redirected := code >= 300 && code < 400 && redirectsAway(resp.Header.Get("Location"), loginURL)
		resp.Body.Close()

		if cookie != "" || redirected {
			res.Session = &action.Session{Host: host, Cookie: cookie}
			res.Credentials = append(res.Credentials, state.Credential{
				Kind: state.CredPassword, Username: user, Secret: pass,
				Source: "login", Target: host,
			})
			ev := fmt.Sprintf("HTTP %d", code)
			if cookie != "" {
				ev += "; Set-Cookie present"
			}
			if redirected {
				ev += "; redirect to " + resp.Header.Get("Location")
			}
			add("Authenticated session established for "+host,
				"the login response set a session cookie or redirected away from the login page, indicating accepted credentials",
				ev)
			res.Success = true
			res.Output = fmt.Sprintf("%s: session established (HTTP %d)", loginURL, code)
			res.FinishedAt = time.Now().UTC()
			return res, nil
		}

		add("Login failed (credentials rejected or no session)",
			"the login response set no cookie and did not redirect away from the login page",
			fmt.Sprintf("HTTP %d, no Set-Cookie", code))
		res.Success = true
		res.Output = fmt.Sprintf("%s: login failed (HTTP %d)", loginURL, code)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
}

// cookiePairs renders the response cookies as a replayable Cookie header value
// ("k=v; k2=v2"), the form the engine injects into Action.Cookie.
func cookiePairs(cookies []*http.Cookie) string {
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// redirectsAway reports whether a Location header points somewhere other than the
// login URL (i.e. a post-login redirect rather than a re-display of the form).
func redirectsAway(location, loginURL string) bool {
	if location == "" {
		return false
	}
	// Same path as the login URL (relative or absolute) is not "away".
	lu, err := url.Parse(loginURL)
	if err == nil {
		if loc, err := url.Parse(location); err == nil {
			if loc.Path != "" && loc.Path == lu.Path {
				return false
			}
		}
	}
	return true
}

// hostOf returns the host (host:port) of a URL, falling back to the raw string.
func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// normalizeURL copies webcheck's scheme inference: bare targets default to http,
// with https for the common TLS ports.
func normalizeURL(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	if strings.HasSuffix(target, ":443") || strings.HasSuffix(target, ":8443") {
		return "https://" + target
	}
	return "http://" + target
}
