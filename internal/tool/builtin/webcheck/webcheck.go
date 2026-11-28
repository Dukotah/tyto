// Package webcheck runs a small set of SAFE, passive HTTP checks against an
// authorized service — missing security headers, server version disclosure, and
// directory-listing exposure. It is a deterministic, non-intrusive stand-in for
// embedded Nuclei (the v0.2 swap-in): every finding is directly observed from one
// GET, so all are marked Validated. The Scope Guard has already authorized the
// target; untrusted response data only reaches quarantined Finding fields.
package webcheck

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

func (t *Tool) Name() string              { return "webcheck" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const maxBody = 64 << 10

// securityHeader is one expected hardening header and the severity of its
// absence.
type securityHeader struct {
	name     string
	severity state.Severity
	why      string
}

var expectedHeaders = []securityHeader{
	{"Strict-Transport-Security", state.SeverityMedium, "no HSTS: connections can be downgraded to plaintext"},
	{"Content-Security-Policy", state.SeverityMedium, "no CSP: weaker XSS/content-injection mitigation"},
	{"X-Content-Type-Options", state.SeverityLow, "no X-Content-Type-Options: MIME sniffing possible"},
	{"X-Frame-Options", state.SeverityLow, "no X-Frame-Options (and no CSP frame-ancestors): clickjacking risk"},
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	url := normalizeURL(a.Target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}
	req.Header.Set("User-Agent", "tyto-webcheck")

	resp, err := t.http.Do(req)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", url, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	var findings []state.Finding
	add := func(sev state.Severity, title, detail, evidence string) {
		findings = append(findings, state.Finding{
			ID: fmt.Sprintf("WC-%s-%d", a.ID, len(findings)), Title: title, Severity: sev,
			Target: url, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true,
		})
	}

	// Missing security headers (only meaningful on a 2xx/3xx response).
	if resp.StatusCode < 400 {
		hasCSP := resp.Header.Get("Content-Security-Policy") != ""
		for _, h := range expectedHeaders {
			if resp.Header.Get(h.name) != "" {
				continue
			}
			// X-Frame-Options is satisfied by a CSP frame-ancestors directive.
			if h.name == "X-Frame-Options" && hasCSP && strings.Contains(strings.ToLower(resp.Header.Get("Content-Security-Policy")), "frame-ancestors") {
				continue
			}
			add(h.severity, "Missing security header: "+h.name, h.why, h.name+": (absent)")
		}
	}

	// Server version disclosure.
	if server := resp.Header.Get("Server"); server != "" && strings.ContainsAny(server, "0123456789") {
		add(state.SeverityLow, "Server version disclosed", "the Server header reveals software/version, aiding targeted attacks", "Server: "+server)
	}

	// Directory-listing exposure.
	if strings.Contains(string(body), "Index of /") {
		add(state.SeverityMedium, "Directory listing exposed", "the server returned an auto-generated directory index", "body contains \"Index of /\"")
	}

	// Cookie security flags.
	for _, c := range resp.Cookies() {
		if !c.Secure {
			add(state.SeverityLow, "Cookie without Secure flag", "a Set-Cookie lacks Secure, so it can be sent over plaintext HTTP", "cookie "+c.Name)
		}
		if !c.HttpOnly {
			add(state.SeverityLow, "Cookie without HttpOnly flag", "a Set-Cookie lacks HttpOnly, so it is reachable from JavaScript (XSS theft)", "cookie "+c.Name)
		}
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == http.SameSiteDefaultMode {
			add(state.SeverityInfo, "Cookie without restrictive SameSite", "a Set-Cookie does not restrict cross-site sending (CSRF surface)", "cookie "+c.Name)
		}
	}

	res.Findings = findings
	res.Success = true
	res.Output = fmt.Sprintf("%s: %d issue(s)", url, len(findings))
	res.FinishedAt = time.Now().UTC()
	return res, nil
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
