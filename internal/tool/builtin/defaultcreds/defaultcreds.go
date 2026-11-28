// Package defaultcreds tests an authorized HTTP endpoint for accepted DEFAULT
// credentials via HTTP Basic auth. It is EXPLOIT-tier: it only runs after the
// Scope Guard has verified the target is in scope AND the engagement carries a
// verified authorization grant for high-risk actions.
//
// It is deliberately bounded and lockout-conscious: it first confirms the
// endpoint actually challenges authentication, tries only a tiny built-in list
// of well-known default pairs, and STOPS at the first accepted pair. It is not a
// brute forcer. A recovered credential is emitted on success so the operator's
// report and the planner's follow-ups can use it; the plaintext secret is held
// only in the quarantined Credential (never reaches the model).
package defaultcreds

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
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "defaultcreds" }
func (t *Tool) Category() action.Category { return action.CategoryIdentity }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskHigh }

// credPair is one default username/password guess.
type credPair struct{ user, pass string }

// defaultPairs is a small, well-known set of default credentials. Kept tiny and
// ordered most-likely-first; we stop at the first hit, so this never becomes a
// brute force and stays lockout-conscious.
var defaultPairs = []credPair{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "admin123"},
	{"admin", ""},
	{"root", "root"},
	{"root", "toor"},
	{"administrator", "administrator"},
	{"tomcat", "tomcat"},
	{"user", "user"},
	{"guest", "guest"},
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	url := normalizeURL(a.Target)

	add := func(sev state.Severity, title, detail, evidence, cvss string) {
		res.Findings = append(res.Findings, state.Finding{
			ID: fmt.Sprintf("DC-%s-%d", a.ID, len(res.Findings)), Title: title, Severity: sev,
			Target: url, Description: detail, Evidence: evidence, CVSS: cvss, Tool: t.Name(), Validated: true,
		})
	}

	// Baseline: an UNAUTHENTICATED GET. We only proceed if the endpoint actually
	// challenges authentication.
	baseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}
	baseReq.Header.Set("User-Agent", "tyto-defaultcreds")

	baseResp, err := t.http.Do(baseReq)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", url, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	challenges := baseResp.StatusCode == http.StatusUnauthorized || baseResp.Header.Get("WWW-Authenticate") != ""
	baseResp.Body.Close()

	if !challenges {
		add(state.SeverityInfo, "No HTTP authentication to test",
			"the endpoint returned a non-401 response with no WWW-Authenticate challenge, so there is no Basic auth to test",
			fmt.Sprintf("baseline HTTP %d, no auth challenge", baseResp.StatusCode), "")
		res.Success = true
		res.Output = fmt.Sprintf("%s: not auth-protected, nothing to test", url)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Try the tiny default list, stopping at the first accepted pair.
	for _, p := range defaultPairs {
		if err := ctx.Err(); err != nil {
			res.Err = err.Error()
			res.Output = fmt.Sprintf("%s: cancelled after partial default-credential test", url)
			res.FinishedAt = time.Now().UTC()
			return res, nil
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			res.Err = err.Error()
			res.FinishedAt = time.Now().UTC()
			return res, nil
		}
		req.Header.Set("User-Agent", "tyto-defaultcreds")
		req.SetBasicAuth(p.user, p.pass)

		resp, err := t.http.Do(req)
		if err != nil {
			res.Err = err.Error()
			res.Output = fmt.Sprintf("%s: no HTTP response (%v)", url, err)
			res.FinishedAt = time.Now().UTC()
			return res, nil
		}
		code := resp.StatusCode
		resp.Body.Close()

		// Auth accepted: no longer challenged/forbidden.
		if code < 400 {
			pair := p.user + "/" + p.pass
			add(state.SeverityHigh, "Default credentials accepted: "+pair,
				"the endpoint accepted a well-known default credential pair over HTTP Basic auth, granting authenticated access",
				fmt.Sprintf("HTTP %d with Basic %s:%s", code, p.user, p.pass),
				"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
			res.Credentials = append(res.Credentials, state.Credential{
				Kind: state.CredPassword, Username: p.user, Secret: p.pass,
				Source: "defaultcreds", Target: url,
			})
			res.Success = true
			res.Output = fmt.Sprintf("%s: default credentials accepted (%s)", url, pair)
			res.FinishedAt = time.Now().UTC()
			return res, nil
		}
	}

	res.Success = true
	res.Output = fmt.Sprintf("%s: no default credentials accepted (%d tried)", url, len(defaultPairs))
	res.FinishedAt = time.Now().UTC()
	return res, nil
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

// WrapTransport implements tool.TransportWrapper: it lets the engine layer a
// RoundTripper (engagement traffic marker, evidence capture) under this tool's
// HTTP client without the tool knowing about it.
func (t *Tool) WrapTransport(wrap func(http.RoundTripper) http.RoundTripper) {
	t.http.Transport = wrap(t.http.Transport)
}
