// Package hostheader tests for Host-header-injection on an authorized URL. Web
// apps that build absolute links/redirects from the request Host (or from
// X-Forwarded-Host and friends) are vulnerable to cache poisoning, link
// injection, and password-reset poisoning: an attacker who controls the host a
// victim's reset email points at can hijack the token.
//
// The probe is read-only. We first fetch with the LEGITIMATE Host to establish
// a baseline, then send one GET per injection vector with a unique benign
// marker host injected (via the Host header itself, or via X-Forwarded-Host /
// X-Forwarded-Server / X-Host / Forwarded). Redirects are NOT followed
// (CheckRedirect returns http.ErrUseLastResponse) so we inspect the first-hop
// Location ourselves. A vector is flagged only when the marker is ABSENT from
// the baseline response and PRESENT in a security-relevant position of the
// injected response (an absolute URL in the body, or a Location redirect) —
// baseline subtraction keeps static occurrences of the real host from
// false-positiving. Detection, not exploitation, so the tool is RiskLow.
package hostheader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// maxBody bounds how much of each response body we read; reflection of a host
// in a link/canonical/og:url lives near the top, and we never need megabytes.
const maxBody = 512 * 1024

// vector is one Host-injection technique: how we set the marker on a request.
type vector struct {
	name   string // human label, used in finding titles
	header string // header to set ("Host" means the request Host field)
}

// vectors are the injection points, one request each.
var vectors = []vector{
	{name: "Host header", header: "Host"},
	{name: "X-Forwarded-Host header", header: "X-Forwarded-Host"},
	{name: "X-Forwarded-Server header", header: "X-Forwarded-Server"},
	{name: "X-Host header", header: "X-Host"},
	{name: "Forwarded header", header: "Forwarded"},
}

// markerSeq makes each engagement's marker host unique so a cached/static page
// from a prior run can never collide with this run's probe.
var markerSeq uint64

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{
		Timeout: 8 * time.Second,
		// Do not follow redirects: we inspect the first-hop Location ourselves
		// and never want to chase a reflected marker host off to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (t *Tool) Name() string              { return "hostheader" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	target := normalizeURL(a.Target)
	if _, err := url.Parse(target); err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}

	// Unique benign marker host for this run.
	marker := fmt.Sprintf("tyto-hh-%d.example", atomic.AddUint64(&markerSeq, 1))

	// Baseline: fetch with the legitimate Host, no injection.
	baseResp, baseBody, err := t.fetch(ctx, target, a.Cookie, "")
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no baseline HTTP response (%v)", target, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	baseLoc := baseResp.Header.Get("Location")

	// If the marker somehow already appears in the baseline (it shouldn't —
	// it's unique), we cannot attribute any later reflection to our injection,
	// so refuse to flag anything for safety.
	baselineHasMarker := bodyReflectsHost(baseBody, marker) || locationReflectsHost(baseLoc, marker)

	var hits int
	add := func(sev state.Severity, title, detail, evidence, repro string) {
		hits++
		res.Findings = append(res.Findings, state.Finding{
			ID:          fmt.Sprintf("HOSTHDR-%s-%d", a.ID, hits),
			Title:       title,
			Severity:    sev,
			Target:      target,
			Description: detail,
			Evidence:    evidence,
			Repro:       repro,
			Impact:      "an attacker who poisons the Host can make the app emit attacker-controlled absolute URLs (cache poisoning, link injection) or redirect/reset links pointing at their host (password-reset poisoning)",
			Tool:        t.Name(),
			Validated:   true,
		})
	}

	for _, v := range vectors {
		if ctx.Err() != nil {
			res.Err = ctx.Err().Error()
			res.FinishedAt = time.Now().UTC()
			return res, ctx.Err()
		}

		var resp *http.Response
		var body string
		var err error
		switch v.header {
		case "Host":
			// Inject the marker as the actual HTTP Host field.
			resp, body, err = t.fetch(ctx, target, a.Cookie, marker)
		case "Forwarded":
			// RFC 7239 syntax: Forwarded: host=<marker>.
			resp, body, err = t.fetchHeader(ctx, target, a.Cookie, "Forwarded", "host="+marker)
		default:
			// X-Forwarded-Host / X-Forwarded-Server / X-Host.
			resp, body, err = t.fetchHeader(ctx, target, a.Cookie, v.header, marker)
		}
		if err != nil {
			continue // a single failed vector should not abort the others
		}
		loc := resp.Header.Get("Location")

		r := classify(baseBody, baseLoc, body, loc, marker, baselineHasMarker)
		switch r.kind {
		case reflectLocation:
			add(state.SeverityHigh,
				"Host injection reflected in Location redirect via "+v.name,
				"the injected marker host appears in the response Location header; the app builds its redirect target from the request Host, enabling open-redirect / password-reset-poisoning (a reset link can be aimed at an attacker host)",
				r.evidence, r.repro(target, v, marker))
		case reflectBody:
			add(state.SeverityMedium,
				"Host injection reflected in response body via "+v.name,
				"the injected marker host appears in an absolute URL in the response body (link/script/canonical/og:url); the app builds absolute URLs from the request Host, enabling web-cache poisoning and link injection",
				r.evidence, r.repro(target, v, marker))
		}
	}

	res.Success = true
	res.Output = fmt.Sprintf("%s: tested %d vector(s), %d issue(s)", target, len(vectors), hits)
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// fetch performs one GET. hostFieldOverride, when non-empty, sets the HTTP Host
// (the Host-header injection vector). Redirects are not followed.
func (t *Tool) fetch(ctx context.Context, target, cookie, hostFieldOverride string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "tyto-hostheader")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if hostFieldOverride != "" {
		req.Host = hostFieldOverride
	}
	return do(t.http, req)
}

// fetchHeader performs one GET with an extra request header set (the
// X-Forwarded-Host / X-Host / Forwarded vectors). The legitimate Host is kept.
func (t *Tool) fetchHeader(ctx context.Context, target, cookie, key, val string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "tyto-hostheader")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set(key, val)
	return do(t.http, req)
}

func do(client *http.Client, req *http.Request) (*http.Response, string, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp, "", err
	}
	return resp, string(body), nil
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
