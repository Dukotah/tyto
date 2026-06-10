// Package subtakeover detects POTENTIAL subdomain takeovers against an authorized
// host. A subdomain is takeover-prone when its DNS points (via CNAME) at a
// third-party service that is no longer claimed — fetching the host then returns
// a known "unclaimed / not-found" fingerprint served by that provider. The tool
// performs one ordinary recursive CNAME lookup plus a single GET, so it is
// RiskLow. A matched fingerprint (optionally corroborated by a CNAME to the
// matching provider) is a directly observed condition, hence Validated. The Scope
// Guard has already authorized the target; untrusted response data only reaches
// quarantined Finding fields.
package subtakeover

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool fetches the target and inspects the CNAME chain + response body for
// known subdomain-takeover fingerprints. The resolver is a field so tests can
// inject a custom *net.Resolver (like dnsenum); the http.Client is likewise a
// field so tests can point it at an httptest server.
type Tool struct {
	http *http.Client
	res  *net.Resolver
}

// New returns a subtakeover Tool backed by the system default resolver.
func New() *Tool {
	return &Tool{
		http: &http.Client{Timeout: 8 * time.Second},
		res:  net.DefaultResolver,
	}
}

func (t *Tool) Name() string              { return "subtakeover" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const maxBody = 64 << 10

// provider is one third-party service with the DNS-target suffixes its claimed
// names live under and the body fingerprints it serves for an unclaimed name.
type provider struct {
	name         string
	cnameDomains []string // CNAME target suffixes that indicate this provider
	fingerprints []string // body substrings shown for an unclaimed/missing resource
}

// providers is a small, high-signal catalog of services commonly affected by
// dangling-DNS subdomain takeovers. Fingerprints are matched literally against
// the response body; cnameDomains corroborate (but are not required for) a match.
var providers = []provider{
	{
		name:         "GitHub Pages",
		cnameDomains: []string{"github.io", "github.map.fastly.net"},
		fingerprints: []string{"There isn't a GitHub Pages site here."},
	},
	{
		name:         "AWS S3",
		cnameDomains: []string{"amazonaws.com", "s3.amazonaws.com"},
		fingerprints: []string{"NoSuchBucket", "The specified bucket does not exist"},
	},
	{
		name:         "Heroku",
		cnameDomains: []string{"herokuapp.com", "herokudns.com", "herokussl.com"},
		fingerprints: []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"},
	},
	{
		name:         "Fastly",
		cnameDomains: []string{"fastly.net"},
		fingerprints: []string{"Fastly error: unknown domain"},
	},
	{
		name:         "Shopify",
		cnameDomains: []string{"myshopify.com"},
		fingerprints: []string{"Sorry, this shop is currently unavailable"},
	},
	{
		name:         "Tumblr",
		cnameDomains: []string{"domains.tumblr.com"},
		fingerprints: []string{"Whatever you were looking for doesn't currently exist at this address"},
	},
	{
		name:         "Surge.sh",
		cnameDomains: []string{"surge.sh"},
		fingerprints: []string{"project not found"},
	},
	{
		name:         "Bitbucket",
		cnameDomains: []string{"bitbucket.io"},
		fingerprints: []string{"Repository not found"},
	},
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	host := extractHost(a.Target)
	if host == "" {
		res.Err = "empty target"
		res.Output = "subtakeover: no host to check"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	url := normalizeURL(a.Target)

	var findings []state.Finding
	n := 0
	add := func(sev state.Severity, title, detail, evidence string, validated bool) {
		findings = append(findings, state.Finding{
			ID: fmt.Sprintf("STO-%s-%d", a.ID, n), Title: title, Severity: sev,
			Target: url, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: validated,
		})
		n++
	}

	// Resolve the CNAME chain. A CNAME to a known provider corroborates a body
	// fingerprint but is not required; lookup errors are non-fatal.
	cname := ""
	if c, err := t.res.LookupCNAME(ctx, host); err == nil {
		c = strings.TrimSuffix(strings.ToLower(c), ".")
		if c != "" && !strings.EqualFold(c, host) {
			cname = c
		}
	}
	cnameProvider := matchCNAMEProvider(cname)

	// Fetch the target over HTTP(S).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: bad request (%v)", url, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	req.Header.Set("User-Agent", "tyto-subtakeover")

	resp, err := t.http.Do(req)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", url, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	body := string(raw)

	// Inspect the body for a known takeover fingerprint.
	prov, matched, found := matchFingerprint(body)
	if found {
		detail := fmt.Sprintf("the response served by %s shows an unclaimed/not-found page, indicating a dangling DNS record that may be takeover-prone", prov.name)
		if cnameProvider == prov.name && cname != "" {
			detail += fmt.Sprintf(" (CNAME points to %s)", cname)
		}
		add(state.SeverityHigh, "Possible subdomain takeover ("+prov.name+")",
			detail, "fingerprint: "+truncate(matched, 120), true)
	} else {
		detail := "the response body contained none of the known third-party takeover fingerprints"
		if cnameProvider != "" {
			detail += fmt.Sprintf(" (CNAME points to %s but the resource appears claimed)", cnameProvider)
		}
		add(state.SeverityInfo, "No subdomain-takeover fingerprint detected", detail, "", true)
	}

	res.Findings = findings
	res.Success = true
	res.Output = fmt.Sprintf("subtakeover %s: %d finding(s)", url, len(findings))
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// matchFingerprint scans body for any provider fingerprint and returns the
// owning provider, the matched substring, and whether a match was found.
func matchFingerprint(body string) (provider, string, bool) {
	for _, p := range providers {
		for _, fp := range p.fingerprints {
			if strings.Contains(body, fp) {
				return p, fp, true
			}
		}
	}
	return provider{}, "", false
}

// matchCNAMEProvider returns the provider name whose cnameDomains the given
// (already lowercased, trailing-dot-trimmed) CNAME target falls under, or "".
func matchCNAMEProvider(cname string) string {
	if cname == "" {
		return ""
	}
	for _, p := range providers {
		for _, d := range p.cnameDomains {
			if cname == d || strings.HasSuffix(cname, "."+d) {
				return p.name
			}
		}
	}
	return ""
}

// truncate shortens s to at most n bytes, appending an ellipsis if cut. It keeps
// quarantined Evidence compact without losing the load-bearing fingerprint.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// extractHost returns the bare host from a target that may be a URL, a host:port
// pair, or already a bare hostname. It strips any scheme, userinfo, path, port,
// and a trailing dot.
func extractHost(target string) string {
	s := strings.TrimSpace(target)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	} else {
		s = strings.TrimPrefix(s, "[")
		s = strings.TrimSuffix(s, "]")
	}
	return strings.TrimSuffix(strings.TrimSpace(s), ".")
}

// normalizeURL turns a bare host (or host:port) into a fetchable URL, defaulting
// to http:// unless an explicit TLS port suggests https. Copied from webcheck so
// the two tools agree on scheme selection.
func normalizeURL(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	if strings.HasSuffix(target, ":443") || strings.HasSuffix(target, ":8443") {
		return "https://" + target
	}
	return "http://" + target
}
