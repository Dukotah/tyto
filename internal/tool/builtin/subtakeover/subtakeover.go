// Package subtakeover detects subdomain takeovers against an authorized host. A
// subdomain is takeover-able when its DNS points (via CNAME) at a third-party
// service that is no longer claimed. Detection is DOUBLE-GATED by the shared
// internal/takeover engine: a finding is only emitted HIGH when BOTH (a) the
// host's CNAME resolves under a fingerprinted provider AND (b) an independent
// unclaimed signal holds (the provider's verbatim unclaimed-page string, or a
// definitive NXDOMAIN on the CNAME target for cloud providers). A body
// fingerprint ALONE is never enough — a claimed page that merely quotes the
// string, or an unrelated host, is not flagged. This near-zero-false-positive
// discipline is what keeps an automated bug-bounty run from getting banned.
//
// The tool performs one recursive CNAME lookup plus a single GET, so it is
// RiskLow. The Scope Guard has already authorized the target; untrusted response
// data only reaches quarantined Finding fields.
package subtakeover

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/takeover"
)

// Tool delegates detection to the shared, double-gated takeover engine.
type Tool struct {
	eng *takeover.Engine
}

// New returns a subtakeover Tool backed by the system resolver and a real HTTP
// fetcher (the takeover engine tries https:// then http:// and never follows a
// redirect off the provider host, so a redirect can't hide the unclaimed page).
func New() *Tool {
	return &Tool{eng: takeover.New(takeover.NewNetResolver(), takeover.NewHTTPFetcher())}
}

// NewWith builds a Tool over injected resolver/fetcher seams (for tests).
func NewWith(res takeover.Resolver, fetch takeover.Fetcher) *Tool {
	return &Tool{eng: takeover.New(res, fetch)}
}

func (t *Tool) Name() string              { return "subtakeover" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	host := extractHost(a.Target)
	if host == "" {
		res.Err = "empty target"
		res.Output = "subtakeover: no host to check"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	target := normalizeURL(a.Target)

	r := t.eng.Check(ctx, host, nil, nil)
	if r.Vulnerable {
		// Double-gate satisfied: CNAME-to-provider AND an independent unclaimed
		// signal. This is a directly-observed, near-certain condition → Validated.
		res.Findings = append(res.Findings, state.Finding{
			ID:          fmt.Sprintf("STO-%s-0", a.ID),
			Title:       "Possible subdomain takeover (" + r.Service + ")",
			Severity:    state.SeverityHigh,
			Target:      target,
			Description: "the host's CNAME points to " + r.Service + " and the resource shows a verbatim unclaimed signal — a dangling DNS record an attacker can claim. " + r.Reason,
			Evidence:    r.Evidence,
			Repro:       "resolve the CNAME for " + host + " (points under " + r.Service + "), then register/claim the dangling resource at that provider to serve content on " + host,
			Impact:      "full control of content served on a trusted in-scope hostname (phishing, cookie/session theft, CSP bypass, reputation abuse)",
			Tool:        t.Name(),
			Validated:   true,
		})
	} else {
		res.Findings = append(res.Findings, state.Finding{
			ID:          fmt.Sprintf("STO-%s-0", a.ID),
			Title:       "No subdomain-takeover detected",
			Severity:    state.SeverityInfo,
			Target:      target,
			Description: r.Reason,
			Tool:        t.Name(),
			Validated:   true,
		})
	}

	res.Success = true
	res.Output = fmt.Sprintf("subtakeover %s: %d finding(s)", target, len(res.Findings))
	res.FinishedAt = time.Now().UTC()
	return res, nil
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
// to http:// unless an explicit TLS port suggests https.
func normalizeURL(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	if strings.HasSuffix(target, ":443") || strings.HasSuffix(target, ":8443") {
		return "https://" + target
	}
	return "http://" + target
}
