// Package dnsenum performs PASSIVE DNS enumeration of an authorized domain: it
// resolves the apex's A/AAAA, MX, NS, TXT, and CNAME records and probes a small
// embedded list of common subdomain labels. It sends nothing to the target host
// itself — only ordinary recursive DNS queries via the system resolver — so the
// whole tool is RiskPassive. Discovered IPs and subdomains become host Assets the
// planner can pivot from; every finding is directly observed, so all are marked
// Validated. The Scope Guard has already authorized the target; record values
// (TXT strings, resolved names) only reach quarantined Finding/Asset fields.
package dnsenum

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool resolves DNS records for a domain. The resolver is a field so tests can
// inject a custom *net.Resolver (or rely on real lookups of "localhost").
type Tool struct{ res *net.Resolver }

// New returns a dnsenum Tool backed by the system default resolver.
func New() *Tool { return &Tool{res: net.DefaultResolver} }

func (t *Tool) Name() string              { return "dnsenum" }
func (t *Tool) Category() action.Category { return action.CategoryRecon }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskPassive }

// commonSubdomains is a small, high-signal wordlist for passive subdomain
// probing. Each is a single recursive DNS query — no contact with the target.
var commonSubdomains = []string{
	"www", "mail", "dev", "staging", "api", "admin", "test", "portal",
	"vpn", "git", "gitlab", "jenkins", "ftp", "smtp", "ns1", "ns2",
	"cpanel", "webmail", "m", "beta",
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	domain := extractDomain(a.Target)
	if domain == "" {
		res.Err = "empty target"
		res.Output = "dnsenum: no domain to resolve"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	var (
		findings []state.Finding
		assets   []state.Asset
		summary  []string
	)
	n := 0
	addFinding := func(sev state.Severity, title, detail, evidence string) {
		findings = append(findings, state.Finding{
			ID: fmt.Sprintf("DNS-%s-%d", a.ID, n), Title: title, Severity: sev,
			Target: domain, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true,
		})
		n++
	}
	m := 0
	addHostAsset := func(value string) {
		assets = append(assets, state.Asset{
			ID: fmt.Sprintf("dnsenum-%s-host-%d", a.ID, m), Type: "host", Value: value,
		})
		m++
	}

	// A/AAAA addresses of the apex.
	if addrs, err := t.res.LookupHost(ctx, domain); err == nil && len(addrs) > 0 {
		sort.Strings(addrs)
		for _, ip := range addrs {
			addHostAsset(ip)
		}
		addFinding(state.SeverityInfo, "DNS A/AAAA records for "+domain,
			"the domain resolves to one or more IP addresses", "addresses: "+strings.Join(addrs, ", "))
		summary = append(summary, fmt.Sprintf("%d address(es)", len(addrs)))
	}

	// MX records.
	if mxs, err := t.res.LookupMX(ctx, domain); err == nil && len(mxs) > 0 {
		hosts := make([]string, 0, len(mxs))
		for _, mx := range mxs {
			hosts = append(hosts, fmt.Sprintf("%s (pref %d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
		sort.Strings(hosts)
		addFinding(state.SeverityInfo, "DNS MX records for "+domain,
			"mail exchangers are published for the domain", "MX: "+strings.Join(hosts, ", "))
		summary = append(summary, fmt.Sprintf("%d MX", len(mxs)))
	}

	// NS records.
	if nss, err := t.res.LookupNS(ctx, domain); err == nil && len(nss) > 0 {
		hosts := make([]string, 0, len(nss))
		for _, ns := range nss {
			hosts = append(hosts, strings.TrimSuffix(ns.Host, "."))
		}
		sort.Strings(hosts)
		addFinding(state.SeverityInfo, "DNS NS records for "+domain,
			"authoritative name servers for the domain", "NS: "+strings.Join(hosts, ", "))
		summary = append(summary, fmt.Sprintf("%d NS", len(nss)))
	}

	// TXT records (often disclose SPF/DMARC and third-party verification tokens).
	if txts, err := t.res.LookupTXT(ctx, domain); err == nil && len(txts) > 0 {
		addFinding(state.SeverityInfo, "DNS TXT records for "+domain,
			"TXT records (may include SPF/DMARC policy and verification tokens)",
			"TXT: "+strings.Join(txts, " | "))
		summary = append(summary, fmt.Sprintf("%d TXT", len(txts)))
	}

	// CNAME (apex usually has none; subdomains may — record if present).
	if cname, err := t.res.LookupCNAME(ctx, domain); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && !strings.EqualFold(cname, domain) {
			addFinding(state.SeverityInfo, "DNS CNAME for "+domain,
				"the domain is an alias (CNAME) for another name", "CNAME: "+cname)
			summary = append(summary, "CNAME")
		}
	}

	// Subdomain brute (one recursive query per label; resolution errors are normal).
	subFound := 0
	for _, sub := range commonSubdomains {
		select {
		case <-ctx.Done():
			res.Err = ctx.Err().Error()
			res.Output = "dnsenum: cancelled"
			res.FinishedAt = time.Now().UTC()
			return res, nil
		default:
		}
		fqdn := sub + "." + domain
		addrs, err := t.res.LookupHost(ctx, fqdn)
		if err != nil || len(addrs) == 0 {
			continue
		}
		addHostAsset(fqdn)
		sort.Strings(addrs)
		addFinding(state.SeverityInfo, "Subdomain discovered: "+fqdn,
			"a common subdomain label resolves for this domain",
			fqdn+" -> "+strings.Join(addrs, ", "))
		subFound++
	}
	if subFound > 0 {
		summary = append(summary, fmt.Sprintf("%d subdomain(s)", subFound))
	}

	res.Findings = findings
	res.Assets = assets
	res.Success = true
	if len(summary) == 0 {
		res.Output = fmt.Sprintf("dnsenum %s: no records resolved", domain)
	} else {
		res.Output = fmt.Sprintf("dnsenum %s: %s", domain, strings.Join(summary, ", "))
	}
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// extractDomain returns the bare host from a target that may be a URL, a
// host:port pair, or already a bare hostname. It strips any scheme, path,
// userinfo, port, and a trailing dot.
func extractDomain(target string) string {
	s := strings.TrimSpace(target)
	if s == "" {
		return ""
	}
	// Strip scheme (e.g. "https://").
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip userinfo (e.g. "user@host").
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// Strip path/query/fragment.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Strip port. Use net.SplitHostPort so bracketed IPv6 literals are handled.
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	} else {
		// Not host:port; still drop bare surrounding brackets from an IPv6 literal.
		s = strings.TrimPrefix(s, "[")
		s = strings.TrimSuffix(s, "]")
	}
	return strings.TrimSuffix(strings.TrimSpace(s), ".")
}
