// Package emailsec performs a PASSIVE check of a domain's email-security DNS
// posture: it reads the domain's SPF (in TXT) and DMARC (in _dmarc TXT) records
// via ordinary recursive DNS queries and flags missing or weak policies. It
// sends nothing to the target host itself, so the tool is RiskPassive. Every
// finding is directly observed from a published record, so all are Validated.
// Record values only ever reach quarantined Finding fields. The Scope Guard has
// already authorized the target before Execute runs.
package emailsec

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// txtResolver is the minimal DNS capability emailsec needs. *net.Resolver
// satisfies it via LookupTXT, and tests inject a fake to run without network.
type txtResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Tool checks a domain's email-security DNS records. The resolver is a field so
// tests can inject a stub; New defaults to the system resolver.
type Tool struct{ res txtResolver }

// New returns an emailsec Tool backed by the system default resolver.
func New() *Tool { return &Tool{res: net.DefaultResolver} }

func (t *Tool) Name() string              { return "emailsec" }
func (t *Tool) Category() action.Category { return action.CategoryRecon }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskPassive }

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	domain := extractDomain(a.Target)
	if domain == "" {
		res.Err = "empty target"
		res.Output = "emailsec: no domain to check"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	var (
		findings []state.Finding
		summary  []string
	)
	n := 0
	addFinding := func(sev state.Severity, title, detail, evidence string) {
		findings = append(findings, state.Finding{
			ID: fmt.Sprintf("EMAILSEC-%s-%d", a.ID, n), Title: title, Severity: sev,
			Target: domain, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true,
		})
		n++
	}

	// Honor cancellation before any lookup work.
	select {
	case <-ctx.Done():
		res.Err = ctx.Err().Error()
		res.Output = "emailsec: cancelled"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	default:
	}

	// --- SPF (published as a TXT record on the apex). ---
	spf := findRecord(t.lookupTXT(ctx, domain), "v=spf1")
	switch {
	case spf == "":
		addFinding(state.SeverityMedium, "No SPF record (email spoofing risk)",
			"the domain publishes no SPF policy, so receivers cannot verify which hosts may send mail as it",
			"no v=spf1 TXT record on "+domain)
		summary = append(summary, "SPF: missing")
	case isOverlyPermissiveSPF(spf):
		addFinding(state.SeverityHigh, "Overly permissive SPF (+all)",
			"the SPF policy ends in +all, which authorizes any host to send mail as the domain",
			spf)
		summary = append(summary, "SPF: +all")
	default:
		summary = append(summary, "SPF: present")
	}

	select {
	case <-ctx.Done():
		res.Err = ctx.Err().Error()
		res.Output = "emailsec: cancelled"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	default:
	}

	// --- DMARC (published as a TXT record on _dmarc.<domain>). ---
	dmarc := findRecord(t.lookupTXT(ctx, "_dmarc."+domain), "v=DMARC1")
	switch {
	case dmarc == "":
		addFinding(state.SeverityMedium, "No DMARC record",
			"the domain publishes no DMARC policy, so SPF/DKIM alignment is neither enforced nor reported",
			"no v=DMARC1 TXT record on _dmarc."+domain)
		summary = append(summary, "DMARC: missing")
	case strings.Contains(dmarc, "p=none"):
		addFinding(state.SeverityLow, "DMARC policy is p=none (monitor only)",
			"the DMARC policy is set to p=none, which reports failures but does not quarantine or reject spoofed mail",
			dmarc)
		summary = append(summary, "DMARC: p=none")
	default:
		summary = append(summary, "DMARC: present")
	}

	// Informational summary of what was found.
	addFinding(state.SeverityInfo, "Email-security DNS posture for "+domain,
		"summary of the domain's SPF and DMARC DNS records",
		strings.Join(summary, "; "))

	res.Findings = findings
	res.Success = true
	res.Output = fmt.Sprintf("emailsec %s: %s", domain, strings.Join(summary, ", "))
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// lookupTXT queries TXT records for name. A lookup error is treated as "no
// records present" (an absent policy), not a tool failure.
func (t *Tool) lookupTXT(ctx context.Context, name string) []string {
	txts, err := t.res.LookupTXT(ctx, name)
	if err != nil {
		return nil
	}
	return txts
}

// findRecord returns the first record whose (whitespace-trimmed) value begins
// with prefix, matched case-insensitively. Returns "" if none match.
func findRecord(records []string, prefix string) string {
	for _, r := range records {
		trimmed := strings.TrimSpace(r)
		if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(prefix)) {
			return trimmed
		}
	}
	return ""
}

// isOverlyPermissiveSPF reports whether an SPF record's all-mechanism is the
// permissive "+all" (or a bare "all", which defaults to "+all"). A "-all" or
// "~all" qualifier is the safe case and is not flagged.
func isOverlyPermissiveSPF(spf string) bool {
	if strings.Contains(spf, "+all") {
		return true
	}
	// A bare "all" token (no qualifier) is equivalent to "+all".
	for _, tok := range strings.Fields(spf) {
		if strings.EqualFold(tok, "all") {
			return true
		}
	}
	return false
}

// extractDomain returns the bare host from a target that may be a URL, a
// host:port pair, or already a bare hostname. It strips any scheme, userinfo,
// path, port, and a trailing dot.
func extractDomain(target string) string {
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
