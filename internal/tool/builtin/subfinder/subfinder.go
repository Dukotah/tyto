// Package subfinder is a passive subdomain-enumeration adapter that shells out to
// the EXTERNAL subfinder binary (`subfinder -d <domain> -silent`) and turns its
// one-host-per-line output into domain assets + info findings. Like every tyto
// shell-out adapter it is runtime-detected: tyto stays a pure-Go, offline-by-
// default binary, so if subfinder is not installed this adapter DEGRADES
// GRACEFULLY — it emits a single info finding and succeeds rather than failing.
// The live enumeration path is only taken when an operator has subfinder on PATH.
//
// It is recon-category and RiskPassive (subfinder queries third-party passive
// data sources — cert logs, passive DNS, search engines — and never contacts the
// target), so the Scope Guard gates it before Execute is ever reached. subfinder
// is driven without a shell (args are a slice), so the domain value can't inject
// arbitrary flags.
package subfinder

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool implements an external subfinder passive subdomain-enumeration adapter.
type Tool struct{}

// New returns a subfinder Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "subfinder" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryRecon }

// MaxRisk implements tool.Tool. Passive subdomain enumeration queries only
// third-party data sources and never contacts the target, so the ceiling is
// Passive.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskPassive }

// maxSubdomains caps emitted findings/assets so a domain with an enormous
// passive footprint (or crafted output) can't balloon the result.
const maxSubdomains = 500

// Execute resolves the bare domain from the target, detects subfinder, and — if
// present — runs `subfinder -d <domain> -silent` and parses the one-host-per-line
// output into domain assets and findings. If the target is an IP it returns early
// with an info finding (subfinder needs a domain). With subfinder not installed it
// degrades gracefully to a single info finding. Both early paths return Success.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	domain := domainOf(a.Target)

	// subfinder enumerates subdomains of a registrable domain; an IP has none.
	if domain == "" || net.ParseIP(domain) != nil {
		res.Findings = []state.Finding{{
			ID:          fmt.Sprintf("F-%s-0", a.ID),
			Title:       "subfinder needs a domain, not an IP",
			Severity:    state.SeverityInfo,
			Target:      a.Target,
			Description: "subfinder performs passive subdomain enumeration of a domain name; the target is an IP (or empty), so enumeration was skipped",
			Tool:        t.Name(),
			Validated:   false,
			FoundAt:     time.Now().UTC(),
		}}
		res.Success = true
		res.Output = "subfinder: target is not a domain; skipped"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	bin := adapter.Detect("subfinder")
	if bin == "" {
		res.Findings = []state.Finding{adapter.Missing("subfinder", a.Target, "apt install subfinder OR go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")}
		res.Success = true
		res.Output = "subfinder not available; subdomain enumeration skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Honor cancellation before launching the external process. (adapter.Run also
	// binds ctx, so an in-flight run is killed on cancel too.)
	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	// -d <domain> target, -silent prints only subdomains (one per line). The "all"
	// param turns on every passive source (slower, noisier). No other a.Params are
	// honored so a tool/model-controlled string can never inject subfinder flags.
	args := []string{"-d", domain, "-silent"}
	if strings.TrimSpace(a.Params["all"]) == "true" {
		args = append(args, "-all")
	}

	out, runErr := adapter.Run(ctx, bin, args, 2<<20)

	findings, assets := parseSubfinder(out, domain)

	// Stamp IDs/tool on parsed findings (parseSubfinder stays tool-agnostic so it
	// is purely unit-testable on a captured output string).
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%s-%d", a.ID, i)
		findings[i].Tool = t.Name()
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = time.Now().UTC()
		}
	}
	res.Findings = append(res.Findings, findings...)
	res.Assets = append(res.Assets, assets...)

	summary := fmt.Sprintf("subfinder: %d subdomain(s)", len(assets))
	if runErr != nil && len(assets) == 0 {
		// subfinder present but failed (no sources configured, network, etc.) and
		// gave us nothing parseable. Not an error from tyto's perspective.
		summary = fmt.Sprintf("subfinder run error with no parseable output: %v", runErr)
	} else if runErr != nil {
		summary += fmt.Sprintf(" (subfinder exited non-zero: %v)", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// parseSubfinder best-effort parses `subfinder -silent` output (one subdomain per
// line) into info findings plus matching domain assets. For each non-empty line
// that looks like a hostname (contains a dot, no whitespace) it emits a
// SeverityInfo "Subdomain: <sub>" finding (Validated, since subfinder directly
// observed it in a passive source) and a "domain" Asset. Results are deduplicated
// and capped at ~500. It is tool-agnostic for unit-testing. parentDomain is
// accepted for context/future scoping but parsing tolerates any hostname.
func parseSubfinder(out, parentDomain string) ([]state.Finding, []state.Asset) {
	var findings []state.Finding
	var assets []state.Asset
	seen := map[string]bool{}

	for _, line := range strings.Split(out, "\n") {
		sub := strings.ToLower(strings.TrimSpace(line))
		if sub == "" {
			continue
		}
		// A hostname has a dot and no embedded whitespace; reject anything else
		// (banners, errors, "[INF] ..." log noise that slips past -silent).
		if strings.ContainsAny(sub, " \t") || !strings.Contains(sub, ".") {
			continue
		}
		// Strip a trailing dot from FQDNs so it dedups with the bare form.
		sub = strings.TrimSuffix(sub, ".")
		if sub == "" || seen[sub] {
			continue
		}
		seen[sub] = true
		if len(assets) >= maxSubdomains {
			break
		}

		findings = append(findings, state.Finding{
			Title:       "Subdomain: " + sub,
			Severity:    state.SeverityInfo,
			Target:      sub,
			Description: "subfinder discovered subdomain " + sub + " via passive sources",
			Evidence:    sub,
			Validated:   true,
		})
		assets = append(assets, state.Asset{
			ID:    "domain:" + sub,
			Type:  "domain",
			Value: sub,
		})
	}
	return findings, assets
}

// domainOf strips scheme/path/port from a target to get a bare domain (or IP).
// A URL like "https://api.h.com:8443/x" resolves to "api.h.com"; a bare
// host/domain/ip passes through unchanged.
func domainOf(target string) string {
	t := strings.TrimSpace(target)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	return strings.ToLower(strings.TrimSuffix(t, "."))
}
