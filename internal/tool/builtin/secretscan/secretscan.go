// Package secretscan fetches a URL (and its same-host <script src> JS files,
// bounded) and regex-scans the bodies for exposed secrets and credentials —
// AWS keys, Google API keys, Slack tokens, private-key blocks, and generic
// hardcoded-secret assignments. It is a low-risk active probe: the Scope Guard
// has already authorized any action that reaches Execute. Matched secret
// material is never stored in full — Evidence holds only a redacted snippet
// (pattern type plus first 4 and last 2 characters) so the raw secret never
// lands in a Finding field or the report.
package secretscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool implements a regex-based secret scanner over an HTTP body and its
// same-host script sources.
type Tool struct{ http *http.Client }

// New returns a secretscan Tool that follows redirects with the default client
// policy and times out quickly.
func New() *Tool {
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "secretscan" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const (
	maxBody       = 512 << 10 // cap the body we read per source
	maxScripts    = 8         // same-host <script src> files we follow
	maxGenericPer = 3         // generic-assignment matches emitted per source
)

// pattern describes one secret regex and how a match is classified.
type pattern struct {
	name     string
	re       *regexp.Regexp
	severity state.Severity
	title    string
	generic  bool // subject to the per-source cap to limit noise
}

var patterns = []pattern{
	{
		name:     "AWS access key ID",
		re:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		severity: state.SeverityHigh,
		title:    "Exposed AWS access key ID",
	},
	{
		name:     "Google API key",
		re:       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		severity: state.SeverityHigh,
		title:    "Exposed Google API key",
	},
	{
		name:     "Slack token",
		re:       regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),
		severity: state.SeverityHigh,
		title:    "Exposed Slack token",
	},
	{
		name:     "private key",
		re:       regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
		severity: state.SeverityHigh,
		title:    "Exposed private key",
	},
	{
		name:     "hardcoded secret",
		re:       regexp.MustCompile(`(?i)(api[_-]?key|secret|passwd|password|token)["'\s:=]{1,4}[0-9A-Za-z\-_]{16,}`),
		severity: state.SeverityMedium,
		title:    "Possible hardcoded secret",
		generic:  true,
	},
	{
		// Credential PAIRS (admin:Password123!, root=hunter2) — commonly left in
		// HTML comments, config snippets and debug output. Keyword-gated to the
		// account side so JSON like "user":"guest" (quote after the key, not a
		// separator) does not match, and the value must be a 6+ char token.
		name:     "exposed credential pair",
		re:       regexp.MustCompile(`(?i)\b(?:administrator|admin|username|user|login|root)\s*[:=]\s*\S{6,40}`),
		severity: state.SeverityHigh,
		title:    "Exposed credentials",
	},
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

// Execute GETs the target plus a bounded set of same-host scripts and scans
// every body for exposed secrets.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	target := normalizeURL(a.Target)

	body, err := t.fetch(ctx, target)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", target, err)
		res.FinishedAt = time.Now().UTC()
		// A connection error is not a tool failure; report it and move on.
		return res, nil
	}

	// (type, redacted-evidence) -> already emitted.
	seen := map[string]bool{}
	var findings []state.Finding
	var creds []state.Credential
	f, c := scan(target, body, seen)
	findings, creds = append(findings, f...), append(creds, c...)

	for _, src := range sameHostScripts(target, body) {
		js, err := t.fetch(ctx, src)
		if err != nil {
			continue // a missing/unreachable script must not fail the scan
		}
		f, c := scan(src, js, seen)
		findings, creds = append(findings, f...), append(creds, c...)
	}

	for i := range findings {
		findings[i].ID = fmt.Sprintf("SECRET-%s-%d", a.ID, i)
		findings[i].Tool = t.Name()
		findings[i].FoundAt = time.Now().UTC()
	}
	res.Findings = findings
	res.Credentials = creds

	res.Success = true
	res.Output = fmt.Sprintf("%s: scanned for secrets, %d finding(s)", target, len(findings))
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// fetch GETs url and returns the body, capped at maxBody.
func (t *Tool) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tyto-secretscan")

	resp, err := t.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

// scan runs every pattern over body and returns deduped, redacted findings.
// seen is shared across sources so identical (type, redacted-evidence) pairs
// are emitted only once per Execute.
func scan(source string, body []byte, seen map[string]bool) ([]state.Finding, []state.Credential) {
	s := string(body)
	var out []state.Finding
	var creds []state.Credential
	for _, p := range patterns {
		genericCount := 0
		for _, m := range p.re.FindAllString(s, -1) {
			if p.generic {
				if genericCount >= maxGenericPer {
					break
				}
			}
			evidence := redact(p.name, m)
			key := p.name + "\x00" + evidence
			if seen[key] {
				continue
			}
			seen[key] = true
			if p.generic {
				genericCount++
			}
			out = append(out, state.Finding{
				Title:       p.title,
				Severity:    p.severity,
				Target:      source,
				Description: fmt.Sprintf("%s detected at %s", p.title, source),
				Evidence:    evidence,
				Validated:   true, // we directly read the match out of the live body
			})
			// Record it in the credential model too (redacted secret, per this
			// tool's never-store-plaintext stance).
			creds = append(creds, state.Credential{
				Kind:   state.CredToken,
				Secret: evidence,
				Source: source,
				Target: source,
			})
		}
	}
	return out, creds
}

// redact returns a non-reversible snippet: the pattern type plus the first 4
// and last 2 characters of the match. The full secret is never returned.
func redact(name, match string) string {
	r := []rune(match)
	var shown string
	if len(r) <= 6 {
		// Too short to partially reveal without exposing most of it.
		shown = strings.Repeat("*", len(r))
	} else {
		shown = string(r[:4]) + strings.Repeat("*", len(r)-6) + string(r[len(r)-2:])
	}
	return fmt.Sprintf("%s: %s", name, shown)
}

// sameHostScripts extracts up to maxScripts same-host <script src> URLs,
// resolved against base.
func sameHostScripts(base string, body []byte) []string {
	bu, err := url.Parse(base)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(string(body), -1) {
		if len(out) >= maxScripts {
			break
		}
		ref, err := url.Parse(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}
		abs := bu.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			continue
		}
		if !strings.EqualFold(abs.Host, bu.Host) {
			continue // bounded to the same host
		}
		u := abs.String()
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// normalizeURL ensures the target has a scheme; bare host:443/:8443 imply https.
func normalizeURL(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	if strings.HasSuffix(target, ":443") || strings.HasSuffix(target, ":8443") {
		return "https://" + target
	}
	return "http://" + target
}
