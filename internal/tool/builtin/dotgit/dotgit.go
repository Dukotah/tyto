// Package dotgit detects an exposed .git directory — a common, high-impact
// misconfiguration that leaks full source history (and often secrets). It is
// content-validated, NOT status-only: many apps (SPAs, catch-all routers) return
// 200 for everything, so a bare 200 on /.git/HEAD means nothing. We confirm the
// response actually looks like a git HEAD/config before reporting.
package dotgit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "dotgit" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const maxBody = 16 << 10

// headRe matches a real .git/HEAD: a symbolic ref or a 40-hex commit.
var headRe = regexp.MustCompile(`^(ref:\s*refs/|[0-9a-f]{40}\s*$)`)

// gitConfigRe matches the unmistakable header of a .git/config file.
var gitConfigRe = regexp.MustCompile(`(?m)^\s*\[core\]`)

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	base := strings.TrimRight(normalizeURL(a.Target), "/")

	// Probe HEAD first (most diagnostic), then config for corroboration.
	headBody, headOK := t.fetchMatch(ctx, base+"/.git/HEAD", a.Cookie, headRe)
	cfgBody, cfgOK := t.fetchMatch(ctx, base+"/.git/config", a.Cookie, gitConfigRe)

	if headOK || cfgOK {
		evidence := headBody
		path := "/.git/HEAD"
		if !headOK {
			evidence, path = cfgBody, "/.git/config"
		}
		res.Findings = append(res.Findings, state.Finding{
			ID:       "DOTGIT-" + a.ID,
			Title:    "Exposed .git directory (source code disclosure)",
			Severity: state.SeverityHigh,
			Target:   base + path,
			Description: "the web root serves the project's .git metadata; an attacker can reconstruct the full " +
				"source tree and history (often including hardcoded secrets) with git-dumper or wget -r",
			Evidence:  firstLine(evidence),
			CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Tool:      t.Name(),
			Validated: true,
			FoundAt:   time.Now().UTC(),
		})
		res.Success = true
		res.Output = fmt.Sprintf("%s: .git EXPOSED (%s)", base, path)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	res.Findings = append(res.Findings, state.Finding{
		ID: "DOTGIT-" + a.ID, Title: "No exposed .git directory", Severity: state.SeverityInfo,
		Target: base, Description: "/.git/HEAD and /.git/config did not return git metadata", Tool: t.Name(), Validated: true, FoundAt: time.Now().UTC(),
	})
	res.Success = true
	res.Output = base + ": .git not exposed"
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// fetchMatch GETs url and reports the body + whether it matches re (content
// validation — a 200 with non-matching body is NOT a hit).
func (t *Tool) fetchMatch(ctx context.Context, url, cookie string, re *regexp.Regexp) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "tyto-dotgit")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	s := strings.TrimSpace(string(body))
	return s, re.MatchString(s)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
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
