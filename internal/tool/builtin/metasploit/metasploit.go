// Package metasploit is an OPERATOR-DIRECTED exploitation adapter that drives a
// single, explicitly-named Metasploit module non-interactively via the EXTERNAL
// `msfconsole` binary. It is NOT autonomous mass-exploitation: it only ever runs
// the one module the planner/operator hands it in a.Params["module"] (e.g.
// "exploit/multi/http/..." or "auxiliary/scanner/..."), against the action's
// target, with operator-supplied options.
//
// It is the most intrusive tier — CategoryExploit / RiskHigh — so it only runs
// after tyto's Scope Guard confirms the target is in scope AND the engagement
// carries a cryptographic authorization grant for high-risk/exploit actions.
// Like every tyto shell-out adapter it is runtime-detected and DEGRADES
// GRACEFULLY: if msfconsole is not installed it emits a single info finding and
// succeeds rather than failing. msfconsole is invoked without an interactive
// shell — its resource script is passed through `-q -x` as a single bounded
// argument, and the module/options come from the planner's vetted params.
package metasploit

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool implements an external Metasploit single-module exploitation adapter.
type Tool struct{}

// New returns a metasploit Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "metasploit" }

// Category implements tool.Tool. Driving an exploit/auxiliary module is
// exploitation.
func (t *Tool) Category() action.Category { return action.CategoryExploit }

// MaxRisk implements tool.Tool. Running a Metasploit module against a live
// target is the intrusive ceiling; the Scope Guard gates it on a verified
// authorization grant before Execute is ever reached.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskHigh }

const (
	// maxFindings caps emitted findings so a chatty module (or crafted output)
	// can't balloon the result.
	maxFindings = 50
	// msfMaxOutput bounds captured msfconsole output. Modules can be verbose; a
	// few MiB is plenty to catch the session/positive lines we parse.
	msfMaxOutput = 4 << 20
	// sessionCVSS reflects full compromise: an opened session demonstrates
	// remote code execution / interactive access on the target.
	sessionCVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
)

// sessionRe matches Metasploit's "session opened" banner for either a
// Meterpreter or a command-shell session, capturing the module is left to the
// caller (the line itself is the evidence).
var sessionRe = regexp.MustCompile(`(?i)(Meterpreter|Command shell) session \d+ opened`)

// Execute requires an explicit a.Params["module"], detects msfconsole, and — if
// present — runs that one module non-interactively against the target, then
// parses the console output into findings. With no module param it emits an
// info finding and succeeds; with msfconsole not installed it degrades
// gracefully to a single info finding and Success=true.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	module := strings.TrimSpace(a.Params["module"])
	if module == "" {
		res.Findings = []state.Finding{{
			ID:          fmt.Sprintf("F-%s-0", a.ID),
			Title:       "metasploit adapter requires a 'module' param",
			Severity:    state.SeverityInfo,
			Target:      a.Target,
			Description: "metasploit is operator-directed: set a.Params[\"module\"] to the exact module to run (e.g. exploit/multi/http/..., auxiliary/scanner/...).",
			Tool:        t.Name(),
			Validated:   false,
			FoundAt:     time.Now().UTC(),
		}}
		res.Success = true
		res.Output = "metasploit skipped: no 'module' param supplied"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	bin := adapter.Detect("msfconsole")
	if bin == "" {
		res.Findings = []state.Finding{adapter.Missing("metasploit", a.Target, "apt install metasploit-framework")}
		res.Success = true
		res.Output = "msfconsole not available; module run skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Honor cancellation before launching the external process. (run also binds
	// ctx, so an in-flight module is killed on cancel too.)
	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	host := hostOf(a.Target)
	cmd := buildResourceCmd(module, host, a.Params["options"])

	out, runErr := adapter.Run(ctx, bin, []string{"-q", "-x", cmd}, msfMaxOutput)

	findings := parseMsf(out)
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%s-%d", a.ID, i)
		if findings[i].Target == "" {
			findings[i].Target = host
		}
		findings[i].Tool = t.Name()
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = time.Now().UTC()
		}
		// Stamp the module name into every finding's title for operator context
		// (parseMsf is module-agnostic so it stays purely unit-testable).
		findings[i].Title = strings.Replace(findings[i].Title, "<module>", module, 1)
	}
	res.Findings = append(res.Findings, findings...)

	summary := fmt.Sprintf("metasploit ran %s against %s: %d finding(s)", module, host, len(findings))
	if runErr != nil && len(findings) == 0 {
		summary = fmt.Sprintf("metasploit run error with no parseable output (%s): %v", module, runErr)
	} else if runErr != nil {
		summary += fmt.Sprintf(" (msfconsole exited non-zero: %v)", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// buildResourceCmd assembles the non-interactive msfconsole resource string:
//
//	use <module>; set RHOSTS <host>; <each option as `set K V`>;
//	set ConsoleLogging true; run; exit -y
//
// options is the operator-supplied "K=V;K2=V2" string; malformed pairs are
// skipped. It contains no shell metacharacters of its own — msfconsole receives
// it verbatim as a single argument (no shell is involved).
func buildResourceCmd(module, host, options string) string {
	var b strings.Builder
	b.WriteString("use ")
	b.WriteString(module)
	b.WriteString("; set RHOSTS ")
	b.WriteString(host)
	b.WriteString("; ")
	for _, pair := range strings.Split(options, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || k == "" {
			continue
		}
		b.WriteString("set ")
		b.WriteString(k)
		b.WriteString(" ")
		b.WriteString(v)
		b.WriteString("; ")
	}
	b.WriteString("set ConsoleLogging true; run; exit -y")
	return b.String()
}

// parseMsf best-effort parses msfconsole console output into findings. It is
// host/tool/module-agnostic (titles carry a "<module>" placeholder the caller
// substitutes) so it is purely unit-testable on a captured output string:
//
//   - "Meterpreter/Command shell session N opened" -> SeverityCritical,
//     Validated, with the session CVSS vector; this is the proof of impact.
//   - "[+]" lines              -> SeverityHigh (module success / a positive hit,
//     e.g. an auxiliary scanner reporting a vulnerable host).
//   - "[-]" lines / "Exploit completed, but no session was created"
//     -> a single SeverityInfo summary of the failure(s).
//   - nothing notable          -> a single SeverityInfo "ran; no result".
//
// Findings are capped at maxFindings.
func parseMsf(out string) []state.Finding {
	var findings []state.Finding
	var negatives []string
	noSession := false

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(strings.TrimSpace(raw), "\r")
		if line == "" {
			continue
		}

		if sessionRe.MatchString(line) {
			if len(findings) < maxFindings {
				findings = append(findings, state.Finding{
					Title:       "Metasploit session opened (<module>)",
					Severity:    state.SeverityCritical,
					Description: "A Metasploit module opened an interactive session on the target, proving remote access / code execution.",
					Evidence:    line,
					CVSS:        sessionCVSS,
					Validated:   true,
				})
			}
			continue
		}

		if strings.Contains(line, "Exploit completed, but no session was created") {
			noSession = true
			continue
		}

		// Strip a leading timestamp/prefix so the marker can be matched at the
		// start of the meaningful text (msfconsole sometimes prefixes lines).
		marker := markerOf(line)
		switch marker {
		case "+":
			if len(findings) < maxFindings {
				findings = append(findings, state.Finding{
					Title:       "Metasploit: " + line,
					Severity:    state.SeverityHigh,
					Description: "Metasploit reported a positive result (success / vulnerable host).",
					Evidence:    line,
					Validated:   true,
				})
			}
		case "-":
			negatives = append(negatives, line)
		}
	}

	// Summarize failures (explicit no-session and/or "[-]" lines) as a single
	// info finding, unless we already proved impact with a session.
	hasSession := false
	for _, f := range findings {
		if f.Severity == state.SeverityCritical {
			hasSession = true
			break
		}
	}
	if !hasSession && (noSession || len(negatives) > 0) {
		desc := "Metasploit module did not yield a session."
		if noSession {
			desc = "Exploit completed, but no session was created."
		}
		if len(negatives) > 0 {
			ev := negatives[0]
			if len(negatives) > 1 {
				ev = fmt.Sprintf("%s (+%d more)", ev, len(negatives)-1)
			}
			desc += " " + ev
		}
		if len(findings) < maxFindings {
			findings = append(findings, state.Finding{
				Title:       "Metasploit: no session / module unsuccessful (<module>)",
				Severity:    state.SeverityInfo,
				Description: desc,
				Evidence:    firstNonEmpty(negatives),
				Validated:   false,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, state.Finding{
			Title:       "Metasploit ran (<module>); no session/positive result",
			Severity:    state.SeverityInfo,
			Description: "The Metasploit module ran but produced no session and no positive ([+]) result.",
			Validated:   false,
		})
	}

	if len(findings) > maxFindings {
		findings = findings[:maxFindings]
	}
	return findings
}

// markerOf returns "+" or "-" if the line is a Metasploit positive/negative
// status line ("[+] ..." / "[-] ..."), else "". msfconsole status lines start
// with the bracketed marker.
func markerOf(line string) string {
	switch {
	case strings.HasPrefix(line, "[+]"):
		return "+"
	case strings.HasPrefix(line, "[-]"):
		return "-"
	default:
		return ""
	}
}

// firstNonEmpty returns the first non-empty string, or "".
func firstNonEmpty(vals []string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// hostOf strips scheme/path/port from a target to get a usable RHOSTS value.
// A URL like "http://h:8080/x" resolves to "h"; an ip/host passes through.
func hostOf(target string) string {
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
	return t
}
