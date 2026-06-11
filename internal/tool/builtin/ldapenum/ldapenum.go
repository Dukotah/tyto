// Package ldapenum is a Phase-5 internal/AD adapter that enumerates an Active
// Directory domain over LDAP via an EXTERNAL tool — NetExec (nxc/netexec) or its
// predecessor CrackMapExec. Like smbenum it is a runtime-detected shell-out:
// tyto stays pure-Go and offline by default, so with no such tool installed this
// adapter DEGRADES GRACEFULLY (emits an info finding and succeeds) rather than
// failing.
//
// It is read-only enumeration (users / groups / password policy), identity-category
// and RiskMedium, so the Scope Guard gates it before Execute is reached. When the
// engagement provides matching provisioned domain credentials the engine injects
// them (username/password params); otherwise the adapter attempts an anonymous
// bind and reports gracefully if the DC refuses it.
package ldapenum

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool implements an external LDAP/AD enumeration adapter.
type Tool struct{}

// New returns an ldapenum Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "ldapenum" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryIdentity }

// MaxRisk implements tool.Tool. Read-only directory enumeration is RiskMedium —
// it touches an authenticated/anonymous LDAP bind but modifies nothing.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

// maxOutput caps captured combined output to keep memory bounded (~256KB).
const maxOutput = 256 * 1024

// candidates are the external tools probed via exec.LookPath, in order.
var candidates = []string{"nxc", "netexec", "crackmapexec"}

// Execute detects an external LDAP enumeration tool and runs it against the
// target DC. With no tool installed it degrades gracefully to a single info
// finding and Success=true. A tool present but failing (e.g. anonymous bind
// refused) is reported in res.Output, still returning a nil error.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	host := hostOf(a.Target)

	bin := detectTool()
	if bin == "" {
		res.Findings = append(res.Findings, state.Finding{
			ID:          "F-" + a.ID,
			Title:       "No LDAP enumeration tool installed (install netexec/crackmapexec) — optional adapter",
			Severity:    state.SeverityInfo,
			Target:      host,
			Description: "ldapenum is a runtime-detected shell-out adapter. None of nxc/netexec/crackmapexec were found on PATH, so AD/LDAP enumeration was skipped. Install NetExec to enable it.",
			Evidence:    "exec.LookPath: nxc/netexec/crackmapexec not found",
			Tool:        t.Name(),
			FoundAt:     time.Now().UTC(),
		})
		res.Success = true
		res.Output = "no LDAP enumeration tool installed; skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Honor cancellation before launching the external process.
	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	// Auth: provisioned domain creds injected by the engine win; otherwise attempt
	// an anonymous bind. Domain is optional (NetExec infers it from the DC).
	args := []string{"ldap", host}
	user, pass := a.Params["username"], a.Params["password"]
	if user != "" {
		args = append(args, "-u", user, "-p", pass)
		if d := a.Params["domain"]; d != "" {
			args = append(args, "-d", d)
		}
	} else {
		// anonymous / null bind
		args = append(args, "-u", "", "-p", "")
	}
	args = append(args, "--users", "--groups", "--pass-pol")

	cmd := exec.CommandContext(ctx, bin, args...)
	raw, runErr := cmd.CombinedOutput()
	out := string(raw)
	if len(out) > maxOutput {
		out = out[:maxOutput]
	}

	findings, assets := parseLDAP(out)
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%s-%d", a.ID, i)
		if findings[i].Target == "" {
			findings[i].Target = host
		}
		findings[i].Tool = t.Name()
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = time.Now().UTC()
		}
	}
	res.Findings = append(res.Findings, findings...)
	res.Assets = append(res.Assets, assets...)

	// Always record the LDAP host/service asset so the planner can pivot to
	// roasting (kerberoast applies_to service:ldap).
	res.Assets = append(res.Assets, state.Asset{
		ID:    net.JoinHostPort(host, "389"),
		Type:  "service",
		Value: net.JoinHostPort(host, "389"),
		Attrs: map[string]string{"port": "389", "service": "ldap", "tool": bin},
	})

	summary := fmt.Sprintf("%s ldap %s: %d finding(s)", bin, host, len(findings))
	if runErr != nil {
		summary += fmt.Sprintf(" — tool error: %v", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// detectTool returns the first supported enumeration binary on PATH, or "".
func detectTool() string {
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil && p != "" {
			return c
		}
	}
	return ""
}

// parseLDAP best-effort parses NetExec/CrackMapExec `ldap ... --users --groups
// --pass-pol` output into findings (enumerated-users count, discovered groups,
// and any weak password-policy signals) plus a host asset. It is deliberately
// tolerant of formatting variation and host-agnostic so it can be unit-tested on
// a captured sample without the external tool present.
//
// NetExec LDAP lines look like:
//
//	LDAP  10.0.0.5  389  DC01  [*] Windows Server 2019 ... (name:DC01) (domain:corp.local)
//	LDAP  10.0.0.5  389  DC01  Administrator    badpwdcount: 0  ...
//	LDAP  10.0.0.5  389  DC01  Guest
//	LDAP  10.0.0.5  389  DC01  Minimum password length: 5
//	LDAP  10.0.0.5  389  DC01  Password Complexity Flags: 000000
func parseLDAP(output string) ([]state.Finding, []state.Asset) {
	var findings []state.Finding
	var assets []state.Asset

	var ip, hostname, domain string
	var users []string
	var groups []string
	minPwLen := -1
	complexityDisabled := false

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 || !strings.EqualFold(fields[0], "LDAP") {
			continue
		}
		// fields: LDAP <ip> <port> <hostname> <rest...>
		if ip == "" {
			ip = fields[1]
		}
		if hostname == "" {
			hostname = fields[3]
		}
		rest := fields[4:]
		if len(rest) == 0 {
			continue
		}
		restLine := strings.Join(rest, " ")
		lowerRest := strings.ToLower(restLine)

		// Banner/status line — pull the domain if present, then skip.
		if strings.HasPrefix(rest[0], "[") {
			if d := extractParen(restLine, "domain:"); d != "" {
				domain = d
			}
			continue
		}
		// Header/separator rows.
		if strings.HasPrefix(rest[0], "---") || strings.EqualFold(rest[0], "-Username-") {
			continue
		}

		// Password-policy signals.
		if strings.Contains(lowerRest, "minimum password length") {
			if n := lastInt(restLine); n >= 0 {
				minPwLen = n
			}
			continue
		}
		if strings.Contains(lowerRest, "password complexity") {
			// "Flags: 000000" (all zero) => complexity disabled.
			if strings.Contains(restLine, "000000") || strings.Contains(lowerRest, "disabled") {
				complexityDisabled = true
			}
			continue
		}
		if strings.HasPrefix(lowerRest, "total of records returned") {
			continue
		}

		// Group rows are tagged by NetExec with a "(group)" hint or a "Found group"
		// prefix depending on version; treat such lines as groups.
		if strings.Contains(lowerRest, "found group") || strings.HasPrefix(lowerRest, "group:") {
			groups = appendUnique(groups, sanitizeName(stripPrefixWords(rest, "found", "group:")))
			continue
		}

		// Otherwise the first token is a sAMAccountName (a user/principal).
		name := sanitizeName(rest[0])
		if name != "" {
			users = appendUnique(users, name)
		}
	}

	if len(users) > 0 {
		findings = append(findings, state.Finding{
			Title:       fmt.Sprintf("AD domain users enumerated (%d)", len(users)),
			Severity:    state.SeverityLow,
			Description: fmt.Sprintf("Enumerated %d domain principal(s) over LDAP: %s", len(users), strings.Join(capList(users, 50), ", ")),
			Evidence:    strings.Join(capList(users, 50), ", "),
			Validated:   true,
		})
	}
	if len(groups) > 0 {
		findings = append(findings, state.Finding{
			Title:       fmt.Sprintf("AD groups enumerated (%d)", len(groups)),
			Severity:    state.SeverityInfo,
			Description: fmt.Sprintf("Enumerated %d group(s) over LDAP: %s", len(groups), strings.Join(capList(groups, 50), ", ")),
			Evidence:    strings.Join(capList(groups, 50), ", "),
			Validated:   true,
		})
	}
	if minPwLen >= 0 && minPwLen < 8 {
		findings = append(findings, state.Finding{
			Title:       fmt.Sprintf("Weak domain password policy: minimum length %d", minPwLen),
			Severity:    state.SeverityMedium,
			Description: fmt.Sprintf("The domain password policy permits passwords as short as %d characters (recommend >= 12). Short minimums make password-spraying and offline cracking materially easier.", minPwLen),
			Evidence:    fmt.Sprintf("Minimum password length: %d", minPwLen),
			Validated:   true,
		})
	}
	if complexityDisabled {
		findings = append(findings, state.Finding{
			Title:       "Weak domain password policy: complexity disabled",
			Severity:    state.SeverityMedium,
			Description: "The domain password policy does not enforce complexity, allowing trivially guessable passwords.",
			Evidence:    "Password Complexity Flags: 000000",
			Validated:   true,
		})
	}

	if ip != "" {
		attrs := map[string]string{"port": "389", "service": "ldap"}
		if hostname != "" {
			attrs["hostname"] = hostname
		}
		if domain != "" {
			attrs["domain"] = domain
		}
		assets = append(assets, state.Asset{
			ID:    net.JoinHostPort(ip, "389"),
			Type:  "service",
			Value: net.JoinHostPort(ip, "389"),
			Attrs: attrs,
		})
	}
	return findings, assets
}

// --- small parse helpers ---------------------------------------------------

// extractParen pulls a value out of a "(key:value)" segment, e.g.
// extractParen("... (domain:corp.local) ...", "domain:") -> "corp.local".
func extractParen(s, key string) string {
	i := strings.Index(s, key)
	if i < 0 {
		return ""
	}
	rest := s[i+len(key):]
	if j := strings.IndexAny(rest, ") "); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// lastInt returns the last integer token in s, or -1 if none.
func lastInt(s string) int {
	out := -1
	for _, f := range strings.Fields(s) {
		if n, err := strconv.Atoi(strings.Trim(f, ":")); err == nil {
			out = n
		}
	}
	return out
}

// sanitizeName trims punctuation noise from an enumerated principal/group name.
func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, ":,()[]")
	// Drop obvious non-name tokens.
	if s == "" || strings.HasPrefix(s, "[") || strings.EqualFold(s, "badpwdcount") {
		return ""
	}
	return s
}

func stripPrefixWords(fields []string, drop ...string) string {
	var kept []string
	for _, f := range fields {
		skip := false
		for _, d := range drop {
			if strings.EqualFold(f, d) {
				skip = true
				break
			}
		}
		if !skip {
			kept = append(kept, f)
		}
	}
	if len(kept) == 0 {
		return ""
	}
	return kept[0]
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func capList(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	out := append([]string(nil), list[:n]...)
	return append(out, fmt.Sprintf("...(+%d more)", len(list)-n))
}

// hostOf strips scheme/path/port from a target to get a usable host.
func hostOf(target string) string {
	t := target
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
