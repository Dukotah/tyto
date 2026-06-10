// Package hydra drives the EXTERNAL thc-hydra binary for credential attacks
// against a network service (ssh, ftp, http-get, ...). Like every tyto
// shell-out adapter it is runtime-detected: tyto stays a pure-Go, offline-by-
// default binary, so if hydra is not installed this adapter DEGRADES GRACEFULLY
// (a single info finding + Success=true) rather than failing. The live attack
// path is only taken when an operator has hydra on PATH.
//
// It is identity/exploit-tier — Category identity, MaxRisk High — so the Scope
// Guard gates it before Execute is ever reached (it only runs after the target
// is confirmed in scope AND the engagement carries a verified high-risk
// authorization grant). It is deliberately LOCKOUT-CONSCIOUS: low parallelism
// (-t 4), stop on the first valid pair (-f), and a per-attempt wait (-w 5), so
// it behaves like a targeted check rather than an unbounded brute forcer.
// hydra is driven without a shell (args are a slice), so target/cred values can
// never inject flags. Any recovered credential is emitted as a quarantined
// Credential — the plaintext secret never reaches the model.
package hydra

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

// Tool implements an external thc-hydra credential-attack adapter.
type Tool struct{}

// New returns a hydra Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "hydra" }

// Category implements tool.Tool. Driving credential guesses against a service
// is an identity/credential operation.
func (t *Tool) Category() action.Category { return action.CategoryIdentity }

// MaxRisk implements tool.Tool. Authenticated brute force is intrusive, so the
// ceiling is High and the Scope Guard gates it behind a verified authorization
// grant.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskHigh }

// successLine matches a hydra "valid pair found" line, e.g.
//
//	[22][ssh] host: 10.0.0.5   login: admin   password: admin123
//
// host/login/password are captured; login and password may be empty.
var successLine = regexp.MustCompile(
	`\[\d+\]\[([^\]]+)\]\s+host:\s*(\S+)(?:\s+login:\s*(\S*))?(?:\s+password:\s*(\S*))?`)

// Execute resolves the host, validates that a service + at least one user
// source + one pass source were supplied, detects hydra, and — if present —
// runs a lockout-conscious `hydra ... -t 4 -f -w 5 <host> <service>`, parsing
// any recovered credentials. Missing params or a missing binary degrade
// gracefully to an info finding with Success=true.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	add := func(sev state.Severity, title, detail, evidence string) {
		res.Findings = append(res.Findings, state.Finding{
			ID:          fmt.Sprintf("HY-%s-%d", a.ID, len(res.Findings)),
			Title:       title,
			Severity:    sev,
			Target:      a.Target,
			Description: detail,
			Evidence:    evidence,
			Tool:        t.Name(),
			Validated:   sev == state.SeverityCritical,
		})
	}

	service := strings.TrimSpace(a.Params["service"])
	if service == "" {
		add(state.SeverityInfo, "hydra adapter requires a 'service' param",
			"hydra needs a service module (e.g. ssh, ftp, http-get) to attack; none was provided", "")
		res.Success = true
		res.Output = "hydra: no service param; nothing to attack"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	user := strings.TrimSpace(a.Params["user"])
	userlist := strings.TrimSpace(a.Params["userlist"])
	pass := strings.TrimSpace(a.Params["pass"])
	passlist := strings.TrimSpace(a.Params["passlist"])

	if (user == "" && userlist == "") || (pass == "" && passlist == "") {
		add(state.SeverityInfo, "hydra needs user(list) + pass(list)",
			"hydra requires at least one user source (user|userlist) AND one pass source (pass|passlist)", "")
		res.Success = true
		res.Output = "hydra: missing credential sources; nothing to attack"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	bin := adapter.Detect("hydra")
	if bin == "" {
		res.Findings = append(res.Findings, adapter.Missing("hydra", a.Target, "apt install hydra"))
		res.Success = true
		res.Output = "hydra not available; credential attack skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Honor cancellation before launching the external process. (adapter.Run also
	// binds ctx, so an in-flight attack is killed on cancel too.)
	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	host := hostOf(a.Target)

	// Build args without a shell. -l/-L user source, -p/-P pass source, then the
	// lockout-conscious knobs: -t 4 (low parallelism), -f (stop on first valid
	// pair), -w 5 (per-connect wait). Finally the host and the service module.
	args := []string{}
	if user != "" {
		args = append(args, "-l", user)
	} else {
		args = append(args, "-L", userlist)
	}
	if pass != "" {
		args = append(args, "-p", pass)
	} else {
		args = append(args, "-P", passlist)
	}
	args = append(args, "-t", "4", "-f", "-w", "5", host, service)

	out, _ := adapter.Run(ctx, bin, args, 1<<20)

	findings, creds := parseHydra(out)
	if len(findings) == 0 {
		add(state.SeverityInfo, "hydra ran; no valid credentials found",
			fmt.Sprintf("hydra completed against %s (%s) with no valid credentials recovered", host, service), "")
	} else {
		// Stamp IDs/host/tool on parsed findings (parseHydra stays host/tool-agnostic
		// so it can be unit-tested in isolation).
		for i := range findings {
			findings[i].ID = fmt.Sprintf("HY-%s-%d", a.ID, len(res.Findings)+i)
			findings[i].Tool = t.Name()
			if findings[i].Target == "" {
				findings[i].Target = a.Target
			}
		}
		res.Findings = append(res.Findings, findings...)
	}
	res.Credentials = append(res.Credentials, creds...)

	res.Success = true
	res.Output = fmt.Sprintf("hydra: %s (%s) — %d credential(s) recovered", host, service, len(creds))
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// parseHydra scans hydra output for "valid pair found" lines and returns one
// Critical finding + one Credential per recovered login. It is host/tool-
// agnostic (the caller stamps IDs/host/tool) so it can be unit-tested directly.
func parseHydra(out string) ([]state.Finding, []state.Credential) {
	var findings []state.Finding
	var creds []state.Credential

	for _, line := range strings.Split(out, "\n") {
		m := successLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		service, host, login, password := m[1], m[2], m[3], m[4]

		findings = append(findings, state.Finding{
			Title:       fmt.Sprintf("Valid credentials found (%s): %s:%s", service, login, password),
			Severity:    state.SeverityCritical,
			Target:      host,
			Description: fmt.Sprintf("hydra recovered a valid credential pair for service %s on %s", service, host),
			Evidence:    strings.TrimSpace(line),
			CVSS:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Validated:   true,
		})
		creds = append(creds, state.Credential{
			Kind:     state.CredPassword,
			Username: login,
			Secret:   password,
			Source:   "hydra",
			Target:   host,
		})
	}
	return findings, creds
}

// hostOf reduces a target (URL/host[:port]) to a bare host for hydra's
// positional host arg.
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
