// Package smbenum is a Phase-5 internal/AD adapter that enumerates SMB shares
// (and optionally users) via an EXTERNAL tool — NetExec (nxc/netexec) or its
// predecessor CrackMapExec. It is a runtime-detected shell-out: tyto stays
// pure-Go and offline by default, so if no such tool is installed this adapter
// DEGRADES GRACEFULLY (emits an info finding and succeeds) rather than failing.
//
// It is identity-category and RiskMedium, so the Scope Guard gates it before
// Execute is ever reached. The live shell-out path is only taken when an
// operator has installed one of the supported tools.
package smbenum

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool implements an external SMB/AD enumeration adapter.
type Tool struct{}

// New returns an smbenum Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "smbenum" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryIdentity }

// MaxRisk implements tool.Tool.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

// maxOutput caps captured combined output to keep memory bounded (~256KB).
const maxOutput = 256 * 1024

// candidates are the external tools probed via exec.LookPath, in order.
var candidates = []string{"nxc", "netexec", "crackmapexec"}

// Execute detects an external SMB enumeration tool and runs it against the
// target host. With no tool installed it degrades gracefully to a single info
// finding and Success=true. A tool that is present but fails is reported in
// res.Output (still returning a nil error).
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	host := hostOf(a.Target)

	bin := detectTool()
	if bin == "" {
		res.Findings = append(res.Findings, state.Finding{
			ID:          "F-" + a.ID,
			Title:       "No SMB enumeration tool installed (install netexec/crackmapexec) — optional adapter",
			Severity:    state.SeverityInfo,
			Target:      host,
			Description: "smbenum is a runtime-detected shell-out adapter. None of nxc/netexec/crackmapexec were found on PATH, so SMB/AD enumeration was skipped. Install NetExec to enable it.",
			Evidence:    "exec.LookPath: nxc/netexec/crackmapexec not found",
			Tool:        t.Name(),
			FoundAt:     time.Now().UTC(),
		})
		res.Success = true
		res.Output = "no SMB enumeration tool installed; skipped (graceful degrade)"
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

	args := []string{"smb", host, "--shares"}
	if u := a.Params["users"]; u == "true" || u == "1" {
		args = append(args, "--users")
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	raw, runErr := cmd.CombinedOutput()
	out := string(raw)
	if len(out) > maxOutput {
		out = out[:maxOutput]
	}

	findings, assets := parseSMB(out)
	// Stamp IDs/host/tool on parsed findings (parseSMB is host-agnostic so it
	// stays purely unit-testable on a raw string).
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

	// Always record the SMB host/service asset so the planner can pivot.
	res.Assets = append(res.Assets, state.Asset{
		ID:    net.JoinHostPort(host, "445"),
		Type:  "service",
		Value: net.JoinHostPort(host, "445"),
		Attrs: map[string]string{"port": "445", "service": "smb", "tool": bin},
	})

	summary := fmt.Sprintf("%s smb %s --shares: %d share finding(s)", bin, host, len(findings))
	if runErr != nil {
		// Tool present but failed (auth required, host down, etc.). Not an error
		// from tyto's perspective — report it and move on.
		summary += fmt.Sprintf(" — tool error: %v", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// detectTool returns the first supported SMB enumeration binary found on PATH,
// or "" if none is installed.
func detectTool() string {
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil && p != "" {
			return c
		}
	}
	return ""
}

// parseSMB best-effort parses NetExec/CrackMapExec `smb ... --shares` output
// into findings (one per discovered share) plus a host asset. It is deliberately
// tolerant of formatting variation and host-agnostic so it can be unit-tested on
// a captured sample without the external tool present.
//
// NetExec/CME lines look like:
//
//	SMB  10.0.0.5  445  DC01  [*] Windows Server 2019 ... (name:DC01) (domain:corp.local) ...
//	SMB  10.0.0.5  445  DC01  [+] corp.local\user:pass (Pwn3d!)
//	SMB  10.0.0.5  445  DC01  Share           Permissions     Remark
//	SMB  10.0.0.5  445  DC01  -----           -----------     ------
//	SMB  10.0.0.5  445  DC01  ADMIN$          READ,WRITE      Remote Admin
//	SMB  10.0.0.5  445  DC01  IPC$            READ            Remote IPC
func parseSMB(output string) ([]state.Finding, []state.Asset) {
	var findings []state.Finding
	var assets []state.Asset

	var ip, hostname string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 || !strings.EqualFold(fields[0], "SMB") {
			continue
		}
		// fields: SMB <ip> <port> <hostname> <rest...>
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

		// Banner / status lines (start with a [*]/[+]/[-] status marker) are not
		// share rows; skip them for share extraction.
		first := rest[0]
		if strings.HasPrefix(first, "[") {
			continue
		}
		// Header / separator rows.
		lower := strings.ToLower(first)
		if lower == "share" || strings.HasPrefix(first, "---") {
			continue
		}

		shareName := first
		perms := ""
		comment := ""
		if len(rest) >= 2 {
			perms = rest[1]
		}
		if len(rest) >= 3 {
			comment = strings.Join(rest[2:], " ")
		}

		sev := state.SeverityInfo
		if strings.Contains(strings.ToUpper(perms), "WRITE") {
			sev = state.SeverityLow
		}

		title := fmt.Sprintf("SMB share: %s (%s)", shareName, perms)
		desc := fmt.Sprintf("SMB share %q on %s (%s) permissions=%q", shareName, hostname, ip, perms)
		if comment != "" {
			desc += " comment=" + comment
		}
		findings = append(findings, state.Finding{
			Title:       title,
			Severity:    sev,
			Description: desc,
			Evidence:    strings.TrimSpace(line),
			Validated:   true,
		})
	}

	if ip != "" {
		attrs := map[string]string{"port": "445", "service": "smb"}
		if hostname != "" {
			attrs["hostname"] = hostname
		}
		assets = append(assets, state.Asset{
			ID:    net.JoinHostPort(ip, "445"),
			Type:  "service",
			Value: net.JoinHostPort(ip, "445"),
			Attrs: attrs,
		})
	}
	return findings, assets
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
