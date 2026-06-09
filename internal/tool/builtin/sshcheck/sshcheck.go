// Package sshcheck is a built-in SSH banner grabber and assessor. On connect an
// SSH server immediately emits an identification string (RFC 4253 §4.2); this
// tool reads that single line and flags an obsolete protocol or an outdated
// OpenSSH version. It is a single benign banner grab, not a full audit. The
// Scope Guard has already authorized any action that reaches Execute.
package sshcheck

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool implements an SSH banner grab and assessment.
type Tool struct{}

// New returns an sshcheck Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "sshcheck" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk implements tool.Tool. A single banner grab is benign active contact.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const (
	dialTimeout = 6 * time.Second
	readTimeout = 5 * time.Second
	// bannerCap bounds how much we read so a hostile/non-SSH peer can't make us
	// buffer unboundedly when no newline ever arrives.
	bannerCap = 512
)

// openSSHVersion extracts the OpenSSH major/minor from an identification string,
// e.g. "OpenSSH_8.9p1" -> ("8","9").
var openSSHVersion = regexp.MustCompile(`OpenSSH[_-]([0-9]+)\.([0-9]+)`)

// Execute grabs and assesses the SSH banner at a.Target (host:port, port 22 by
// default). A dial/read error is reported via res.Err/res.Output and returned as
// (res, nil) — it is data about the target, not a tool failure. Only a cancelled
// context returns a non-nil error.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	target := addrOf(a.Target)
	host, _, _ := net.SplitHostPort(target)

	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		if ctx.Err() != nil {
			res.FinishedAt = time.Now().UTC()
			res.Err = ctx.Err().Error()
			return res, ctx.Err()
		}
		res.Output = fmt.Sprintf("ssh %s: dial failed: %v", target, err)
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	banner, err := readBanner(conn)
	if err != nil && banner == "" {
		if ctx.Err() != nil {
			res.FinishedAt = time.Now().UTC()
			res.Err = ctx.Err().Error()
			return res, ctx.Err()
		}
		res.Output = fmt.Sprintf("ssh %s: read failed: %v", target, err)
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Service asset for the contacted endpoint.
	res.Assets = append(res.Assets, state.Asset{
		ID:    target,
		Type:  "service",
		Value: target,
		Attrs: map[string]string{"service": "ssh"},
	})

	now := time.Now().UTC()

	// Obsolete SSH protocol 1.x. "SSH-1.99" advertises 1.x compatibility from a
	// 2.0-capable server and is NOT obsolete, so it is excluded.
	if strings.HasPrefix(banner, "SSH-1.") && !strings.HasPrefix(banner, "SSH-1.99") {
		res.Findings = append(res.Findings, state.Finding{
			ID:          "F-" + a.ID + "-proto1",
			Title:       "Obsolete SSH protocol 1.x supported",
			Severity:    state.SeverityHigh,
			Target:      target,
			Description: fmt.Sprintf("Host %s offers the cryptographically broken SSH protocol version 1.x.", host),
			Evidence:    banner,
			Tool:        t.Name(),
			Validated:   true,
			FoundAt:     now,
		})
	}

	// Outdated OpenSSH (< 7.4).
	if m := openSSHVersion.FindStringSubmatch(banner); m != nil {
		major, _ := strconv.Atoi(m[1])
		minor, _ := strconv.Atoi(m[2])
		if major < 7 || (major == 7 && minor < 4) {
			res.Findings = append(res.Findings, state.Finding{
				ID:          "F-" + a.ID + "-oldver",
				Title:       "Outdated OpenSSH version (<7.4)",
				Severity:    state.SeverityMedium,
				Target:      target,
				Description: fmt.Sprintf("Host %s runs OpenSSH %d.%d, older than 7.4; known fixed vulnerabilities may apply.", host, major, minor),
				Evidence:    banner,
				Tool:        t.Name(),
				Validated:   true,
				FoundAt:     now,
			})
		}
	}

	// Always emit the raw banner as an informational finding.
	res.Findings = append(res.Findings, state.Finding{
		ID:          "F-" + a.ID + "-banner",
		Title:       "SSH banner: " + banner,
		Severity:    state.SeverityInfo,
		Target:      target,
		Description: fmt.Sprintf("SSH service on %s presented an identification string.", host),
		Evidence:    banner,
		Tool:        t.Name(),
		Validated:   true,
		FoundAt:     now,
	})

	res.Success = true
	res.Output = fmt.Sprintf("ssh %s: %s", target, banner)
	res.FinishedAt = now
	return res, nil
}

// readBanner reads one line (up to bannerCap bytes, ending at '\n') from the SSH
// server and returns it with trailing CR/LF trimmed.
func readBanner(conn net.Conn) (string, error) {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if len(line) > bannerCap {
		line = line[:bannerCap]
	}
	line = strings.TrimRight(line, "\r\n")
	return line, err
}

// addrOf turns a target into a dialable host:port, defaulting the port to 22.
// It strips any scheme and path the way portscan's hostOf does.
func addrOf(target string) string {
	t := target
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if _, _, err := net.SplitHostPort(t); err == nil {
		return t
	}
	return net.JoinHostPort(t, "22")
}
