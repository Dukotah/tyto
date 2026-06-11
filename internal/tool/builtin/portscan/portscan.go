// Package portscan is a built-in TCP connect scanner. It is intentionally
// simple and bounded — a real capability to prove the plugin path end-to-end,
// not a replacement for nmap. The Scope Guard has already authorized any action
// that reaches Execute.
package portscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool implements a TCP connect port scan.
type Tool struct{}

// New returns a portscan Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "portscan" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk implements tool.Tool.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

// defaultPorts is a small, common set scanned when none are specified.
var defaultPorts = []int{21, 22, 23, 25, 53, 80, 88, 110, 143, 389, 443, 445, 636, 3268, 3306, 3389, 8080, 8443}

// Execute runs the scan. Supported params: "ports" (comma-separated list).
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	host := hostOf(a.Target)
	ports := defaultPorts
	if p, ok := a.Params["ports"]; ok && p != "" {
		if parsed := parsePorts(p); len(parsed) > 0 {
			ports = parsed
		}
	}

	dialer := net.Dialer{Timeout: 800 * time.Millisecond}
	var open []int
	for _, port := range ports {
		select {
		case <-ctx.Done():
			res.FinishedAt = time.Now().UTC()
			res.Err = ctx.Err().Error()
			return res, ctx.Err()
		default:
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			open = append(open, port)
			_ = conn.Close()
		}
	}
	sort.Ints(open)

	// The host is recorded as an asset once contacted, even with no open ports.
	res.Assets = append(res.Assets, state.Asset{ID: host, Type: "host", Value: host})

	summary := fmt.Sprintf("host %s: %d/%d scanned ports open", host, len(open), len(ports))
	if len(open) > 0 {
		summary += fmt.Sprintf(" %v", open)
		res.Findings = append(res.Findings, state.Finding{
			ID:          "F-" + a.ID,
			Title:       fmt.Sprintf("%d open TCP port(s) on %s", len(open), host),
			Severity:    state.SeverityInfo,
			Target:      host,
			Description: fmt.Sprintf("Open TCP ports discovered: %v", open),
			Evidence:    summary,
			Tool:        t.Name(),
			FoundAt:     time.Now().UTC(),
		})
		// One service asset per open port. service is resolved from OUR port map,
		// not from any data the target controls, so it is safe for the frontier.
		for _, port := range open {
			res.Assets = append(res.Assets, state.Asset{
				ID:    net.JoinHostPort(host, strconv.Itoa(port)),
				Type:  "service",
				Value: net.JoinHostPort(host, strconv.Itoa(port)),
				Attrs: map[string]string{"port": strconv.Itoa(port), "service": serviceName(port)},
			})
		}
	}

	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

func parsePorts(s string) []int {
	var ports []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if n, err := strconv.Atoi(f); err == nil && n > 0 && n < 65536 {
			ports = append(ports, n)
		}
	}
	return ports
}

// serviceName maps a well-known port to a coarse service label. Deterministic
// and tyto-controlled (never derived from target-supplied banner data), so it is
// safe to surface to the planner via the frontier. "" means unrecognized.
func serviceName(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 88:
		return "kerberos"
	case 80, 8080:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 389, 3268:
		return "ldap"
	case 443, 8443:
		return "https"
	case 445:
		return "smb"
	case 636:
		return "ldaps"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	default:
		return ""
	}
}

// hostOf strips scheme/path/port from a target to get a dialable host.
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
