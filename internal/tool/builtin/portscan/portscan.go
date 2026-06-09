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
func (t *Tool) Category() string { return "scan" }

// MaxRisk implements tool.Tool.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

// defaultPorts is a small, common set scanned when none are specified.
var defaultPorts = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443}

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
