// Package ftpcheck is a built-in FTP banner grabber and anonymous-login probe.
// It is intentionally minimal — a single bounded conversation with one service,
// not a replacement for a full FTP auditor. The Scope Guard has already
// authorized any action that reaches Execute.
package ftpcheck

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool implements an FTP banner grab plus anonymous-login test.
type Tool struct{}

// New returns an ftpcheck Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "ftpcheck" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk implements tool.Tool. A single banner grab and anonymous login attempt
// is benign active contact.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const (
	dialTimeout = 6 * time.Second
	readTimeout = 5 * time.Second
)

// Execute dials the FTP service, records the banner, and tests anonymous login.
// A dial/read error is reported via res.Err/res.Output and returned as (res, nil)
// — not a tool error — unless the context was cancelled.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	addr := targetAddr(a.Target)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			res.FinishedAt = time.Now().UTC()
			res.Err = ctx.Err().Error()
			return res, ctx.Err()
		}
		res.Err = fmt.Sprintf("dial %s: %v", addr, err)
		res.Output = res.Err
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	defer conn.Close()

	r := bufio.NewReader(conn)

	// 1. Greeting — expect "220 ...".
	code, banner, err := readReply(conn, r)
	if err != nil {
		return readErr(res, "read greeting", err, ctx)
	}
	res.Findings = append(res.Findings, state.Finding{
		ID:          "F-" + a.ID + "-banner",
		Title:       "FTP banner: " + banner,
		Severity:    state.SeverityInfo,
		Target:      host,
		Description: fmt.Sprintf("FTP greeting from %s (code %d)", addr, code),
		Evidence:    banner,
		Tool:        t.Name(),
		FoundAt:     time.Now().UTC(),
	})

	// 2. USER anonymous — expect 331 (need password) or 230 (already in).
	if err := writeLine(conn, "USER anonymous"); err != nil {
		return readErr(res, "send USER", err, ctx)
	}
	userCode, _, err := readReply(conn, r)
	if err != nil {
		return readErr(res, "read USER reply", err, ctx)
	}

	anonymous := userCode == 230
	if userCode == 331 {
		// 3. PASS — supply a courtesy address; 230 means anonymous login allowed.
		if err := writeLine(conn, "PASS anonymous@example.com"); err != nil {
			return readErr(res, "send PASS", err, ctx)
		}
		passCode, passLine, err := readReply(conn, r)
		if err != nil {
			return readErr(res, "read PASS reply", err, ctx)
		}
		if passCode == 230 {
			anonymous = true
			res.Findings = append(res.Findings, state.Finding{
				ID:          "F-" + a.ID + "-anon",
				Title:       "Anonymous FTP login allowed",
				Severity:    state.SeverityMedium,
				Target:      host,
				Description: fmt.Sprintf("Server %s accepted anonymous credentials", addr),
				Evidence:    passLine,
				Tool:        t.Name(),
				Validated:   true,
				FoundAt:     time.Now().UTC(),
			})
		}
	}

	// 4. QUIT politely; ignore any error since we are tearing down.
	_ = writeLine(conn, "QUIT")

	res.Assets = append(res.Assets, state.Asset{
		ID:    addr,
		Type:  "service",
		Value: addr,
		Attrs: map[string]string{"service": "ftp"},
	})

	summary := fmt.Sprintf("ftp %s: banner %q", addr, banner)
	if anonymous {
		summary += "; anonymous login ALLOWED"
	} else {
		summary += "; anonymous login denied"
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// readErr finishes res for a dial/read/write failure. It returns a tool error
// only when the context was cancelled; otherwise the failure is data, not error.
func readErr(res action.Result, what string, err error, ctx context.Context) (action.Result, error) {
	res.FinishedAt = time.Now().UTC()
	if ctx.Err() != nil {
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	}
	res.Err = fmt.Sprintf("%s: %v", what, err)
	res.Output = res.Err
	return res, nil
}

// writeLine sends a CRLF-terminated FTP command with a write deadline so a wedged
// server can't block the tool.
func writeLine(conn net.Conn, line string) error {
	_ = conn.SetWriteDeadline(time.Now().Add(readTimeout))
	_, err := conn.Write([]byte(line + "\r\n"))
	return err
}

// readReply reads one CRLF-terminated line under a read deadline and parses the
// leading 3-digit FTP reply code. The returned line is trimmed of CRLF.
func readReply(conn net.Conn, r *bufio.Reader) (int, string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return 0, "", err
	}
	line = strings.TrimRight(line, "\r\n")
	code := parseCode(line)
	return code, line, nil
}

// parseCode extracts the leading 3-digit reply code, or 0 if the line does not
// start with one.
func parseCode(line string) int {
	if len(line) < 3 {
		return 0
	}
	d0, d1, d2 := line[0], line[1], line[2]
	if d0 < '0' || d0 > '9' || d1 < '0' || d1 > '9' || d2 < '0' || d2 > '9' {
		return 0
	}
	return int(d0-'0')*100 + int(d1-'0')*10 + int(d2-'0')
}

// targetAddr normalizes a target to host:port, defaulting to port 21 when no
// port is present (portscan style host extraction).
func targetAddr(target string) string {
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
	return net.JoinHostPort(t, "21")
}
