package ftpcheck

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// mockFTP starts a one-shot FTP server on 127.0.0.1 that speaks the standard
// greeting -> USER -> PASS -> QUIT dialogue. passReply is the line written in
// response to the PASS command (e.g. "230 Login successful." or
// "530 Login incorrect."). It returns the listener address; the listener closes
// after one connection.
func mockFTP(t *testing.T, passReply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(conn)

		_, _ = conn.Write([]byte("220 Welcome\r\n"))

		// Expect USER anonymous.
		userLine, _ := r.ReadString('\n')
		if !strings.HasPrefix(userLine, "USER ") {
			return
		}
		_, _ = conn.Write([]byte("331 Please specify the password.\r\n"))

		// Expect PASS ...
		passLine, _ := r.ReadString('\n')
		if !strings.HasPrefix(passLine, "PASS ") {
			return
		}
		_, _ = conn.Write([]byte(passReply + "\r\n"))

		// Drain QUIT and close.
		_, _ = r.ReadString('\n')
	}()
	return ln.Addr().String()
}

func findBy(findings []state.Finding, title string) (state.Finding, bool) {
	for _, f := range findings {
		if f.Title == title {
			return f, true
		}
	}
	return state.Finding{}, false
}

func TestExecuteAnonymousAllowed(t *testing.T) {
	addr := mockFTP(t, "230 Login successful.")

	tool := New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := tool.Execute(ctx, action.Action{ID: "A1", Target: addr})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got Err=%q Output=%q", res.Err, res.Output)
	}

	banner, ok := findBy(res.Findings, "FTP banner: 220 Welcome")
	if !ok {
		t.Fatalf("expected info banner finding; findings=%v", res.Findings)
	}
	if banner.Severity != state.SeverityInfo {
		t.Errorf("banner severity = %v, want info", banner.Severity)
	}
	if banner.Evidence != "220 Welcome" {
		t.Errorf("banner evidence = %q, want %q", banner.Evidence, "220 Welcome")
	}

	anon, ok := findBy(res.Findings, "Anonymous FTP login allowed")
	if !ok {
		t.Fatalf("expected anonymous-login finding; findings=%v", res.Findings)
	}
	if anon.Severity != state.SeverityMedium {
		t.Errorf("anon severity = %v, want medium", anon.Severity)
	}
	if !anon.Validated {
		t.Errorf("anon finding should be Validated")
	}
	if !strings.Contains(anon.Evidence, "230") {
		t.Errorf("anon evidence = %q, want it to contain the 230 line", anon.Evidence)
	}
}

func TestExecuteAnonymousDenied(t *testing.T) {
	addr := mockFTP(t, "530 Login incorrect.")

	tool := New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := tool.Execute(ctx, action.Action{ID: "A2", Target: addr})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got Err=%q Output=%q", res.Err, res.Output)
	}

	if _, ok := findBy(res.Findings, "FTP banner: 220 Welcome"); !ok {
		t.Fatalf("expected info banner finding; findings=%v", res.Findings)
	}
	if _, ok := findBy(res.Findings, "Anonymous FTP login allowed"); ok {
		t.Fatalf("did not expect anonymous-login finding when PASS is rejected")
	}
}

func TestTargetAddrDefaultsPort21(t *testing.T) {
	if got := targetAddr("ftp://example.com/pub"); got != "example.com:21" {
		t.Errorf("targetAddr = %q, want example.com:21", got)
	}
	if got := targetAddr("10.0.0.5:2121"); got != "10.0.0.5:2121" {
		t.Errorf("targetAddr = %q, want 10.0.0.5:2121", got)
	}
}
