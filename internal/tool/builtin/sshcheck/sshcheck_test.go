package sshcheck

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// mockSSHServer starts a TCP listener that writes the given identification
// string to the first connection it accepts, then closes. It returns the
// listener address (host:port) and a cleanup func.
func mockSSHServer(t *testing.T, banner string) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(banner))
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// findingTitled reports whether any finding has the given title (substring) and
// severity.
func hasFinding(findings []state.Finding, titlePrefix string, sev state.Severity) bool {
	for _, f := range findings {
		if strings.HasPrefix(f.Title, titlePrefix) && f.Severity == sev {
			return true
		}
	}
	return false
}

func run(t *testing.T, banner string) action.Result {
	t.Helper()
	addr, cleanup := mockSSHServer(t, banner)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := New().Execute(ctx, action.Action{ID: "A1", Target: addr})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got Err=%q Output=%q", res.Err, res.Output)
	}
	// Findings carry Target = host:port (the dialed listener address).
	for _, f := range res.Findings {
		if f.Target != addr {
			t.Fatalf("finding Target = %q, want %q", f.Target, addr)
		}
	}
	return res
}

func TestCurrentVersion_BannerOnly(t *testing.T) {
	res := run(t, "SSH-2.0-OpenSSH_7.4\r\n")

	if !hasFinding(res.Findings, "SSH banner:", state.SeverityInfo) {
		t.Errorf("expected info banner finding; got %#v", res.Findings)
	}
	if hasFinding(res.Findings, "Outdated OpenSSH", state.SeverityMedium) {
		t.Errorf("7.4 should NOT be flagged as outdated")
	}
	if hasFinding(res.Findings, "Obsolete SSH protocol", state.SeverityHigh) {
		t.Errorf("2.0 should NOT be flagged as obsolete protocol")
	}
	// banner must be CRLF-trimmed.
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, "\r") || strings.Contains(f.Evidence, "\n") {
			t.Errorf("evidence not trimmed: %q", f.Evidence)
		}
		if !f.Validated {
			t.Errorf("finding %q not Validated", f.Title)
		}
	}
}

func TestOutdatedVersion_Medium(t *testing.T) {
	res := run(t, "SSH-2.0-OpenSSH_6.6p1\r\n")

	if !hasFinding(res.Findings, "Outdated OpenSSH version (<7.4)", state.SeverityMedium) {
		t.Errorf("expected MEDIUM outdated-version finding; got %#v", res.Findings)
	}
	if !hasFinding(res.Findings, "SSH banner:", state.SeverityInfo) {
		t.Errorf("expected info banner finding to always appear")
	}
}

func TestObsoleteProtocol1x_High(t *testing.T) {
	res := run(t, "SSH-1.5-OpenSSH_3.0\r\n")

	if !hasFinding(res.Findings, "Obsolete SSH protocol 1.x supported", state.SeverityHigh) {
		t.Errorf("expected HIGH obsolete-protocol finding; got %#v", res.Findings)
	}
	if !hasFinding(res.Findings, "SSH banner:", state.SeverityInfo) {
		t.Errorf("expected info banner finding to always appear")
	}
}

func TestSSH199_NotFlaggedAsObsolete(t *testing.T) {
	res := run(t, "SSH-1.99-OpenSSH_3.0\r\n")

	if hasFinding(res.Findings, "Obsolete SSH protocol", state.SeverityHigh) {
		t.Errorf("SSH-1.99 (2.0-compatible) must NOT be flagged as obsolete")
	}
	if !hasFinding(res.Findings, "SSH banner:", state.SeverityInfo) {
		t.Errorf("expected info banner finding")
	}
}

func TestDialError_NotAToolError(t *testing.T) {
	// Reserve a port by listening, capture its address, then close so dials fail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := New().Execute(ctx, action.Action{ID: "A2", Target: addr})
	if err != nil {
		t.Fatalf("dial failure should not be a tool error, got %v", err)
	}
	if res.Success {
		t.Errorf("expected Success=false on dial failure")
	}
	if res.Err == "" {
		t.Errorf("expected res.Err to be populated on dial failure")
	}
}

func TestAddrOf_DefaultsPort22(t *testing.T) {
	cases := map[string]string{
		"example.com":            "example.com:22",
		"ssh://example.com":      "example.com:22",
		"example.com:2222":       "example.com:2222",
		"http://example.com/foo": "example.com:22",
		"10.0.0.1":               "10.0.0.1:22",
	}
	for in, want := range cases {
		if got := addrOf(in); got != want {
			t.Errorf("addrOf(%q) = %q, want %q", in, got, want)
		}
	}
}
