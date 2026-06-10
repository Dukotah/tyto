package metasploit

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// sessionSample mimics msfconsole output where an exploit module landed a
// Meterpreter session and reported a couple of positive ([+]) lines.
const sessionSample = `[*] Started reverse TCP handler on 10.0.0.5:4444
[*] Sending stage (200774 bytes) to 10.0.0.9
[+] target appears vulnerable
[+] payload delivered
[*] Meterpreter session 1 opened (10.0.0.5:4444 -> 10.0.0.9:51010) at 2026-06-10
meterpreter > `

// noSessionSample mimics an exploit that fired but failed to land a session.
const noSessionSample = `[*] Started reverse TCP handler on 10.0.0.5:4444
[*] Sending exploit...
[-] Exploit aborted due to failure: unexpected-reply
[*] Exploit completed, but no session was created.`

func find(t *testing.T, fs []state.Finding, sev state.Severity, titleSub string) state.Finding {
	t.Helper()
	for _, f := range fs {
		if f.Severity == sev && strings.Contains(f.Title, titleSub) {
			return f
		}
	}
	t.Fatalf("no finding with severity %v and title containing %q; got %+v", sev, titleSub, fs)
	return state.Finding{}
}

func TestParseMsf_SessionOpened(t *testing.T) {
	fs := parseMsf(sessionSample)

	crit := find(t, fs, state.SeverityCritical, "session opened")
	if !crit.Validated {
		t.Errorf("session finding should be Validated, got %+v", crit)
	}
	if crit.CVSS != sessionCVSS {
		t.Errorf("session CVSS = %q, want %q", crit.CVSS, sessionCVSS)
	}
	if !strings.Contains(crit.Evidence, "Meterpreter session 1 opened") {
		t.Errorf("session evidence missing the session line: %q", crit.Evidence)
	}

	// The two [+] lines must both produce High findings.
	var highs int
	for _, f := range fs {
		if f.Severity == state.SeverityHigh && strings.HasPrefix(f.Title, "Metasploit: [+]") {
			highs++
		}
	}
	if highs != 2 {
		t.Errorf("got %d High [+] findings, want 2 (%+v)", highs, fs)
	}
}

func TestParseMsf_NoSession(t *testing.T) {
	fs := parseMsf(noSessionSample)

	for _, f := range fs {
		if f.Severity == state.SeverityCritical {
			t.Fatalf("did not expect a Critical finding for a no-session run: %+v", f)
		}
	}

	info := find(t, fs, state.SeverityInfo, "no session")
	if info.Validated {
		t.Errorf("no-session info finding should not be Validated: %+v", info)
	}
	if !strings.Contains(info.Description, "no session was created") {
		t.Errorf("info description should summarize the failure: %q", info.Description)
	}
}

func TestExecute_NoModuleParam(t *testing.T) {
	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: "10.0.0.9"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Errorf("Success should be true on the no-module path")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d (%+v)", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo || !strings.Contains(f.Title, "requires a 'module' param") {
		t.Errorf("unexpected no-module finding: %+v", f)
	}
}

func TestExecute_GracefulDegrade(t *testing.T) {
	// This host has no msfconsole on PATH, so Execute must degrade gracefully to
	// a single "metasploit not available" Info finding and still succeed. (If a
	// future CI image ships msfconsole this assertion would change; not the case
	// for the dev/test environment.)
	res, err := New().Execute(context.Background(), action.Action{
		ID:     "a2",
		Target: "10.0.0.9",
		Params: map[string]string{"module": "auxiliary/scanner/http/title"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Errorf("Success should be true on graceful-degrade")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d (%+v)", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo || !strings.Contains(f.Title, "metasploit not available") {
		t.Errorf("unexpected graceful-degrade finding: %+v", f)
	}
}

func TestBuildResourceCmd(t *testing.T) {
	cmd := buildResourceCmd("exploit/multi/http/x", "1.2.3.4", "LHOST=10.0.0.5;LPORT=4444")
	for _, want := range []string{
		"use exploit/multi/http/x;",
		"set RHOSTS 1.2.3.4;",
		"set LHOST 10.0.0.5;",
		"set LPORT 4444;",
		"set ConsoleLogging true;",
		"run; exit -y",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("resource cmd missing %q; got: %s", want, cmd)
		}
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"http://h:8080/x": "h",
		"1.2.3.4":         "1.2.3.4",
		"1.2.3.4:443":     "1.2.3.4",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
