package cmdexec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// rceServer simulates a host vulnerable to command injection: it reflects the
// injected value AND "executes" the marker-wrapped commands, returning their
// output between the markers (as a real shelling-out app would).
func rceServer() *httptest.Server {
	fake := map[string]string{
		"whoami":   "root",
		"hostname": "victim-01",
		"id":       "uid=0(root) gid=0(root) groups=0(root)",
		"uname -a": "Linux victim-01 5.15.0 x86_64 GNU/Linux",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("host")
		body := "PING " + v + "\n" // reflects the literal payload (contains "echo MARK")
		if strings.Contains(v, markStart) {
			for cmd, out := range fake {
				if strings.Contains(v, cmd) {
					body += markStart + "\n" + out + "\n" + markEnd + "\n"
				}
			}
		}
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		// Reflects input but never executes anything.
		_, _ = w.Write([]byte("hello " + r.URL.Query().Get("host")))
	})
	return httptest.NewServer(mux)
}

func TestCmdexecConfirmsRCEAndCapturesOutput(t *testing.T) {
	srv := rceServer()
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL + "/ping?host=1"})
	if err != nil {
		t.Fatal(err)
	}
	var rce *state.Finding
	for i := range res.Findings {
		if strings.HasPrefix(res.Findings[i].Title, "Remote command execution") {
			rce = &res.Findings[i]
		}
	}
	if rce == nil {
		t.Fatalf("expected an RCE finding, got %+v", res.Findings)
	}
	if rce.Severity != state.SeverityCritical || !rce.Validated || rce.CVSS == "" {
		t.Fatalf("RCE finding should be Critical+Validated+CVSS: %+v", rce)
	}
	// The captured output must contain real command results.
	if !strings.Contains(rce.Evidence, "root") || !strings.Contains(rce.Evidence, "victim-01") {
		t.Fatalf("RCE evidence missing captured command output:\n%s", rce.Evidence)
	}
}

func TestCmdexecNoFalsePositiveOnReflectiveOnly(t *testing.T) {
	srv := rceServer()
	defer srv.Close()

	// /safe reflects input but never executes — no marker output, so no RCE.
	res, _ := New().Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL + "/safe?host=1"})
	for _, f := range res.Findings {
		if strings.HasPrefix(f.Title, "Remote command execution") {
			t.Fatalf("reflection without execution must not be flagged as RCE: %+v", f)
		}
	}
}
