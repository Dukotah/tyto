package dotgit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func hasSev(fs []state.Finding, sev state.Severity) bool {
	for _, f := range fs {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

func TestDetectsExposedGit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "g1", Target: srv.URL})
	if !hasSev(res.Findings, state.SeverityHigh) {
		t.Fatalf("expected HIGH finding for exposed .git, got %+v", res.Findings)
	}
}

// TestCatchAll200IsNotAFalsePositive guards the failure mode that bit the SQLi
// tool: a server that returns 200 for everything must NOT be reported as exposed.
func TestCatchAll200IsNotAFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>SPA catch-all, always 200</html>"))
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "g2", Target: srv.URL})
	if hasSev(res.Findings, state.SeverityHigh) {
		t.Fatalf("catch-all 200 was misreported as exposed .git: %+v", res.Findings)
	}
}
