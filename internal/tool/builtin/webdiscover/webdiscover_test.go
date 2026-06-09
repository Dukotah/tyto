package webdiscover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// server that 404s unknown paths but exposes /.env and /server-status.
func discoverableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env", "/server-status", "/robots.txt":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestWebdiscoverFindsExposedPaths(t *testing.T) {
	srv := discoverableServer()
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}

	bySeverity := map[state.Severity]int{}
	titles := map[string]bool{}
	for _, f := range res.Findings {
		if !f.Validated {
			t.Errorf("finding %q should be validated", f.Title)
		}
		bySeverity[f.Severity]++
		titles[f.Title] = true
	}
	if !titles["Exposed path: /.env"] {
		t.Errorf("expected /.env finding; got %v", titles)
	}
	if !titles["Exposed path: /server-status"] {
		t.Errorf("expected /server-status finding; got %v", titles)
	}
	if bySeverity[state.SeverityHigh] == 0 {
		t.Error("expected a HIGH-severity finding for /.env")
	}
}

func TestWebdiscoverSkipsCatchAllServer(t *testing.T) {
	// Server returns 200 for everything -> discovery must bail with one info note.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL})
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Title, "unreliable") {
		t.Fatalf("catch-all server should yield one 'unreliable' note, got %+v", res.Findings)
	}
}

func TestWebdiscoverDeadPortNotFatal(t *testing.T) {
	res, err := New().Execute(context.Background(), action.Action{ID: "a3", Target: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("connection failure should not be a tool error: %v", err)
	}
	if res.Success {
		t.Fatal("dead port should not report success")
	}
}
