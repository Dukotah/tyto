package redircheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func redirServer() *httptest.Server {
	mux := http.NewServeMux()
	// Open redirect: bounces the client to whatever `next` says.
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})
	// Safe: ignores the param entirely and returns 200.
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	return httptest.NewServer(mux)
}

func findingTitles(res action.Result) map[string]state.Severity {
	m := map[string]state.Severity{}
	for _, f := range res.Findings {
		m[f.Title] = f.Severity
	}
	return m
}

func TestRedircheckDetectsOpenRedirect(t *testing.T) {
	srv := redirServer()
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL + "/go?next=placeholder"})
	if err != nil {
		t.Fatal(err)
	}
	titles := findingTitles(res)
	if titles["Open redirect via parameter next"] != state.SeverityMedium {
		t.Errorf("expected MEDIUM open-redirect finding; got %v", titles)
	}
}

func TestRedircheckNoFalsePositiveOnSafeEndpoint(t *testing.T) {
	srv := redirServer()
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL + "/safe?next=placeholder"})
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "Open redirect") {
			t.Errorf("safe endpoint should not produce open-redirect findings, got %q", f.Title)
		}
	}
}

func TestRedircheckNoParams(t *testing.T) {
	srv := redirServer()
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "a3", Target: srv.URL + "/go"})
	if len(res.Findings) != 1 || res.Findings[0].Title != "No redirect parameters to test" {
		t.Fatalf("expected a single 'no parameters' note, got %+v", res.Findings)
	}
}
