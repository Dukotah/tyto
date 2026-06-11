package apidocs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func sev(fs []state.Finding, s state.Severity) bool {
	for _, f := range fs {
		if f.Severity == s {
			return true
		}
	}
	return false
}

func TestDetectsExposedSwagger(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"swagger":"2.0","info":{"title":"API"},"paths":{}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL})
	if !sev(res.Findings, state.SeverityLow) {
		t.Fatalf("expected LOW finding for exposed swagger, got %+v", res.Findings)
	}
}

func TestCatchAll200NotMisdetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>catch-all 200</html>"))
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL})
	if sev(res.Findings, state.SeverityLow) {
		t.Fatalf("catch-all HTML misdetected as API docs: %+v", res.Findings)
	}
}
