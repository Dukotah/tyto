package graphqlcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func sevExists(fs []state.Finding, sev state.Severity) bool {
	for _, f := range fs {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

func TestDetectsIntrospection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "q1", Target: srv.URL})
	if !sevExists(res.Findings, state.SeverityMedium) {
		t.Fatalf("expected MEDIUM finding for enabled introspection, got %+v", res.Findings)
	}
}

// TestCatchAllHTMLNotGraphQL ensures a server that 200s everything with HTML is
// not misreported as a GraphQL endpoint (the catch-all false-positive class).
func TestCatchAllHTMLNotGraphQL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>everything is 200 here</html>"))
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "q2", Target: srv.URL})
	if sevExists(res.Findings, state.SeverityMedium) {
		t.Fatalf("catch-all HTML was misdetected as GraphQL: %+v", res.Findings)
	}
}
