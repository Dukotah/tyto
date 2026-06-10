package templatescan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func TestTemplatescanMatchesEmbeddedTemplates(t *testing.T) {
	// Serve a couple of paths the embedded starter pack checks for.
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("DB_PASSWORD=hunter2\nAPI_KEY=abc\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // everything else 404s
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}
	// The git-config exposure (a high-severity template) should match.
	var gitHit bool
	for _, f := range res.Findings {
		if strings.Contains(f.Target, "/.git/config") && f.Severity == state.SeverityHigh {
			gitHit = true
		}
		if !f.Validated {
			t.Errorf("template finding %q should be Validated", f.Title)
		}
	}
	if !gitHit {
		var got []string
		for _, f := range res.Findings {
			got = append(got, f.Title)
		}
		t.Fatalf("expected a high-severity /.git/config match; got %v", got)
	}
}

func TestTemplatescanCleanServerNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL})
	if len(res.Findings) != 0 {
		var got []string
		for _, f := range res.Findings {
			got = append(got, f.Title)
		}
		t.Fatalf("clean server should yield no template matches, got %v", got)
	}
}
