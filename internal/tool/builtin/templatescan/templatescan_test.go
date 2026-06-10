package templatescan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestTemplatescanLoadsDiskTemplates(t *testing.T) {
	// A server that exposes a custom path only a disk template knows about.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/custom-leak" {
			_, _ = w.Write([]byte("CUSTOM-MARKER-12345"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dir := t.TempDir()
	tmpl := `
id: custom-disk-template
info:
  name: Custom Disk Template
  severity: high
  description: Loaded from disk via TYTO_TEMPLATES.
http:
  - method: GET
    path:
      - "{{BaseURL}}/custom-leak"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["CUSTOM-MARKER-12345"]
`
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(tmpl), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TYTO_TEMPLATES", dir)

	res, err := New().Execute(context.Background(), action.Action{ID: "a3", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}
	var found bool
	for _, f := range res.Findings {
		if f.Title == "Custom Disk Template" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected disk template to match; output=%q findings=%+v", res.Output, res.Findings)
	}
	if !strings.Contains(res.Output, "from disk") {
		t.Errorf("output missing disk count: %q", res.Output)
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
