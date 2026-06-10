package ssti

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// vulnServer "evaluates" the {{...}} (Jinja2/Twig) and ${...} template forms by
// replacing the wrapped arithmetic with its product, but returns the literal
// control string (and any other text) unchanged.
func vulnServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/render", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Naive template engine: evaluate the two common expression wrappers.
		q = strings.ReplaceAll(q, "{{1337*1337}}", "1788569")
		q = strings.ReplaceAll(q, "${1337*1337}", "1788569")
		_, _ = w.Write([]byte("<html>welcome, " + q + "</html>"))
	})
	return httptest.NewServer(mux)
}

// safeServer reflects the parameter verbatim — it never evaluates the
// expression, so the body contains `{{1337*1337}}` literally and never the
// product. The control (literal `1337*1337`) is also echoed verbatim.
func safeServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/render", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>welcome, " + r.URL.Query().Get("q") + "</html>"))
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

func TestSSTIDetectsTemplateInjection(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL + "/render?q=test"})
	if err != nil {
		t.Fatal(err)
	}
	titles := findingTitles(res)
	if titles["Server-Side Template Injection in parameter q"] != state.SeverityHigh {
		t.Fatalf("expected HIGH SSTI finding for param q; got %v", titles)
	}
	var f *state.Finding
	for i := range res.Findings {
		if res.Findings[i].Title == "Server-Side Template Injection in parameter q" {
			f = &res.Findings[i]
			break
		}
	}
	if f == nil {
		t.Fatal("SSTI finding not present")
	}
	if !f.Validated {
		t.Errorf("SSTI finding should be Validated:true")
	}
	if f.CVSS != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("unexpected CVSS vector: %q", f.CVSS)
	}
	if !strings.Contains(f.Evidence, "1788569") {
		t.Errorf("evidence should contain the reflected result, got %q", f.Evidence)
	}
}

func TestSSTINoFalsePositiveOnReflectingServer(t *testing.T) {
	srv := safeServer()
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL + "/render?q=test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "Template Injection") {
			t.Errorf("server that reflects the payload literally should not produce an SSTI finding, got %q", f.Title)
		}
	}
}

func TestSSTINoParams(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a3", Target: srv.URL + "/render"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Title != "No parameters to test for SSTI" {
		t.Fatalf("expected a single 'no parameters' note, got %+v", res.Findings)
	}
	if res.Findings[0].Severity != state.SeverityInfo {
		t.Errorf("no-params finding should be SeverityInfo")
	}
}
