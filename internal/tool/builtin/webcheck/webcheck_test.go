package webcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func TestWebcheckFlagsMissingHeaders(t *testing.T) {
	// A server with NO security headers and a versioned Server header.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		_, _ = w.Write([]byte("<html><title>hi</title>Index of /</html>"))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}

	titles := map[string]state.Severity{}
	for _, f := range res.Findings {
		if !f.Validated {
			t.Errorf("finding %q should be Validated (directly observed)", f.Title)
		}
		titles[f.Title] = f.Severity
	}
	for _, want := range []string{
		"Missing security header: Strict-Transport-Security",
		"Missing security header: Content-Security-Policy",
		"Server version disclosed",
		"Directory listing exposed",
	} {
		if _, ok := titles[want]; !ok {
			t.Errorf("expected finding %q; got %v", want, keys(titles))
		}
	}
}

func TestWebcheckQuietOnHardenedServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000")
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		_, _ = w.Write([]byte("<html><title>ok</title></html>"))
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL})
	if len(res.Findings) != 0 {
		var got []string
		for _, f := range res.Findings {
			got = append(got, f.Title)
		}
		t.Fatalf("hardened server should produce no findings, got: %s", strings.Join(got, "; "))
	}
}

func keys(m map[string]state.Severity) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
