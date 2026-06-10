package httpmethods

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func TestHTTPMethodsFlagsDangerousMethods(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST, PUT, DELETE, TRACE")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "m1", Target: srv.URL})
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
		if f.Target != srv.URL {
			t.Errorf("finding %q target = %q, want %q", f.Title, f.Target, srv.URL)
		}
		titles[f.Title] = f.Severity
	}

	want := map[string]state.Severity{
		"Dangerous HTTP method allowed: PUT":      state.SeverityMedium,
		"Dangerous HTTP method allowed: DELETE":   state.SeverityMedium,
		"HTTP TRACE enabled (Cross-Site Tracing)": state.SeverityMedium,
	}
	for title, sev := range want {
		got, ok := titles[title]
		if !ok {
			t.Errorf("expected finding %q; got %v", title, keys(titles))
			continue
		}
		if got != sev {
			t.Errorf("finding %q severity = %v, want %v", title, got, sev)
		}
	}
}

func TestHTTPMethodsQuietOnSafeServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// TRACE not supported -> respond non-200 so no XST finding.
		if r.Method == http.MethodTrace {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "m2", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		var got []string
		for _, f := range res.Findings {
			got = append(got, f.Title)
		}
		t.Fatalf("safe server should produce no dangerous-method findings, got: %s", strings.Join(got, "; "))
	}
}

func TestHTTPMethodsDetectsTraceReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodTrace {
			// Echo the request headers back, as a TRACE-supporting server does.
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("TRACE / HTTP/1.1\r\n" + traceHeader + ": " + traceValue + "\r\n"))
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "m3", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	titles := map[string]state.Severity{}
	for _, f := range res.Findings {
		titles[f.Title] = f.Severity
	}
	if sev, ok := titles["HTTP TRACE method reflects request (XST)"]; !ok {
		t.Fatalf("expected XST reflection finding; got %v", keys(titles))
	} else if sev != state.SeverityMedium {
		t.Fatalf("XST finding severity = %v, want medium", sev)
	}
}

func keys(m map[string]state.Severity) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
