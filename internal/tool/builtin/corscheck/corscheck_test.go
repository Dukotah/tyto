package corscheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func TestCorscheckFlagsReflectedOriginWithCredentials(t *testing.T) {
	// A server that reflects the request Origin into ACAO and allows credentials.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		_, _ = w.Write([]byte("ok"))
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
		if f.Target != res.Findings[0].Target {
			t.Errorf("finding target mismatch: %q", f.Target)
		}
		titles[f.Title] = f.Severity
	}

	const want = "CORS: arbitrary origin reflected with credentials"
	sev, ok := titles[want]
	if !ok {
		t.Fatalf("expected finding %q; got %v", want, keys(titles))
	}
	if sev != state.SeverityHigh {
		t.Errorf("expected %q to be High, got %s", want, sev)
	}
}

func TestCorscheckQuietWithoutCORSHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><title>ok</title></html>"))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		var got []string
		for _, f := range res.Findings {
			got = append(got, f.Title)
		}
		t.Fatalf("server with no CORS headers should produce no findings, got: %v", got)
	}
}

func keys(m map[string]state.Severity) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
