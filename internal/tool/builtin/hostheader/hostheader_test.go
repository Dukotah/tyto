package hostheader

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func titles(res action.Result) map[string]state.Severity {
	m := map[string]state.Severity{}
	for _, f := range res.Findings {
		m[f.Title] = f.Severity
	}
	return m
}

// effectiveHost returns the host the app would "trust" from a request, honoring
// X-Forwarded-Host / X-Forwarded-Server / X-Host / Forwarded over the real Host.
func effectiveHost(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-Server"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Host"); v != "" {
		return v
	}
	if v := r.Header.Get("Forwarded"); v != "" {
		// crude host= extraction, enough for the test
		for _, part := range strings.Split(v, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "host=") {
				return strings.TrimPrefix(part, "host=")
			}
		}
	}
	return r.Host
}

func TestExecuteFlagsBodyReflection(t *testing.T) {
	// Vulnerable: builds an absolute canonical link from the (spoofable) host.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := effectiveHost(r)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<link rel="canonical" href="https://` + h + `/page"/>`))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	got := titles(res)
	// Every header-based vector reflects here; at least one medium body finding.
	var foundMedium bool
	for title, sev := range got {
		if strings.Contains(title, "reflected in response body") {
			if sev != state.SeverityMedium {
				t.Errorf("body reflection should be medium, got %v", sev)
			}
			foundMedium = true
		}
	}
	if !foundMedium {
		t.Fatalf("expected a body-reflection finding, got %v", got)
	}
}

func TestExecuteFlagsLocationReflectionHigh(t *testing.T) {
	// Vulnerable: issues a redirect whose Location is built from the host.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := effectiveHost(r)
		w.Header().Set("Location", "https://"+h+"/reset?token=abc")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	var foundHigh bool
	for title, sev := range titles(res) {
		if strings.Contains(title, "reflected in Location redirect") {
			if sev != state.SeverityHigh {
				t.Errorf("location reflection should be high, got %v", sev)
			}
			foundHigh = true
		}
	}
	if !foundHigh {
		t.Fatalf("expected a high-severity Location-reflection finding, got %+v", res.Findings)
	}
}

func TestExecuteRefutesSafeApp(t *testing.T) {
	// Safe: always uses a fixed, hard-coded host — never reflects the request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<link rel="canonical" href="https://fixed.example/page"/>`))
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "a3", Target: srv.URL})
	for _, f := range res.Findings {
		t.Errorf("safe app must produce no findings, got %q", f.Title)
	}
	if !res.Success {
		t.Errorf("expected Success on a clean run")
	}
}

func TestExecuteDoesNotFollowRedirects(t *testing.T) {
	// If redirects were followed, this off-host redirect would error/chase; we
	// only inspect the first hop. The app reflects host into Location, so this
	// is also a positive Location case.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+effectiveHost(r)+"/next", http.StatusFound)
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a4", Target: srv.URL})
	if err != nil {
		t.Fatalf("execute should not error on a non-followed redirect: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Errorf("expected first-hop Location reflection to be detected")
	}
}
