package defaultcreds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// basicAuthServer returns a handler that 401s unless Basic auth matches the
// given user/pass.
func basicAuthServer(wantUser, wantPass string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != wantUser || p != wantPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("authenticated"))
	}
}

func findingTitles(res action.Result) map[string]state.Severity {
	out := map[string]state.Severity{}
	for _, f := range res.Findings {
		out[f.Title] = f.Severity
	}
	return out
}

func TestDefaultcredsAcceptsKnownPair(t *testing.T) {
	srv := httptest.NewServer(basicAuthServer("admin", "admin"))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}

	const want = "Default credentials accepted: admin/admin"
	titles := findingTitles(res)
	sev, ok := titles[want]
	if !ok {
		t.Fatalf("expected finding %q; got %v", want, titles)
	}
	if sev != state.SeverityHigh {
		t.Errorf("expected %q to be High, got %s", want, sev)
	}

	if len(res.Credentials) != 1 {
		t.Fatalf("expected exactly 1 recovered credential, got %d", len(res.Credentials))
	}
	c := res.Credentials[0]
	if c.Username != "admin" || c.Secret != "admin" || c.Kind != state.CredPassword {
		t.Errorf("unexpected credential: %+v", c)
	}
	if c.Source != "defaultcreds" {
		t.Errorf("expected Source defaultcreds, got %q", c.Source)
	}
}

func TestDefaultcredsRejectsStrongCred(t *testing.T) {
	// Requires a credential that is not in the built-in list.
	srv := httptest.NewServer(basicAuthServer("admin", "S3cret-N0t-Default!"))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}

	for _, f := range res.Findings {
		if f.Title == "Default credentials accepted: admin/admin" ||
			(len(f.Title) >= 28 && f.Title[:28] == "Default credentials accepted") {
			t.Fatalf("did not expect any accepted-credentials finding, got %q", f.Title)
		}
	}
	if len(res.Credentials) != 0 {
		t.Fatalf("expected no recovered credentials, got %d", len(res.Credentials))
	}
}

func TestDefaultcredsNoAuthToTest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a3", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}

	const want = "No HTTP authentication to test"
	titles := findingTitles(res)
	sev, ok := titles[want]
	if !ok {
		t.Fatalf("expected finding %q; got %v", want, titles)
	}
	if sev != state.SeverityInfo {
		t.Errorf("expected %q to be Info, got %s", want, sev)
	}
	if len(res.Credentials) != 0 {
		t.Fatalf("expected no credentials, got %d", len(res.Credentials))
	}
}

func TestDefaultcredsToolMetadata(t *testing.T) {
	tl := New()
	if tl.Name() != "defaultcreds" {
		t.Errorf("Name() = %q, want defaultcreds", tl.Name())
	}
	if tl.Category() != action.CategoryIdentity {
		t.Errorf("Category() = %v, want CategoryIdentity", tl.Category())
	}
	if tl.MaxRisk() != action.RiskHigh {
		t.Errorf("MaxRisk() = %v, want RiskHigh", tl.MaxRisk())
	}
}
