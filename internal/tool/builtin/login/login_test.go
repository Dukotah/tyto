package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
)

// findingTitled reports whether any finding's title contains sub.
func findingTitled(res action.Result, sub string) bool {
	for _, f := range res.Findings {
		if strings.Contains(f.Title, sub) {
			return true
		}
	}
	return false
}

func TestFormLoginSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		if r.PostForm.Get("username") == "admin" && r.PostForm.Get("password") == "admin" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{
		ID:     "a1",
		Target: srv.URL,
		Params: map[string]string{"username": "admin", "password": "admin", "login_url": srv.URL + "/login"},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Errorf("Success = false, want true")
	}
	if res.Session == nil {
		t.Fatalf("res.Session is nil, want a session")
	}
	if !strings.Contains(res.Session.Cookie, "session=abc123") {
		t.Errorf("Session.Cookie = %q, want it to contain %q", res.Session.Cookie, "session=abc123")
	}
	if !findingTitled(res, "Authenticated session established") {
		t.Errorf("missing 'session established' finding; got %+v", res.Findings)
	}
	if len(res.Credentials) != 1 {
		t.Fatalf("len(Credentials) = %d, want 1", len(res.Credentials))
	}
	if c := res.Credentials[0]; c.Username != "admin" || c.Secret != "admin" || c.Source != "login" {
		t.Errorf("Credential = %+v, want admin/admin from login", c)
	}
}

func TestFormLoginWrongPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("username") == "admin" && r.PostForm.Get("password") == "admin" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{
		ID:     "a2",
		Target: srv.URL,
		Params: map[string]string{"username": "admin", "password": "wrong", "login_url": srv.URL + "/login"},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if res.Session != nil {
		t.Errorf("res.Session = %+v, want nil on failed login", res.Session)
	}
	if !findingTitled(res, "Login failed") {
		t.Errorf("missing 'Login failed' finding; got %+v", res.Findings)
	}
	if len(res.Credentials) != 0 {
		t.Errorf("len(Credentials) = %d, want 0 on failure", len(res.Credentials))
	}
}

func TestBasicLoginSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tl := New()
	res, err := tl.Execute(context.Background(), action.Action{
		ID:     "a3",
		Target: srv.URL,
		Params: map[string]string{"username": "admin", "password": "secret", "mode": "basic"},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Errorf("Success = false, want true")
	}
	if res.Session == nil {
		t.Fatalf("res.Session is nil, want a session on basic-auth success")
	}
	if res.Session.Cookie != "" {
		t.Errorf("Session.Cookie = %q, want empty for basic mode", res.Session.Cookie)
	}
	if !findingTitled(res, "Authenticated session established") {
		t.Errorf("missing 'session established' finding; got %+v", res.Findings)
	}
	if len(res.Credentials) != 1 {
		t.Errorf("len(Credentials) = %d, want 1", len(res.Credentials))
	}

	// Wrong password -> failure, no session.
	bad, err := tl.Execute(context.Background(), action.Action{
		ID:     "a4",
		Target: srv.URL,
		Params: map[string]string{"username": "admin", "password": "nope", "mode": "basic"},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if bad.Session != nil {
		t.Errorf("res.Session = %+v, want nil on bad basic creds", bad.Session)
	}
	if !findingTitled(bad, "Login failed") {
		t.Errorf("missing 'Login failed' finding; got %+v", bad.Findings)
	}
}

func TestToolMetadata(t *testing.T) {
	tl := New()
	if tl.Name() != "login" {
		t.Errorf("Name() = %q, want login", tl.Name())
	}
	if tl.Category() != action.CategoryIdentity {
		t.Errorf("Category() = %v, want CategoryIdentity", tl.Category())
	}
	if tl.MaxRisk() != action.RiskMedium {
		t.Errorf("MaxRisk() = %v, want RiskMedium", tl.MaxRisk())
	}
}
