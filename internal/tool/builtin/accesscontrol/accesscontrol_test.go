package accesscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

const sessionCookie = "session=secret-token"

func findTitle(fs []state.Finding, substr string) *state.Finding {
	for i := range fs {
		if strings.Contains(fs[i].Title, substr) {
			return &fs[i]
		}
	}
	return nil
}

// TestExecuteFlagsMissingAuth: the endpoint serves the same protected resource
// to authenticated AND anonymous requests => BAC flag.
func TestExecuteFlagsMissingAuth(t *testing.T) {
	body := strings.Repeat("account balance statement transactions history detail row ", 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignores the cookie entirely: no auth enforcement.
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{
		ID: "a1", Target: srv.URL + "/account", Cookie: sessionCookie,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}
	f := findTitle(res.Findings, "without authentication")
	if f == nil {
		t.Fatalf("expected missing-auth finding, got %+v", titles(res.Findings))
	}
	if !f.Validated {
		t.Errorf("BAC finding should be Validated")
	}
}

// TestExecuteRefutesEnforcedAuth: anonymous requests get a 401 => no BAC finding.
func TestExecuteRefutesEnforcedAuth(t *testing.T) {
	body := strings.Repeat("account balance statement transactions history detail row ", 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{
		ID: "a2", Target: srv.URL + "/account", Cookie: sessionCookie,
	})
	if err != nil {
		t.Fatal(err)
	}
	if f := findTitle(res.Findings, "without authentication"); f != nil {
		t.Fatalf("auth is enforced; should not flag BAC, got %q", f.Description)
	}
}

// TestExecuteFlagsIDOR: id=41 and id=42 return distinct valid records; the
// server enforces session auth (so BAC is refuted) but does NOT scope objects
// to the session => IDOR flag on the `id` param.
func TestExecuteFlagsIDOR(t *testing.T) {
	records := map[string]string{
		"41": "id 41 name alice role member email alice@example.com city portland status active balance 100",
		"42": "id 42 name bob role member email bob@example.com city portland status active balance 250",
		"43": "id 43 name carol role member email carol@example.com city portland status active balance 75",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") == "" { // auth enforced (so BAC refuted)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		id := r.URL.Query().Get("id")
		rec, ok := records[id]
		if !ok {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Error: record not found"))
			return
		}
		_, _ = w.Write([]byte(rec))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{
		ID: "a3", Target: srv.URL + "/profile?id=41", Cookie: sessionCookie,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}
	if f := findTitle(res.Findings, "without authentication"); f != nil {
		t.Fatalf("auth enforced; BAC should be refuted, got %q", f.Description)
	}
	f := findTitle(res.Findings, "IDOR")
	if f == nil {
		t.Fatalf("expected IDOR finding, got %+v", titles(res.Findings))
	}
	if !strings.Contains(f.Title, "id") {
		t.Errorf("IDOR finding should name the param: %q", f.Title)
	}
}

// TestExecuteRefutesScopedObjects: the server returns "forbidden" for any id
// other than the session's own => no IDOR finding.
func TestExecuteRefutesScopedObjects(t *testing.T) {
	own := "id 41 name alice role member email alice@example.com city portland status active balance 100"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		if r.URL.Query().Get("id") != "41" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("403 Forbidden: access denied to this object"))
			return
		}
		_, _ = w.Write([]byte(own))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{
		ID: "a4", Target: srv.URL + "/profile?id=41", Cookie: sessionCookie,
	})
	if err != nil {
		t.Fatal(err)
	}
	if f := findTitle(res.Findings, "IDOR"); f != nil {
		t.Fatalf("objects are scoped; IDOR should be refuted, got %q", f.Description)
	}
}

// TestExecuteNoCookieHonestNote: without a session cookie, the auth-vs-anon
// check must be skipped honestly (note in Output), not flagged.
func TestExecuteNoCookieHonestNote(t *testing.T) {
	body := strings.Repeat("public landing page content here marketing copy ", 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{
		ID: "a5", Target: srv.URL + "/page",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}
	if f := findTitle(res.Findings, "without authentication"); f != nil {
		t.Fatalf("no cookie => auth-vs-anon must be skipped, not flagged: %q", f.Description)
	}
	if !strings.Contains(res.Output, "no session cookie") {
		t.Errorf("expected honest skip note in output, got %q", res.Output)
	}
}

func titles(fs []state.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Title)
	}
	return out
}
