package cookieaudit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func TestFlagsUnderProtectedSessionCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A session cookie with NO hardening flags.
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "abc"})
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "c1", Target: srv.URL})
	var found bool
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "sessionid") && f.Severity == state.SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a MEDIUM finding for the unflagged session cookie, got %+v", res.Findings)
	}
}

func TestProperlyFlaggedCookieIsClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "x", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "c2", Target: srv.URL})
	for _, f := range res.Findings {
		if f.Severity == state.SeverityMedium || f.Severity == state.SeverityLow {
			t.Fatalf("a properly-flagged cookie produced a gap finding: %+v", f)
		}
	}
}
