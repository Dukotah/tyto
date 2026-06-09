package httpprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dukotah/tyto/internal/action"
)

func TestHTTPProbeFingerprints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "test-srv/2.0")
		_, _ = w.Write([]byte("<html><head><title>Login</title></head></html>"))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success || len(res.Assets) != 1 || res.Assets[0].Type != "url" {
		t.Fatalf("expected one url asset on success, got %+v", res.Assets)
	}
	if res.Assets[0].Attrs["server"] != "test-srv/2.0" || res.Assets[0].Attrs["title"] != "Login" {
		t.Fatalf("fingerprint attrs wrong: %+v", res.Assets[0].Attrs)
	}
	if len(res.Findings) != 1 || !res.Findings[0].Validated {
		t.Fatalf("expected one validated info finding, got %+v", res.Findings)
	}
}

func TestHTTPProbeConnectionErrorIsNotFatal(t *testing.T) {
	// Nothing listening on this port; probe should report, not error.
	res, err := New().Execute(context.Background(), action.Action{ID: "a2", Target: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("connection failure should not be a tool error: %v", err)
	}
	if res.Success {
		t.Fatal("probe of a dead port should not report success")
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"example.com":           "http://example.com",
		"example.com:443":       "https://example.com:443",
		"https://example.com/x": "https://example.com/x",
		"10.0.0.1:8443":         "https://10.0.0.1:8443",
	}
	for in, want := range cases {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}
