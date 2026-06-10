package tlscheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
)

func TestTLSCheckFlagsSelfSignedCert(t *testing.T) {
	// httptest TLS server uses a self-signed cert for a non-127.0.0.1 name.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}

	titles := map[string]bool{}
	for _, f := range res.Findings {
		if !f.Validated {
			t.Errorf("finding %q should be validated", f.Title)
		}
		titles[f.Title] = true
	}
	if !titles["Self-signed TLS certificate"] {
		t.Errorf("expected self-signed finding; got %v", titles)
	}
	// httptest serves modern TLS only, so no deprecated-version finding.
	if titles["Deprecated TLS version supported"] {
		t.Error("httptest server should not report deprecated TLS support")
	}
}

func TestTLSCheckNoTLSIsNotFatal(t *testing.T) {
	// A plain (non-TLS) target: the handshake fails, reported but not an error.
	res, err := New().Execute(context.Background(), action.Action{ID: "a2", Target: "127.0.0.1:1"})
	if err != nil {
		t.Fatalf("handshake failure should not be a tool error: %v", err)
	}
	if res.Success {
		t.Fatal("a failed TLS handshake should not report success")
	}
}

func TestDialTarget(t *testing.T) {
	cases := map[string][2]string{
		"https://example.com/x": {"example.com:443", "example.com"},
		"example.com:8443":      {"example.com:8443", "example.com"},
		"10.0.0.1":              {"10.0.0.1:443", "10.0.0.1"},
	}
	for in, want := range cases {
		addr, host := dialTarget(in)
		if addr != want[0] || host != want[1] {
			t.Errorf("dialTarget(%q) = (%q,%q), want (%q,%q)", in, addr, host, want[0], want[1])
		}
	}
}

func TestTLSVersionName(t *testing.T) {
	if !strings.Contains(tlsVersionName(0x0304), "1.3") {
		t.Error("expected TLS 1.3 name")
	}
}
