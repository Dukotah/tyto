package wafdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func titleSet(res action.Result) map[string]state.Severity {
	m := map[string]state.Severity{}
	for _, f := range res.Findings {
		m[f.Title] = f.Severity
	}
	return m
}

func keys(m map[string]state.Severity) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestWafdetectIdentifiesCloudflare(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("cf-ray", "abc123")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "cf1", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}

	titles := titleSet(res)
	sev, ok := titles["WAF/CDN detected: Cloudflare"]
	if !ok {
		t.Fatalf("expected Cloudflare detection, got %v", keys(titles))
	}
	if sev != state.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %v", sev)
	}
	for _, f := range res.Findings {
		if f.Title == "WAF/CDN detected: Cloudflare" && !f.Validated {
			t.Error("detection finding should be Validated")
		}
	}
}

func TestWafdetectGenericBlockBehavior(t *testing.T) {
	// 200 to a benign request, 403 when the query string carries a payload.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "g1", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	titles := titleSet(res)
	if _, ok := titles["Generic WAF behavior (blocks malicious requests)"]; !ok {
		t.Fatalf("expected generic WAF behavior finding, got %v", keys(titles))
	}
	if strings.Contains(strings.Join(keys(titles), "|"), "No WAF/CDN fingerprinted") {
		t.Error("should not emit the no-WAF finding when a signal was found")
	}
}

func TestWafdetectNoWAF(t *testing.T) {
	// Plain server: always 200, no signature headers, no block.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>hello</html>"))
	}))
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "n1", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly one finding, got %d: %v", len(res.Findings), keys(titleSet(res)))
	}
	f := res.Findings[0]
	if f.Title != "No WAF/CDN fingerprinted" {
		t.Errorf("expected no-WAF finding, got %q", f.Title)
	}
	if f.Severity != state.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %v", f.Severity)
	}
}
