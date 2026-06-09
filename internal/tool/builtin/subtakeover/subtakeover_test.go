package subtakeover

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// stubTool returns a Tool whose HTTP client targets the given httptest server
// and whose resolver is the system default (CNAME lookups of httptest's
// 127.0.0.1 host simply return no provider match — kept off the real network for
// the fingerprint assertions, which are the load-bearing paths here).
func stubTool(srv *httptest.Server) *Tool {
	return &Tool{
		http: srv.Client(),
		res:  net.DefaultResolver,
	}
}

func bodyServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
}

func findingByTitle(fs []state.Finding, title string) (state.Finding, bool) {
	for _, f := range fs {
		if f.Title == title {
			return f, true
		}
	}
	return state.Finding{}, false
}

func TestStaticToolMetadata(t *testing.T) {
	tl := New()
	if tl.Name() != "subtakeover" {
		t.Errorf("Name() = %q, want subtakeover", tl.Name())
	}
	if tl.Category() != action.CategoryScan {
		t.Errorf("Category() = %v, want CategoryScan", tl.Category())
	}
	if tl.MaxRisk() != action.RiskLow {
		t.Errorf("MaxRisk() = %v, want RiskLow", tl.MaxRisk())
	}
}

func TestExtractHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"sub.example.com", "sub.example.com"},
		{"https://sub.example.com/path", "sub.example.com"},
		{"http://sub.example.com:8443/x?y=1#z", "sub.example.com"},
		{"sub.example.com:443", "sub.example.com"},
		{"user@sub.example.com", "sub.example.com"},
		{"sub.example.com.", "sub.example.com"},
		{"127.0.0.1:8080", "127.0.0.1"},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := extractHost(c.in); got != c.want {
			t.Errorf("extractHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExecuteEmptyTarget(t *testing.T) {
	res, err := New().Execute(context.Background(), action.Action{ID: "e1", Target: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Errorf("expected Success=false for empty target")
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings for empty target, got %v", res.Findings)
	}
}

func TestGitHubPagesFingerprint(t *testing.T) {
	srv := bodyServer(t, "<html><body>There isn't a GitHub Pages site here.</body></html>")
	defer srv.Close()

	res, err := stubTool(srv).Execute(context.Background(), action.Action{ID: "gh", Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success, got Err=%q", res.Err)
	}

	f, ok := findingByTitle(res.Findings, "Possible subdomain takeover (GitHub Pages)")
	if !ok {
		t.Fatalf("missing GitHub Pages takeover finding; got %+v", res.Findings)
	}
	if f.Severity != state.SeverityHigh {
		t.Errorf("severity = %v, want High", f.Severity)
	}
	if !f.Validated {
		t.Errorf("takeover finding should be Validated")
	}
	if !strings.Contains(f.Evidence, "There isn't a GitHub Pages site here.") {
		t.Errorf("evidence should carry the matched fingerprint, got %q", f.Evidence)
	}
}

func TestAWSS3Fingerprint(t *testing.T) {
	srv := bodyServer(t, "<Error><Code>NoSuchBucket</Code></Error>")
	defer srv.Close()

	res, err := stubTool(srv).Execute(context.Background(), action.Action{ID: "s3", Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f, ok := findingByTitle(res.Findings, "Possible subdomain takeover (AWS S3)")
	if !ok {
		t.Fatalf("missing AWS S3 takeover finding; got %+v", res.Findings)
	}
	if f.Severity != state.SeverityHigh {
		t.Errorf("severity = %v, want High", f.Severity)
	}
	if !f.Validated {
		t.Errorf("takeover finding should be Validated")
	}
}

func TestNoFingerprint(t *testing.T) {
	srv := bodyServer(t, "<html><body>Welcome to a perfectly normal, claimed site.</body></html>")
	defer srv.Close()

	res, err := stubTool(srv).Execute(context.Background(), action.Action{ID: "ok", Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success, got Err=%q", res.Err)
	}

	if _, ok := findingByTitle(res.Findings, "No subdomain-takeover fingerprint detected"); !ok {
		t.Fatalf("missing the negative (info) finding; got %+v", res.Findings)
	}
	// And no HIGH finding should be present.
	for _, f := range res.Findings {
		if f.Severity == state.SeverityHigh {
			t.Errorf("unexpected HIGH finding on a clean body: %q", f.Title)
		}
	}
}

func TestConnectionError(t *testing.T) {
	srv := bodyServer(t, "x")
	url := srv.URL
	tl := stubTool(srv)
	srv.Close() // close so the request fails to connect

	res, err := tl.Execute(context.Background(), action.Action{ID: "ce", Target: url})
	if err != nil {
		t.Fatalf("connection error must return nil error, got %v", err)
	}
	if res.Success {
		t.Errorf("expected Success=false on connection error")
	}
	if res.Err == "" {
		t.Errorf("expected res.Err to be populated on connection error")
	}
}

// TestMatchCNAMEProvider exercises the CNAME-provider matching path without any
// real network: matchCNAMEProvider is the pure decision function the resolver's
// LookupCNAME result is fed into.
func TestMatchCNAMEProvider(t *testing.T) {
	cases := []struct{ cname, want string }{
		{"victim.github.io", "GitHub Pages"},
		{"github.io", "GitHub Pages"},
		{"my-bucket.s3.amazonaws.com", "AWS S3"},
		{"app.herokuapp.com", "Heroku"},
		{"shop.myshopify.com", "Shopify"},
		{"example.com", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := matchCNAMEProvider(c.cname); got != c.want {
			t.Errorf("matchCNAMEProvider(%q) = %q, want %q", c.cname, got, c.want)
		}
	}
}

func TestExecuteHonorsCancellation(t *testing.T) {
	srv := bodyServer(t, "There isn't a GitHub Pages site here.")
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := stubTool(srv).Execute(ctx, action.Action{ID: "cx", Target: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Cancelled before/at the request: the HTTP call should fail, yielding a
	// graceful non-success result rather than a panic or hang.
	_ = res
}
