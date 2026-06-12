package spacrawl

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/action"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestExtractSurface_LinksFormsXHR feeds rendered SPA HTML to the pure extractor
// and asserts links, GET-form endpoints, and inline fetch endpoints are picked up
// while same-host scope and static-asset filtering hold.
func TestExtractSurface_LinksFormsXHR(t *testing.T) {
	start := mustURL(t, "http://app.test/")
	dom := `<html><body>
		<a href="/dashboard">dash</a>
		<a href="/search?q=foo">search</a>
		<a href="https://evil.test/steal?x=1">offsite</a>
		<a href="/bundle.js?v=2">asset</a>
		<form action="/find" method="get">
			<input name="term">
			<input name="page">
		</form>
		<form action="/login" method="post">
			<input name="user">
		</form>
		<script>
			fetch("/api/users?id=1");
			axios.get('https://app.test/api/orders?status=open');
			fetch("https://other.test/api/leak?k=1");
		</script>
	</body></html>`

	s := extractSurface(dom, start, start)

	// Links: same-host and offsite anchors are both recorded as raw links (scoping
	// is applied at the endpoint/follow layer, not the raw link list).
	if !contains(s.links, "/dashboard") || !contains(s.links, "/search?q=foo") {
		t.Fatalf("expected dashboard+search links, got %v", s.links)
	}

	// Same-host parameterized endpoints from anchors.
	if !contains(s.endpoints, "http://app.test/search?q=foo") {
		t.Errorf("missing anchor endpoint /search?q=foo: %v", s.endpoints)
	}
	// GET form → endpoint with placeholder params.
	if !contains(s.endpoints, "http://app.test/find?page=test&term=test") {
		t.Errorf("missing GET-form endpoint: %v", s.endpoints)
	}
	// Inline fetch endpoints (root-relative + same-host absolute).
	if !contains(s.endpoints, "http://app.test/api/users?id=1") {
		t.Errorf("missing inline fetch endpoint /api/users: %v", s.endpoints)
	}
	if !contains(s.endpoints, "https://app.test/api/orders?status=open") {
		t.Errorf("missing inline axios endpoint /api/orders: %v", s.endpoints)
	}

	// Off-host endpoints MUST be excluded by same-host scope.
	for _, ep := range s.endpoints {
		if strings.Contains(ep, "evil.test") || strings.Contains(ep, "other.test") {
			t.Errorf("off-host endpoint leaked into scope: %q", ep)
		}
	}
	// POST form must NOT become a GET endpoint.
	for _, ep := range s.endpoints {
		if strings.Contains(ep, "/login") {
			t.Errorf("POST form leaked as GET endpoint: %q", ep)
		}
	}
	// Static .js asset (even with query) must be dropped.
	for _, ep := range s.endpoints {
		if strings.Contains(ep, "bundle.js") {
			t.Errorf("static asset leaked as endpoint: %q", ep)
		}
	}
}

// TestExtractSurface_NoSurface confirms an empty SPA shell yields no endpoints.
func TestExtractSurface_NoSurface(t *testing.T) {
	start := mustURL(t, "http://app.test/")
	s := extractSurface(`<html><body><div id="root"></div></body></html>`, start, start)
	if len(s.endpoints) != 0 {
		t.Errorf("expected no endpoints from empty shell, got %v", s.endpoints)
	}
}

// fakeRenderer serves canned DOM per URL and records what it was asked to render.
type fakeRenderer struct {
	pages map[string]string
	err   error // when non-nil, every render fails (simulates no Chrome)
	calls int
}

func (f *fakeRenderer) render(ctx context.Context, u string, settle time.Duration, cookie string) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	if dom, ok := f.pages[u]; ok {
		return dom, nil
	}
	return "<html><body></body></html>", nil
}

// TestExecute_RendersAndEmitsAssets drives Execute with a fake browser across two
// linked pages and asserts endpoint assets + the info finding are produced.
func TestExecute_RendersAndEmitsAssets(t *testing.T) {
	fr := &fakeRenderer{pages: map[string]string{
		"http://app.test/": `<html><body>
			<a href="/products">products</a>
			<script>fetch("/api/me?id=1")</script>
		</body></html>`,
		"http://app.test/products": `<html><body>
			<a href="/products?cat=books">books</a>
		</body></html>`,
	}}
	tool := &Tool{render: fr}

	res, err := tool.Execute(context.Background(), action.Action{ID: "A1", Target: "http://app.test/"})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got output=%q", res.Output)
	}
	if fr.calls < 2 {
		t.Errorf("expected to render at least 2 pages, rendered %d", fr.calls)
	}

	got := map[string]bool{}
	for _, as := range res.Assets {
		if as.Type != "endpoint" {
			t.Errorf("unexpected asset type %q", as.Type)
		}
		got[as.Value] = true
	}
	for _, want := range []string{
		"http://app.test/api/me?id=1",
		"http://app.test/products?cat=books",
	} {
		if !got[want] {
			t.Errorf("missing expected endpoint asset %q (got %v)", want, got)
		}
	}

	// Exactly one info finding summarizing the crawl.
	var infoFindings int
	for _, f := range res.Findings {
		if strings.HasPrefix(f.ID, "SPACRAWL-") {
			infoFindings++
		}
	}
	if infoFindings != 1 {
		t.Errorf("expected 1 summary finding, got %d", infoFindings)
	}
}

// TestExecute_NoChromeGracefulDegrade asserts that a renderer that can't launch a
// browser produces an honest info result, Success=true, and never an error.
func TestExecute_NoChromeGracefulDegrade(t *testing.T) {
	fr := &fakeRenderer{err: errors.New("exec: \"chrome\": executable file not found in $PATH")}
	tool := &Tool{render: fr}

	res, err := tool.Execute(context.Background(), action.Action{ID: "A2", Target: "http://app.test/"})
	if err != nil {
		t.Fatalf("graceful degrade must not return an error, got %v", err)
	}
	if !res.Success {
		t.Fatalf("graceful degrade should report Success=true, output=%q", res.Output)
	}
	if len(res.Assets) != 0 {
		t.Errorf("expected no assets when browser is down, got %d", len(res.Assets))
	}
	if len(res.Findings) != 1 || !strings.Contains(strings.ToLower(res.Findings[0].Title), "headless browser unavailable") {
		t.Fatalf("expected single 'headless browser unavailable' info finding, got %+v", res.Findings)
	}
	if res.Findings[0].Severity.String() != "info" {
		t.Errorf("degrade finding should be info severity, got %s", res.Findings[0].Severity)
	}
}

// TestNewBindsNoBrowser ensures construction launches no browser and reports the
// expected guard-facing identity.
func TestNewBindsNoBrowser(t *testing.T) {
	tool := New()
	if tool.Name() != "spacrawl" {
		t.Errorf("Name = %q", tool.Name())
	}
	if tool.Category() != action.CategoryRecon {
		t.Errorf("Category = %v, want recon", tool.Category())
	}
	if tool.MaxRisk() != action.RiskLow {
		t.Errorf("MaxRisk = %v, want low", tool.MaxRisk())
	}
	if tool.render == nil {
		t.Error("expected a renderer bound, got nil")
	}
}

// TestIntParam covers the cap-parsing helper's bounds and fallbacks.
func TestIntParam(t *testing.T) {
	cases := []struct {
		in  string
		def int
		out int
	}{
		{"", 5, 5},
		{"3", 5, 3},
		{"0", 5, 5},
		{"-1", 5, 5},
		{"abc", 5, 5},
		{"99999", 7, 7}, // absurd → fall back to default
	}
	for _, c := range cases {
		if got := intParam(c.in, c.def); got != c.out {
			t.Errorf("intParam(%q,%d) = %d, want %d", c.in, c.def, got, c.out)
		}
	}
}
