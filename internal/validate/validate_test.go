package validate

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/state"
)

// fakeFetcher is a deterministic, no-network Fetcher. It maps a matcher
// function over the requested URL to a Response (or error), so each test
// declares exactly how the "live" target behaves on re-verification.
type fakeFetcher struct {
	// fn returns the response for a given URL. If it returns ok=false the
	// fetcher returns errUnreachable (simulating an unreachable target).
	fn func(rawURL string) (Response, bool)
}

var errUnreachable = errors.New("simulated: target unreachable")

func (f fakeFetcher) Fetch(_ context.Context, rawURL string) (Response, error) {
	if f.fn == nil {
		return Response{}, errUnreachable
	}
	resp, ok := f.fn(rawURL)
	if !ok {
		return Response{}, errUnreachable
	}
	return resp, nil
}

func hdr(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Set(pairs[i], pairs[i+1])
	}
	return h
}

// (a) A genuinely-reflected XSS is confirmed: the injected marker comes back
// verbatim in the response that has our marker in the query string.
func TestReflectedXSS_Confirmed(t *testing.T) {
	f := state.Finding{
		Title:  "Reflected XSS in parameter q",
		Target: "http://app.test/search?q=hello",
	}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		// Vulnerable app: echoes the raw q value into the body, unencoded.
		body := "<html>results for: " + valueOf(rawURL, "q") + "</html>"
		return Response{Status: 200, Header: hdr(), Body: body}, true
	}}
	v := New(ff)
	vd := v.Validate(context.Background(), f)
	if vd.Status != StatusConfirmed {
		t.Fatalf("expected confirmed, got %s (%s)", vd.Status, vd.Reason)
	}
	if !vd.Confirmed() {
		t.Fatal("Confirmed() should be true")
	}
	if vd.Class != ClassReflectedXSS {
		t.Fatalf("class = %s", vd.Class)
	}
}

// (b) A static page that merely echoes nothing (or a fixed, unrelated string)
// is refuted — no false positive. Baseline subtraction ensures a page that
// always contains some text but never our marker cannot confirm.
func TestReflectedXSS_RefutedNoReflection(t *testing.T) {
	f := state.Finding{
		Title:  "Reflected XSS in parameter q",
		Target: "http://static.test/page?q=hello",
	}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		// Static page: identical body regardless of input; never reflects q.
		return Response{Status: 200, Header: hdr(), Body: "<html>welcome to our site</html>"}, true
	}}
	v := New(ff)
	vd := v.Validate(context.Background(), f)
	if vd.Status != StatusRefuted {
		t.Fatalf("expected refuted, got %s (%s)", vd.Status, vd.Reason)
	}
	if vd.Confirmed() {
		t.Fatal("a non-reflecting static page must not be confirmed")
	}
}

// XSS that is HTML-encoded on reflection must NOT be confirmed (the literal
// marker with < > " is not present once encoded).
func TestReflectedXSS_EncodedEchoRefuted(t *testing.T) {
	f := state.Finding{Title: "Reflected XSS in parameter q", Target: "http://app.test/s?q=x"}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		raw := valueOf(rawURL, "q")
		enc := strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(raw)
		return Response{Status: 200, Header: hdr(), Body: "echo: " + enc}, true
	}}
	vd := New(ff).Validate(context.Background(), f)
	if vd.Status == StatusConfirmed {
		t.Fatalf("HTML-encoded reflection must not confirm; got %s", vd.Reason)
	}
}

// (c) A header present on re-fetch flips a 'missing-header' finding to refuted.
func TestMissingHeader_PresentOnRefetchRefuted(t *testing.T) {
	f := state.Finding{
		Title:  "Missing security header: Content-Security-Policy",
		Target: "https://app.test/",
	}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		return Response{Status: 200, Header: hdr("Content-Security-Policy", "default-src 'self'"), Body: ""}, true
	}}
	vd := New(ff).Validate(context.Background(), f)
	if vd.Status != StatusRefuted {
		t.Fatalf("expected refuted (header now present), got %s (%s)", vd.Status, vd.Reason)
	}
}

// Missing header that is genuinely still absent on re-fetch is confirmed.
func TestMissingHeader_AbsentConfirmed(t *testing.T) {
	f := state.Finding{
		Title:  "Missing security header: X-Frame-Options",
		Target: "https://app.test/",
	}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		// No X-Frame-Options present.
		return Response{Status: 200, Header: hdr("Server", "nginx"), Body: ""}, true
	}}
	vd := New(ff).Validate(context.Background(), f)
	if vd.Status != StatusConfirmed {
		t.Fatalf("expected confirmed (still missing), got %s (%s)", vd.Status, vd.Reason)
	}
}

// (d) A redacted/placeholder secret is refuted.
func TestExposedSecret_PlaceholderRefuted(t *testing.T) {
	f := state.Finding{
		Title:    "Exposed AWS access key ID",
		Target:   "app.test",
		Evidence: "found at https://app.test/config.js",
	}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		// Documentation/placeholder: AWS-shaped but obviously a placeholder.
		body := `const cfg = { awsKey: "AKIAXXXXXXXXXXXXXXXX", note: "replace with your key" };`
		return Response{Status: 200, Header: hdr(), Body: body}, true
	}}
	vd := New(ff).Validate(context.Background(), f)
	if vd.Status != StatusRefuted {
		t.Fatalf("expected refuted (placeholder), got %s (%s)", vd.Status, vd.Reason)
	}
}

// A genuinely-exposed, well-formed secret still present is confirmed.
func TestExposedSecret_RealConfirmed(t *testing.T) {
	f := state.Finding{
		Title:    "Exposed AWS access key ID",
		Target:   "app.test",
		Evidence: "found at https://app.test/app.js",
	}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		body := `var k = "AKIA1B2C3D4E5F6G7H8I"; // real-looking key`
		return Response{Status: 200, Header: hdr(), Body: body}, true
	}}
	vd := New(ff).Validate(context.Background(), f)
	if vd.Status != StatusConfirmed {
		t.Fatalf("expected confirmed (real secret), got %s (%s)", vd.Status, vd.Reason)
	}
	if strings.Contains(vd.Evidence, "AKIA1B2C3D4E5F6G7H8I") {
		t.Fatalf("evidence must be redacted, leaked full secret: %s", vd.Evidence)
	}
}

// Secret that is simply gone on re-fetch is refuted (no live exposure).
func TestExposedSecret_GoneRefuted(t *testing.T) {
	f := state.Finding{Title: "Exposed API key", Target: "app.test", Evidence: "https://app.test/app.js"}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		return Response{Status: 200, Header: hdr(), Body: "// cleaned up, no secrets here"}, true
	}}
	vd := New(ff).Validate(context.Background(), f)
	if vd.Status != StatusRefuted {
		t.Fatalf("expected refuted (secret gone), got %s (%s)", vd.Status, vd.Reason)
	}
}

// Error-based SQLi: a DB error appears only after injecting a quote -> confirmed.
func TestErrorSQLi_Confirmed(t *testing.T) {
	f := state.Finding{
		Title:  "SQL injection (error-based) in parameter id",
		Target: "http://app.test/item?id=5",
	}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		v := valueOf(rawURL, "id")
		if strings.Contains(v, "'") {
			return Response{Status: 500, Header: hdr(), Body: "You have an error in your SQL syntax near ''"}, true
		}
		return Response{Status: 200, Header: hdr(), Body: "item 5 ok"}, true
	}}
	vd := New(ff).Validate(context.Background(), f)
	if vd.Status != StatusConfirmed {
		t.Fatalf("expected confirmed, got %s (%s)", vd.Status, vd.Reason)
	}
}

// Error-based SQLi where the page ALWAYS shows a DB error (baseline) -> refuted.
func TestErrorSQLi_AlwaysErroringRefuted(t *testing.T) {
	f := state.Finding{
		Title:  "SQL injection (error-based) in parameter id",
		Target: "http://app.test/item?id=5",
	}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		// Broken page: shows a SQL error even with no injection.
		return Response{Status: 500, Header: hdr(), Body: "Warning: mysqli_query(): SQL syntax error"}, true
	}}
	vd := New(ff).Validate(context.Background(), f)
	if vd.Status != StatusRefuted {
		t.Fatalf("expected refuted (always-erroring), got %s (%s)", vd.Status, vd.Reason)
	}
}

// Error-based SQLi with no error after injection -> refuted.
func TestErrorSQLi_NoErrorRefuted(t *testing.T) {
	f := state.Finding{Title: "SQL injection (error-based) in parameter id", Target: "http://app.test/item?id=5"}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		return Response{Status: 200, Header: hdr(), Body: "ok, no errors"}, true
	}}
	vd := New(ff).Validate(context.Background(), f)
	if vd.Status != StatusRefuted {
		t.Fatalf("expected refuted (no error), got %s (%s)", vd.Status, vd.Reason)
	}
}

// Unreachable target -> inconclusive, never confirmed (refute-by-default).
func TestUnreachableInconclusive(t *testing.T) {
	f := state.Finding{Title: "Reflected XSS in parameter q", Target: "http://down.test/x?q=1"}
	ff := fakeFetcher{fn: func(string) (Response, bool) { return Response{}, false }}
	vd := New(ff).Validate(context.Background(), f)
	if vd.Status != StatusInconclusive {
		t.Fatalf("expected inconclusive, got %s (%s)", vd.Status, vd.Reason)
	}
	if vd.Confirmed() {
		t.Fatal("unreachable target must never be confirmed")
	}
}

// A finding of an unknown class -> inconclusive, never silently confirmed.
func TestUnknownClassInconclusive(t *testing.T) {
	f := state.Finding{Title: "Open port 8080", Target: "host.test", Validated: true}
	ff := fakeFetcher{fn: func(string) (Response, bool) { return Response{Status: 200, Body: ""}, true }}
	vd := New(ff).Validate(context.Background(), f)
	if vd.Status != StatusInconclusive || vd.Class != ClassUnknown {
		t.Fatalf("expected inconclusive/unknown, got %s/%s", vd.Status, vd.Class)
	}
}

// ValidateAll + Confirmed + Partition end-to-end: only confirmed findings pass.
func TestValidateAllAndConfirmed(t *testing.T) {
	findings := []state.Finding{
		{Title: "Reflected XSS in parameter q", Target: "http://app.test/s?q=h"},                // confirmed
		{Title: "Missing security header: Content-Security-Policy", Target: "http://app.test/"}, // refuted (present)
		{Title: "Open port 22", Target: "host.test"},                                            // inconclusive
	}
	ff := fakeFetcher{fn: func(rawURL string) (Response, bool) {
		if strings.Contains(rawURL, "/s") {
			return Response{Status: 200, Header: hdr(), Body: "x: " + valueOf(rawURL, "q")}, true
		}
		return Response{Status: 200, Header: hdr("Content-Security-Policy", "default-src 'self'"), Body: ""}, true
	}}
	v := New(ff)
	verdicts := v.ValidateAll(context.Background(), findings)
	if len(verdicts) != 3 {
		t.Fatalf("want 3 verdicts, got %d", len(verdicts))
	}
	conf := Confirmed(verdicts)
	if len(conf) != 1 {
		t.Fatalf("want 1 confirmed finding, got %d", len(conf))
	}
	if !conf[0].Validated {
		t.Fatal("confirmed finding must have Validated=true")
	}
	if !strings.Contains(conf[0].Evidence, "re-verified:") {
		t.Fatalf("confirmed finding should carry re-verification evidence, got %q", conf[0].Evidence)
	}
	c, r, inc := Partition(verdicts)
	if len(c) != 1 || len(r) != 1 || len(inc) != 1 {
		t.Fatalf("partition want 1/1/1, got %d/%d/%d", len(c), len(r), len(inc))
	}
}

// Classify is consistent with handles().
func TestClassify(t *testing.T) {
	cases := map[string]Class{
		"Reflected XSS in parameter q":                ClassReflectedXSS,
		"SQL injection (error-based) in parameter id": ClassErrorSQLi,
		"Missing security header: X-Frame-Options":    ClassMissingHeader,
		"Exposed AWS access key ID":                   ClassExposedSecret,
		"Some unrelated network finding":              ClassUnknown,
	}
	for title, want := range cases {
		got := Classify(state.Finding{Title: title})
		if got != want {
			t.Errorf("Classify(%q) = %s, want %s", title, got, want)
		}
	}
}

// valueOf extracts a query parameter value from a raw URL (test helper).
func valueOf(rawURL, name string) string {
	i := strings.Index(rawURL, "?")
	if i < 0 {
		return ""
	}
	q := rawURL[i+1:]
	for _, kv := range strings.Split(q, "&") {
		parts := strings.SplitN(kv, "=", 2)
		if parts[0] == name && len(parts) == 2 {
			dec, err := url.QueryUnescape(parts[1])
			if err != nil {
				return parts[1]
			}
			return dec
		}
	}
	return ""
}
