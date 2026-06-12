package subtakeover

import (
	"context"
	"errors"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/takeover"
)

// fakeResolver / fakeFetcher implement the takeover engine's injectable seams so
// the tool is tested with NO network. LookupHost returns a live address by
// default so the NXDOMAIN-only providers are never falsely triggered.
type fakeResolver struct {
	cname    string
	cnameErr error
	addrs    []string
	hostErr  error
}

func (f fakeResolver) LookupCNAME(_ context.Context, _ string) (string, error) {
	return f.cname, f.cnameErr
}
func (f fakeResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	if f.hostErr != nil {
		return nil, f.hostErr
	}
	if f.addrs == nil {
		return []string{"203.0.113.10"}, nil
	}
	return f.addrs, nil
}

type fakeFetcher struct {
	status int
	body   string
	err    error
}

func (f fakeFetcher) Fetch(_ context.Context, _ string) (int, string, error) {
	if f.err != nil {
		return 0, "", f.err
	}
	st := f.status
	if st == 0 {
		st = 200
	}
	return st, f.body, nil
}

func toolWith(cname, body string) *Tool {
	return NewWith(fakeResolver{cname: cname}, fakeFetcher{body: body})
}

func findingByTitle(fs []state.Finding, title string) (state.Finding, bool) {
	for _, f := range fs {
		if f.Title == title {
			return f, true
		}
	}
	return state.Finding{}, false
}

func hasHigh(fs []state.Finding) bool {
	for _, f := range fs {
		if f.Severity == state.SeverityHigh {
			return true
		}
	}
	return false
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

// DOUBLE-GATE SATISFIED: CNAME to provider AND unclaimed fingerprint => HIGH.
func TestTakeover_GitHubPages_DoubleGated(t *testing.T) {
	tl := toolWith("victim.github.io", "There isn't a GitHub Pages site here.")
	res, _ := tl.Execute(context.Background(), action.Action{ID: "gh", Target: "sub.example.com"})
	f, ok := findingByTitle(res.Findings, "Possible subdomain takeover (GitHub Pages)")
	if !ok {
		t.Fatalf("missing GitHub Pages takeover finding; got %+v", res.Findings)
	}
	if f.Severity != state.SeverityHigh || !f.Validated {
		t.Errorf("want HIGH+Validated, got sev=%v validated=%v", f.Severity, f.Validated)
	}
}

func TestTakeover_S3_DoubleGated(t *testing.T) {
	tl := toolWith("my-bucket.s3.amazonaws.com", "<Error><Code>NoSuchBucket</Code></Error>")
	res, _ := tl.Execute(context.Background(), action.Action{ID: "s3", Target: "sub.example.com"})
	if !hasHigh(res.Findings) {
		t.Fatalf("want HIGH for s3 NoSuchBucket double-gate; got %+v", res.Findings)
	}
}

// CRITICAL FP GUARD: the body contains a fingerprint string, but the CNAME does
// NOT point to any provider. A body match ALONE must never flag — this is the
// exact false positive that bans a fresh bounty account.
func TestNoTakeover_BodyMatchWithoutProviderCNAME(t *testing.T) {
	// A page (e.g. a blog or WAF) that merely quotes "NoSuchBucket", but the host
	// CNAMEs nowhere relevant.
	tl := toolWith("", "Today we discuss the AWS NoSuchBucket error and how to fix it.")
	res, _ := tl.Execute(context.Background(), action.Action{ID: "fp", Target: "sub.example.com"})
	if hasHigh(res.Findings) {
		t.Fatalf("FALSE POSITIVE: body-only fingerprint flagged HIGH without a provider CNAME: %+v", res.Findings)
	}
	if _, ok := findingByTitle(res.Findings, "No subdomain-takeover detected"); !ok {
		t.Fatalf("want the negative info finding; got %+v", res.Findings)
	}
}

// CLAIMED PAGE: CNAME points to a provider, but the page is a real published
// site (no unclaimed fingerprint) => refuted, never HIGH.
func TestNoTakeover_ClaimedProviderPage(t *testing.T) {
	tl := toolWith("victim.github.io", "<html><body>Welcome to my live, claimed GitHub Pages site!</body></html>")
	res, _ := tl.Execute(context.Background(), action.Action{ID: "claimed", Target: "sub.example.com"})
	if hasHigh(res.Findings) {
		t.Fatalf("FALSE POSITIVE: claimed provider page flagged HIGH: %+v", res.Findings)
	}
}

func TestExecuteHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tl := NewWith(fakeResolver{cnameErr: errors.New("cancelled")}, fakeFetcher{err: errors.New("cancelled")})
	res, err := tl.Execute(ctx, action.Action{ID: "cx", Target: "sub.example.com"})
	if err != nil {
		t.Fatalf("cancellation must not return a hard error: %v", err)
	}
	if hasHigh(res.Findings) {
		t.Errorf("a failed lookup/fetch must not produce a HIGH finding")
	}
	_ = takeover.ConfidenceHigh // keep the takeover import meaningful across refactors
}
