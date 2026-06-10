package subfinder

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// sampleOut is captured `subfinder -d example.com -silent` output: three distinct
// subdomains, with api.example.com repeated to exercise dedup.
const sampleOut = "api.example.com\nwww.example.com\ndev.example.com\napi.example.com\n"

func TestParseSubfinder(t *testing.T) {
	findings, assets := parseSubfinder(sampleOut, "example.com")

	if len(findings) != 3 {
		t.Fatalf("expected 3 deduped findings, got %d: %+v", len(findings), findings)
	}
	if len(assets) != 3 {
		t.Fatalf("expected 3 deduped domain assets, got %d: %+v", len(assets), assets)
	}

	byVal := map[string]state.Asset{}
	for _, a := range assets {
		if a.Type != "domain" {
			t.Errorf("asset %q: want Type=domain, got %q", a.Value, a.Type)
		}
		byVal[a.Value] = a
	}
	for _, want := range []string{"api.example.com", "www.example.com", "dev.example.com"} {
		if _, ok := byVal[want]; !ok {
			t.Errorf("missing domain asset %q; have %+v", want, byVal)
		}
	}

	for _, f := range findings {
		if f.Severity != state.SeverityInfo {
			t.Errorf("finding %q: want SeverityInfo, got %v", f.Title, f.Severity)
		}
		if !f.Validated {
			t.Errorf("finding %q: want Validated=true", f.Title)
		}
		if !strings.HasPrefix(f.Title, "Subdomain: ") {
			t.Errorf("finding title %q: want 'Subdomain: ' prefix", f.Title)
		}
	}
}

// TestParseSubfinderGarbage confirms blank lines and non-hostname noise are
// tolerated and produce nothing, not a panic.
func TestParseSubfinderGarbage(t *testing.T) {
	garbage := "\n   \n[INF] enumerating sources\nnodothostname\nhas space.com\n\t\n"
	findings, assets := parseSubfinder(garbage, "example.com")
	if len(findings) != 0 || len(assets) != 0 {
		t.Errorf("garbage input should yield nothing, got %d findings / %d assets: %+v %+v",
			len(findings), len(assets), findings, assets)
	}
	// Empty input too.
	if f, a := parseSubfinder("", "example.com"); len(f) != 0 || len(a) != 0 {
		t.Errorf("empty input should yield nothing, got %d/%d", len(f), len(a))
	}
}

func TestDomainOf(t *testing.T) {
	cases := map[string]string{
		"https://api.h.com:8443/x": "api.h.com",
		"http://host/a/b":          "host",
		"example.com":              "example.com",
		"example.com.":             "example.com",
		"EXAMPLE.COM":              "example.com",
		"10.0.0.5":                 "10.0.0.5",
		"10.0.0.5:443":             "10.0.0.5",
	}
	for in, want := range cases {
		if got := domainOf(in); got != want {
			t.Errorf("domainOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExecuteIPTarget asserts that an IP target returns the "needs a domain" info
// finding before ever reaching detect/run, and still succeeds.
func TestExecuteIPTarget(t *testing.T) {
	res, err := New().Execute(context.Background(), action.Action{
		ID:     "a1",
		Target: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected Success=true for IP target")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo {
		t.Errorf("IP-target finding should be SeverityInfo, got %v", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Title), "needs a domain") {
		t.Errorf("finding title = %q, want it to mention 'needs a domain'", f.Title)
	}
	if len(res.Assets) != 0 {
		t.Errorf("IP target should produce no assets, got %d", len(res.Assets))
	}
}

// TestExecuteGracefulDegrade asserts that when subfinder is not installed, Execute
// still succeeds with the standard "subfinder not available" Info finding. Skipped
// if subfinder happens to be on PATH (then the live enumeration path would run).
func TestExecuteGracefulDegrade(t *testing.T) {
	if adapter.Detect("subfinder") != "" {
		t.Skip("subfinder is installed on this host; graceful-degrade path not exercised")
	}
	res, err := New().Execute(context.Background(), action.Action{
		ID:     "a1",
		Target: "https://example.com/path",
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected Success=true on graceful degrade")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo {
		t.Errorf("graceful-degrade finding should be SeverityInfo, got %v", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Title), "subfinder not available") {
		t.Errorf("finding title = %q, want it to mention 'subfinder not available'", f.Title)
	}
}

// Compile-time assertion that *Tool satisfies the tool.Tool contract.
var (
	_ interface {
		Name() string
		Category() action.Category
		MaxRisk() action.RiskLevel
		Execute(context.Context, action.Action) (action.Result, error)
	} = (*Tool)(nil)
)
