package gobuster

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// sampleDir is captured gobuster dir quiet (-q) output: an /admin 200, a
// /.git/config 200 (sensitive), and a /login 302 redirect.
const sampleDir = `/admin                (Status: 200) [Size: 1234]
/.git/config          (Status: 200) [Size: 92]
/login                (Status: 302) [Size: 0]
`

// sampleDNS is captured gobuster dns quiet (-q) output: two resolved subdomains.
const sampleDNS = "Found: api.example.com\nFound: dev.example.com\n"

// sampleVhost is captured gobuster vhost quiet (-q) output: one responding vhost.
const sampleVhost = "Found: dev.example.com (Status: 200) [Size: 512]\n"

func TestParseGobusterDir(t *testing.T) {
	const target = "http://target.example"
	findings, assets := parseGobuster(sampleDir, "dir", target)

	if len(findings) != 3 {
		t.Fatalf("dir: want 3 findings, got %d: %+v", len(findings), findings)
	}

	// All dir findings are validated discoveries.
	for _, f := range findings {
		if !f.Validated {
			t.Errorf("dir finding %q should be Validated", f.Title)
		}
		if !strings.HasPrefix(f.Title, "Discovered: ") {
			t.Errorf("dir finding title %q missing Discovered prefix", f.Title)
		}
	}

	// .git/config is sensitive -> Low; /admin contains "admin" -> Low; /login -> Info.
	sevByPath := map[string]state.Severity{}
	for _, f := range findings {
		sevByPath[f.Target] = f.Severity
	}
	if got := sevByPath["/.git/config"]; got != state.SeverityLow {
		t.Errorf("/.git/config severity: want Low, got %v", got)
	}
	if got := sevByPath["/login"]; got != state.SeverityInfo {
		t.Errorf("/login severity: want Info, got %v", got)
	}

	// Endpoint assets: /admin (200) and /login (302) are reachable -> assets; the
	// .git/config is also 200 -> asset. All three are 200/3xx, so 3 endpoint assets.
	if len(assets) != 3 {
		t.Fatalf("dir: want 3 endpoint assets, got %d: %+v", len(assets), assets)
	}
	wantURL := map[string]bool{
		"http://target.example/admin":       false,
		"http://target.example/.git/config": false,
		"http://target.example/login":       false,
	}
	for _, as := range assets {
		if as.Type != "endpoint" {
			t.Errorf("asset %q type: want endpoint, got %q", as.Value, as.Type)
		}
		if _, ok := wantURL[as.Value]; !ok {
			t.Errorf("unexpected endpoint asset url %q", as.Value)
			continue
		}
		wantURL[as.Value] = true
	}
	for u, seen := range wantURL {
		if !seen {
			t.Errorf("missing endpoint asset for %q", u)
		}
	}
}

func TestParseGobusterDNS(t *testing.T) {
	findings, assets := parseGobuster(sampleDNS, "dns", "example.com")

	if len(findings) != 2 {
		t.Fatalf("dns: want 2 findings, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Severity != state.SeverityInfo {
			t.Errorf("dns finding %q: want Info, got %v", f.Title, f.Severity)
		}
		if !strings.HasPrefix(f.Title, "Subdomain (DNS brute): ") {
			t.Errorf("dns finding title %q missing subdomain prefix", f.Title)
		}
	}
	if findings[0].Target != "api.example.com" || findings[1].Target != "dev.example.com" {
		t.Errorf("dns finding targets wrong: %q, %q", findings[0].Target, findings[1].Target)
	}

	if len(assets) != 2 {
		t.Fatalf("dns: want 2 assets, got %d: %+v", len(assets), assets)
	}
	for _, as := range assets {
		if as.Type != "domain" {
			t.Errorf("dns asset %q type: want domain, got %q", as.Value, as.Type)
		}
	}
	if assets[0].Value != "api.example.com" || assets[1].Value != "dev.example.com" {
		t.Errorf("dns asset values wrong: %q, %q", assets[0].Value, assets[1].Value)
	}
}

func TestParseGobusterVhost(t *testing.T) {
	findings, assets := parseGobuster(sampleVhost, "vhost", "http://example.com")

	if len(findings) != 1 {
		t.Fatalf("vhost: want 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != state.SeverityLow {
		t.Errorf("vhost finding: want Low, got %v", f.Severity)
	}
	if f.Title != "Virtual host: dev.example.com" {
		t.Errorf("vhost finding title: got %q", f.Title)
	}
	if f.Target != "dev.example.com" {
		t.Errorf("vhost finding target: got %q", f.Target)
	}

	if len(assets) != 1 {
		t.Fatalf("vhost: want 1 asset, got %d", len(assets))
	}
	if assets[0].Value != "dev.example.com" {
		t.Errorf("vhost asset value: got %q", assets[0].Value)
	}
}

func TestDomainOf(t *testing.T) {
	cases := map[string]string{
		"https://example.com":           "example.com",
		"http://example.com:8080/path":  "example.com",
		"example.com":                   "example.com",
		"http://user@host.example:80/x": "host.example",
		"sub.example.com:443":           "sub.example.com",
	}
	for in, want := range cases {
		if got := domainOf(in); got != want {
			t.Errorf("domainOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildArgs(t *testing.T) {
	dir := buildArgs("dir", "http://t", "wl")
	if dir[0] != "dir" || dir[1] != "-u" || dir[2] != "http://t" {
		t.Errorf("dir args wrong: %v", dir)
	}
	if !contains(dir, "-k") || !contains(dir, "-z") || !contains(dir, "-q") {
		t.Errorf("dir args missing flags: %v", dir)
	}

	dns := buildArgs("dns", "https://sub.example.com:443/x", "wl")
	if dns[0] != "dns" || dns[1] != "-d" || dns[2] != "sub.example.com" {
		t.Errorf("dns args should use bare domain: %v", dns)
	}

	vh := buildArgs("vhost", "http://t", "wl")
	if vh[0] != "vhost" || !contains(vh, "--append-domain") {
		t.Errorf("vhost args wrong: %v", vh)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestExecuteGracefulDegrade exercises the no-gobuster-installed path. In CI
// gobuster is not present, so Execute must emit the single "gobuster not
// available" Info finding and Success=true. If gobuster IS present this test is
// skipped (the live path is intentionally untested here).
func TestExecuteGracefulDegrade(t *testing.T) {
	if bin := adapter.Detect("gobuster"); bin != "" {
		t.Skipf("gobuster present at %q; skipping graceful-degrade test", bin)
	}

	tool := New()
	res, err := tool.Execute(context.Background(), action.Action{
		ID:     "a1",
		Target: "http://target.example",
		Params: map[string]string{"mode": "dir"},
	})
	if err != nil {
		t.Fatalf("Execute returned err: %v", err)
	}
	if !res.Success {
		t.Errorf("graceful degrade should still Succeed")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 degrade finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo {
		t.Errorf("degrade finding severity: want Info, got %v", f.Severity)
	}
	if !strings.Contains(f.Title, "not available") {
		t.Errorf("degrade finding title: got %q", f.Title)
	}
}
