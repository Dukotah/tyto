package ffufadapter

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// sampleFfufJSON is a captured `ffuf -of json -o -` output with three hits: an
// /admin 200, a /.git/config 200 (sensitive), and a /login 302 redirect.
const sampleFfufJSON = `{
  "commandline": "ffuf -u http://target.example/FUZZ -w /usr/share/wordlists/dirb/common.txt -of json -o - -mc 200,204,301,302,307,401,403 -s",
  "time": "2026-06-10T12:00:00Z",
  "results": [
    {
      "input": {"FUZZ": "admin"},
      "url": "http://target.example/admin",
      "status": 200,
      "length": 1024,
      "words": 80,
      "lines": 30,
      "content-type": "text/html"
    },
    {
      "input": {"FUZZ": ".git/config"},
      "url": "http://target.example/.git/config",
      "status": 200,
      "length": 92,
      "words": 5,
      "lines": 6,
      "content-type": "text/plain"
    },
    {
      "input": {"FUZZ": "login"},
      "url": "http://target.example/login",
      "status": 302,
      "length": 0,
      "words": 1,
      "lines": 1,
      "content-type": "text/html"
    }
  ]
}`

func TestParseFfuf(t *testing.T) {
	findings, assets := parseFfuf(sampleFfufJSON)

	if len(findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(findings))
	}
	// Endpoint assets for all three (200, 200, 302 are all 200/3xx).
	if len(assets) != 3 {
		t.Fatalf("want 3 endpoint assets, got %d", len(assets))
	}

	// Findings carry url + status in title and status+length in evidence.
	byTarget := map[string]state.Finding{}
	for _, f := range findings {
		byTarget[f.Target] = f
		if !f.Validated {
			t.Errorf("finding %q should be Validated", f.Target)
		}
	}

	admin, ok := byTarget["http://target.example/admin"]
	if !ok {
		t.Fatal("missing /admin finding")
	}
	if !strings.Contains(admin.Title, "HTTP 200") {
		t.Errorf("admin title missing status: %q", admin.Title)
	}
	if !strings.Contains(admin.Evidence, "200") || !strings.Contains(admin.Evidence, "1024") {
		t.Errorf("admin evidence missing status/length: %q", admin.Evidence)
	}
	// "admin" is classified sensitive -> Low.
	if admin.Severity != state.SeverityLow {
		t.Errorf("admin severity = %v, want Low", admin.Severity)
	}

	git, ok := byTarget["http://target.example/.git/config"]
	if !ok {
		t.Fatal("missing /.git/config finding")
	}
	// .git bumped to Low.
	if git.Severity != state.SeverityLow {
		t.Errorf(".git/config severity = %v, want Low", git.Severity)
	}
	if !strings.Contains(git.Evidence, "92") {
		t.Errorf(".git evidence missing length: %q", git.Evidence)
	}

	login, ok := byTarget["http://target.example/login"]
	if !ok {
		t.Fatal("missing /login finding")
	}
	if !strings.Contains(login.Title, "HTTP 302") {
		t.Errorf("login title missing status: %q", login.Title)
	}

	// Every asset is an endpoint with a status attr.
	for _, as := range assets {
		if as.Type != "endpoint" {
			t.Errorf("asset %q type = %q, want endpoint", as.Value, as.Type)
		}
		if as.Attrs["status"] == "" {
			t.Errorf("asset %q missing status attr", as.Value)
		}
	}
}

func TestParseFfufEmpty(t *testing.T) {
	findings, assets := parseFfuf(`{"results":[]}`)
	if len(findings) != 0 || len(assets) != 0 {
		t.Fatalf("want no findings/assets, got %d/%d", len(findings), len(assets))
	}
	// Garbage input parses to nothing without panicking.
	if f, a := parseFfuf("not json"); f != nil || a != nil {
		t.Fatalf("garbage input: want nil/nil, got %d/%d", len(f), len(a))
	}
}

func TestFuzzURLFor(t *testing.T) {
	cases := []struct {
		name   string
		target string
		params map[string]string
		want   string
	}{
		{"append fuzz", "http://h.example", nil, "http://h.example/FUZZ"},
		{"trim trailing slash", "http://h.example/", nil, "http://h.example/FUZZ"},
		{"already has fuzz", "http://h.example/FUZZ/x", nil, "http://h.example/FUZZ/x"},
		{"url param overrides", "http://h.example", map[string]string{"url": "http://o.example/api/FUZZ"}, "http://o.example/api/FUZZ"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := fuzzURLFor(action.Action{Target: c.target, Params: c.params})
			if got != c.want {
				t.Errorf("fuzzURLFor = %q, want %q", got, c.want)
			}
		})
	}
}

// TestExecuteGracefulDegrade exercises the missing-binary path. This relies on
// ffuf not being installed in the test environment (the common CI/dev case);
// when ffuf IS present the live path runs instead, so we only assert the
// degrade behavior when Detect found nothing.
func TestExecuteGracefulDegrade(t *testing.T) {
	tl := New()
	if tl.Name() != "ffuf" {
		t.Fatalf("Name = %q, want ffuf", tl.Name())
	}
	if tl.Category() != action.CategoryScan {
		t.Fatalf("Category = %v, want scan", tl.Category())
	}
	if tl.MaxRisk() != action.RiskLow {
		t.Fatalf("MaxRisk = %v, want low", tl.MaxRisk())
	}

	res, err := tl.Execute(context.Background(), action.Action{ID: "a1", Target: "http://target.example"})
	if err != nil {
		t.Fatalf("Execute err = %v", err)
	}
	if !res.Success {
		t.Fatal("Execute should succeed even when ffuf is missing")
	}

	// When ffuf is not on PATH we expect exactly the graceful-degrade Info finding.
	if findContains(res.Findings, "ffuf not available") {
		if len(res.Findings) != 1 {
			t.Fatalf("graceful degrade: want 1 finding, got %d", len(res.Findings))
		}
		if res.Findings[0].Severity != state.SeverityInfo {
			t.Errorf("graceful-degrade finding severity = %v, want Info", res.Findings[0].Severity)
		}
		if !strings.Contains(res.Output, "ffuf not available") {
			t.Errorf("graceful-degrade output = %q", res.Output)
		}
	} else {
		t.Skip("ffuf is installed in this environment; skipping graceful-degrade assertions")
	}
}

func findContains(findings []state.Finding, sub string) bool {
	for _, f := range findings {
		if strings.Contains(f.Title, sub) {
			return true
		}
	}
	return false
}
