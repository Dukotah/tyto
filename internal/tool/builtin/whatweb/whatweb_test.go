package whatweb

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// sampleJSON is a captured whatweb --log-json output: a JSON array with one
// target object whose plugins include nginx (HTTPServer, with version), PHP
// (with version), and jQuery (no version).
const sampleJSON = `[
  {
    "target": "https://target.example/",
    "http_status": 200,
    "plugins": {
      "HTTPServer": {"string": ["nginx/1.18.0"], "version": ["1.18.0"]},
      "PHP": {"version": ["7.4.3"], "string": ["PHP/7.4.3"]},
      "jQuery": {"version": []},
      "X-Powered-By": {"string": ["PHP/7.4.3"]}
    }
  }
]`

func TestParseWhatweb(t *testing.T) {
	findings, assets := parseWhatweb(sampleJSON)

	if len(findings) != 4 {
		t.Fatalf("expected 4 findings (one per plugin), got %d: %v", len(findings), titles(findings))
	}

	byTitle := map[string]state.Finding{}
	for _, f := range findings {
		byTitle[f.Title] = f
		if f.Severity != state.SeverityInfo {
			t.Errorf("finding %q: severity = %v, want info", f.Title, f.Severity)
		}
		if !f.Validated {
			t.Errorf("finding %q: expected Validated=true", f.Title)
		}
		if f.Target != "https://target.example/" {
			t.Errorf("finding %q: Target = %q, want the target", f.Title, f.Target)
		}
	}

	// nginx via HTTPServer: version in title + evidence.
	srv, ok := byTitle["Technology: HTTPServer 1.18.0"]
	if !ok {
		t.Fatalf("missing HTTPServer finding; got titles: %v", titles(findings))
	}
	if !strings.Contains(srv.Evidence, "1.18.0") {
		t.Errorf("HTTPServer: Evidence = %q, want version present", srv.Evidence)
	}

	// PHP: version named in title.
	if _, ok := byTitle["Technology: PHP 7.4.3"]; !ok {
		t.Fatalf("missing PHP finding; got titles: %v", titles(findings))
	}

	// jQuery: no version, so title is just the plugin name.
	if _, ok := byTitle["Technology: jQuery"]; !ok {
		t.Fatalf("missing jQuery finding; got titles: %v", titles(findings))
	}

	// One endpoint asset for the target.
	if len(assets) != 1 {
		t.Fatalf("expected 1 endpoint asset, got %d: %+v", len(assets), assets)
	}
	asset := assets[0]
	if asset.Type != "endpoint" {
		t.Errorf("asset Type = %q, want endpoint", asset.Type)
	}
	if asset.Value != "https://target.example/" {
		t.Errorf("asset Value = %q, want the target", asset.Value)
	}
	if asset.Attrs["http_status"] != "200" {
		t.Errorf("asset http_status = %q, want 200", asset.Attrs["http_status"])
	}
	if asset.Attrs["server"] != "nginx/1.18.0" {
		t.Errorf("asset server = %q, want nginx/1.18.0", asset.Attrs["server"])
	}
	if !strings.Contains(asset.Attrs["plugins"], "PHP") {
		t.Errorf("asset plugins = %q, want PHP listed", asset.Attrs["plugins"])
	}
}

// TestParseWhatweb_Empty ensures blank/garbage input yields nothing, not a panic.
func TestParseWhatweb_Empty(t *testing.T) {
	for _, in := range []string{"", "   ", "not json", "{}"} {
		f, a := parseWhatweb(in)
		if len(f) != 0 || len(a) != 0 {
			t.Errorf("parseWhatweb(%q): expected no findings/assets, got %d/%d", in, len(f), len(a))
		}
	}
}

// TestExecute_GracefulDegrade exercises the path on a box WITHOUT whatweb
// installed (CI/dev). Execute must succeed and emit the single "whatweb not
// available" info finding rather than erroring.
//
// NOTE: the live shell-out path is NOT exercised here — by design there is no
// whatweb present, so adapter.Detect returns "".
func TestExecute_GracefulDegrade(t *testing.T) {
	if adapter.Detect("whatweb") != "" {
		t.Skip("whatweb is installed; graceful-degrade path not applicable")
	}

	tool := New()
	res, err := tool.Execute(context.Background(), action.Action{
		ID:     "a1",
		Tool:   "whatweb",
		Target: "https://target.example",
	})
	if err != nil {
		t.Fatalf("Execute returned error on degrade path: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success=true on graceful degrade, got false")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %v", f.Severity)
	}
	if !strings.Contains(f.Title, "whatweb not available") {
		t.Errorf("unexpected finding title: %q", f.Title)
	}
}

// TestToolMetadata pins the tool.Tool surface.
func TestToolMetadata(t *testing.T) {
	tool := New()
	if tool.Name() != "whatweb" {
		t.Errorf("Name() = %q, want whatweb", tool.Name())
	}
	if tool.Category() != action.CategoryRecon {
		t.Errorf("Category() = %v, want CategoryRecon", tool.Category())
	}
	if tool.MaxRisk() != action.RiskPassive {
		t.Errorf("MaxRisk() = %v, want RiskPassive", tool.MaxRisk())
	}
}

func titles(fs []state.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Title
	}
	return out
}
