package wpscanadapter

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// sampleJSON is a captured-shape `wpscan --format json` blob: WordPress 5.8
// (outdated) with one core vulnerability carrying a CVE, one vulnerable plugin,
// one interesting finding, and one enumerated user.
const sampleJSON = `{
  "version": {
    "number": "5.8",
    "status": "outdated",
    "vulnerabilities": [
      {
        "title": "WordPress 5.8 - Stored XSS via Post Slugs",
        "references": { "cve": ["2022-21661"] }
      }
    ]
  },
  "plugins": {
    "contact-form-7": {
      "version": { "number": "5.3.1" },
      "vulnerabilities": [
        {
          "title": "Contact Form 7 < 5.3.2 - Unrestricted File Upload",
          "references": { "cve": ["2020-35489"] }
        }
      ]
    }
  },
  "interesting_findings": [
    {
      "type": "headers",
      "to_s": "Headers (Apache, X-Powered-By: PHP/7.4)",
      "url": "https://victim.example/"
    }
  ],
  "users": {
    "admin": { "id": 1, "found_by": "Author Id Brute Forcing" }
  }
}`

func findByTitlePrefix(fs []state.Finding, prefix string) *state.Finding {
	for i := range fs {
		if strings.HasPrefix(fs[i].Title, prefix) {
			return &fs[i]
		}
	}
	return nil
}

func TestParseWpscanSample(t *testing.T) {
	fs := parseWpscan(sampleJSON)
	if len(fs) == 0 {
		t.Fatal("expected findings, got none")
	}

	// WordPress version finding — Medium because outdated.
	ver := findByTitlePrefix(fs, "WordPress 5.8 (outdated)")
	if ver == nil {
		t.Fatal("missing WordPress version finding")
	}
	if ver.Severity != state.SeverityMedium {
		t.Errorf("version severity: want medium, got %v", ver.Severity)
	}
	if !ver.Validated {
		t.Error("version finding should be validated")
	}

	// High core-vuln finding with the CVE in evidence.
	coreVuln := findByTitlePrefix(fs, "WordPress core vuln:")
	if coreVuln == nil {
		t.Fatal("missing core vuln finding")
	}
	if coreVuln.Severity != state.SeverityHigh {
		t.Errorf("core vuln severity: want high, got %v", coreVuln.Severity)
	}
	if !strings.Contains(coreVuln.Evidence, "2022-21661") {
		t.Errorf("core vuln evidence missing CVE, got %q", coreVuln.Evidence)
	}

	// High plugin-vuln finding.
	plugVuln := findByTitlePrefix(fs, "Plugin contact-form-7 vuln:")
	if plugVuln == nil {
		t.Fatal("missing plugin vuln finding")
	}
	if plugVuln.Severity != state.SeverityHigh {
		t.Errorf("plugin vuln severity: want high, got %v", plugVuln.Severity)
	}
	if !strings.Contains(plugVuln.Evidence, "2020-35489") {
		t.Errorf("plugin vuln evidence missing CVE, got %q", plugVuln.Evidence)
	}

	// Info finding naming the detected plugin.
	plugDet := findByTitlePrefix(fs, "WordPress plugin detected: contact-form-7")
	if plugDet == nil {
		t.Fatal("missing plugin-detected info finding")
	}
	if plugDet.Severity != state.SeverityInfo {
		t.Errorf("plugin detected severity: want info, got %v", plugDet.Severity)
	}

	// Info interesting finding.
	interesting := findByTitlePrefix(fs, "Interesting finding:")
	if interesting == nil {
		t.Fatal("missing interesting finding")
	}
	if interesting.Severity != state.SeverityInfo {
		t.Errorf("interesting severity: want info, got %v", interesting.Severity)
	}

	// Low user-enum finding.
	user := findByTitlePrefix(fs, "WordPress user enumerated: admin")
	if user == nil {
		t.Fatal("missing user-enum finding")
	}
	if user.Severity != state.SeverityLow {
		t.Errorf("user severity: want low, got %v", user.Severity)
	}
}

func TestParseWpscanMinimal(t *testing.T) {
	for _, in := range []string{`{}`, `{"version":null}`, `{"version":null,"plugins":{},"users":{}}`} {
		fs := parseWpscan(in)
		if len(fs) != 0 {
			t.Errorf("input %q: want 0 findings, got %d", in, len(fs))
		}
	}
}

func TestParseWpscanInvalidJSON(t *testing.T) {
	if fs := parseWpscan("not json at all"); fs != nil {
		t.Errorf("invalid JSON should yield nil, got %d findings", len(fs))
	}
}

func TestParseWpscanSecureVersion(t *testing.T) {
	// status latest => Low (not Medium).
	fs := parseWpscan(`{"version":{"number":"6.5","status":"latest"}}`)
	ver := findByTitlePrefix(fs, "WordPress 6.5 (latest)")
	if ver == nil {
		t.Fatal("missing version finding")
	}
	if ver.Severity != state.SeverityLow {
		t.Errorf("latest version severity: want low, got %v", ver.Severity)
	}
}

// TestExecuteGracefulDegrade exercises the no-wpscan path: in CI/this env wpscan
// is not installed, so Execute should emit the "wpscan not available" Info
// finding and succeed.
func TestExecuteGracefulDegrade(t *testing.T) {
	tl := New()
	if tl.Name() != "wpscan" {
		t.Errorf("Name: want wpscan, got %q", tl.Name())
	}
	if tl.Category() != action.CategoryScan {
		t.Errorf("Category: want scan, got %v", tl.Category())
	}
	if tl.MaxRisk() != action.RiskLow {
		t.Errorf("MaxRisk: want low, got %v", tl.MaxRisk())
	}

	res, err := tl.Execute(context.Background(), action.Action{ID: "a1", Target: "https://victim.example"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Error("Execute should succeed on graceful degrade")
	}
	deg := findByTitlePrefix(res.Findings, "wpscan not available")
	if deg == nil {
		t.Fatal("missing 'wpscan not available' info finding")
	}
	if deg.Severity != state.SeverityInfo {
		t.Errorf("degrade finding severity: want info, got %v", deg.Severity)
	}
}
