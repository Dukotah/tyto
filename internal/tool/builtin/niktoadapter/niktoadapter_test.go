package niktoadapter

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// sampleNiktoJSON is a captured nikto `-Format json` object with three
// vulnerabilities: one "outdated" (-> Medium), one generic XSS-ish (-> Low),
// and one informational header note (-> Info).
const sampleNiktoJSON = `{
  "host": "example.com",
  "ip": "93.184.216.34",
  "port": "80",
  "banner": "Apache/2.2.8",
  "vulnerabilities": [
    {
      "id": "999103",
      "method": "GET",
      "url": "/",
      "msg": "Apache/2.2.8 appears to be outdated (current is at least Apache/2.4.54).",
      "OSVDB": "0"
    },
    {
      "id": "000455",
      "method": "GET",
      "url": "/login.php?id=test",
      "msg": "Reflected parameter id may be susceptible to injection.",
      "OSVDB": "0"
    },
    {
      "id": "999957",
      "method": "GET",
      "url": "/",
      "msg": "The X-Content-Type-Options header is not set.",
      "OSVDB": "0"
    }
  ]
}`

func TestParseNikto(t *testing.T) {
	findings := parseNikto(sampleNiktoJSON)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// 1. Outdated -> Medium.
	f0 := findings[0]
	if f0.Severity != state.SeverityMedium {
		t.Errorf("finding[0] severity = %v, want medium", f0.Severity)
	}
	if !strings.HasPrefix(f0.Title, "nikto: ") {
		t.Errorf("finding[0] title = %q, want nikto: prefix", f0.Title)
	}
	if !f0.Validated {
		t.Errorf("finding[0] should be Validated")
	}
	if f0.Target != "example.com/" {
		t.Errorf("finding[0] target = %q, want example.com/", f0.Target)
	}
	if f0.Evidence != "GET / 999103" {
		t.Errorf("finding[0] evidence = %q, want %q", f0.Evidence, "GET / 999103")
	}

	// 2. Generic injection -> Low.
	f1 := findings[1]
	if f1.Severity != state.SeverityLow {
		t.Errorf("finding[1] severity = %v, want low", f1.Severity)
	}
	if f1.Target != "example.com/login.php?id=test" {
		t.Errorf("finding[1] target = %q", f1.Target)
	}
	if f1.Evidence != "GET /login.php?id=test 000455" {
		t.Errorf("finding[1] evidence = %q", f1.Evidence)
	}

	// 3. Header note -> Info.
	f2 := findings[2]
	if f2.Severity != state.SeverityInfo {
		t.Errorf("finding[2] severity = %v, want info", f2.Severity)
	}
}

// TestParseNiktoArrayForm confirms the top level may be an array of host objects.
func TestParseNiktoArrayForm(t *testing.T) {
	arr := "[" + sampleNiktoJSON + "]"
	findings := parseNikto(arr)
	if len(findings) != 3 {
		t.Fatalf("array form: expected 3 findings, got %d", len(findings))
	}
	if findings[0].Severity != state.SeverityMedium {
		t.Errorf("array form: finding[0] severity = %v, want medium", findings[0].Severity)
	}
}

// TestParseNiktoEmpty tolerates empty / non-JSON output without panicking.
func TestParseNiktoEmpty(t *testing.T) {
	if f := parseNikto(""); f != nil {
		t.Errorf("empty input: expected nil, got %v", f)
	}
	if f := parseNikto("not json at all"); f != nil {
		t.Errorf("garbage input: expected nil, got %v", f)
	}
}

// TestExecuteGracefulDegrade exercises the no-nikto path: with nikto absent from
// PATH, Execute must succeed and emit the single "nikto not available" info
// finding. (When nikto IS installed the live path runs instead; this test
// asserts only the documented degrade behavior.)
func TestExecuteGracefulDegrade(t *testing.T) {
	bin := adapter.Detect("nikto")
	if bin != "" {
		t.Skipf("nikto is installed at %q; graceful-degrade path not exercised", bin)
	}

	tool := New()
	res, err := tool.Execute(context.Background(), action.Action{
		ID:     "A1",
		Target: "http://example.com",
	})
	if err != nil {
		t.Fatalf("Execute returned err: %v", err)
	}
	if !res.Success {
		t.Errorf("Execute Success = false, want true")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo {
		t.Errorf("degrade finding severity = %v, want info", f.Severity)
	}
	if f.Title != "nikto not available" {
		t.Errorf("degrade finding title = %q, want %q", f.Title, "nikto not available")
	}
}
