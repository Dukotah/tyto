package nucleiscan

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// sampleJSONL is a captured nuclei -jsonl output (anonymized): three findings,
// one per line — a critical with a cve-id + cvss vector, a medium, and an info.
// nuclei emits one compact JSON object per line.
const sampleJSONL = `{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","description":"Log4Shell remote code execution via JNDI lookup","classification":{"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cve-id":["CVE-2021-44228"]}},"matched-at":"https://target.example/api"}
{"template-id":"tech-detect-nginx","info":{"name":"Nginx Version Disclosure","severity":"medium","description":"Server header leaks the Nginx version","classification":{}},"matched-at":"https://target.example/"}
{"template-id":"http-missing-security-headers","info":{"name":"Missing Security Headers","severity":"info","description":"X-Frame-Options header is absent"},"matched":"https://target.example/login"}`

func TestParseNucleiJSONL(t *testing.T) {
	findings := parseNucleiJSONL(sampleJSONL)

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(findings), findings)
	}

	byTitle := map[string]state.Finding{}
	for _, f := range findings {
		byTitle[f.Title] = f
		if !f.Validated {
			t.Errorf("finding %q: expected Validated=true", f.Title)
		}
	}

	// Critical: title includes template-id, severity mapped, CVSS vector carried,
	// target from matched-at, cve folded into description.
	crit, ok := byTitle["Apache Log4j RCE (CVE-2021-44228)"]
	if !ok {
		t.Fatalf("missing critical finding; got titles: %v", titles(findings))
	}
	if crit.Severity != state.SeverityCritical {
		t.Errorf("critical: severity = %v, want critical", crit.Severity)
	}
	if crit.CVSS != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" {
		t.Errorf("critical: CVSS = %q, want the cvss vector", crit.CVSS)
	}
	if crit.Target != "https://target.example/api" {
		t.Errorf("critical: Target = %q, want matched-at", crit.Target)
	}
	if !strings.Contains(crit.Description, "CVE-2021-44228") {
		t.Errorf("critical: Description = %q, want cve-id folded in", crit.Description)
	}

	// Medium.
	med, ok := byTitle["Nginx Version Disclosure (tech-detect-nginx)"]
	if !ok {
		t.Fatalf("missing medium finding; got titles: %v", titles(findings))
	}
	if med.Severity != state.SeverityMedium {
		t.Errorf("medium: severity = %v, want medium", med.Severity)
	}
	if med.CVSS != "" {
		t.Errorf("medium: CVSS = %q, want empty", med.CVSS)
	}

	// Info: target falls back to "matched" when matched-at is absent.
	info, ok := byTitle["Missing Security Headers (http-missing-security-headers)"]
	if !ok {
		t.Fatalf("missing info finding; got titles: %v", titles(findings))
	}
	if info.Severity != state.SeverityInfo {
		t.Errorf("info: severity = %v, want info", info.Severity)
	}
	if info.Target != "https://target.example/login" {
		t.Errorf("info: Target = %q, want matched fallback", info.Target)
	}
}

// TestParseNucleiJSONL_SkipsMalformed ensures blank and unparseable lines are
// dropped without aborting the rest of the stream.
func TestParseNucleiJSONL_SkipsMalformed(t *testing.T) {
	in := "\n{not json}\n" + `{"template-id":"x","info":{"name":"Good","severity":"low"},"matched-at":"http://h/"}` + "\n   \n"
	findings := parseNucleiJSONL(in)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (malformed/blank skipped), got %d", len(findings))
	}
	if findings[0].Severity != state.SeverityLow {
		t.Errorf("severity = %v, want low", findings[0].Severity)
	}
}

// TestExecute_GracefulDegrade exercises the path on a box WITHOUT nuclei
// installed (CI/dev). Execute must succeed and emit the single "nuclei not
// available" info finding rather than erroring.
//
// NOTE: the live shell-out path is NOT exercised here — by design there is no
// nuclei present, so adapter.Detect returns "".
func TestExecute_GracefulDegrade(t *testing.T) {
	if adapter.Detect("nuclei") != "" {
		t.Skip("nuclei is installed; graceful-degrade path not applicable")
	}

	tool := New()
	res, err := tool.Execute(context.Background(), action.Action{
		ID:     "a1",
		Tool:   "nucleiscan",
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
	if !strings.Contains(f.Title, "nuclei not available") {
		t.Errorf("unexpected finding title: %q", f.Title)
	}
}

// TestToolMetadata pins the tool.Tool surface.
func TestToolMetadata(t *testing.T) {
	tool := New()
	if tool.Name() != "nucleiscan" {
		t.Errorf("Name() = %q, want nucleiscan", tool.Name())
	}
	if tool.Category() != action.CategoryScan {
		t.Errorf("Category() = %v, want CategoryScan", tool.Category())
	}
	if tool.MaxRisk() != action.RiskMedium {
		t.Errorf("MaxRisk() = %v, want RiskMedium", tool.MaxRisk())
	}
}

func titles(fs []state.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Title
	}
	return out
}
