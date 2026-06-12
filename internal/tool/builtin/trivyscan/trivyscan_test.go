package trivyscan

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// sampleJSON is a captured (anonymized) Trivy `--format json` document for an
// `fs` scan of a Node lockfile plus an OS package set: it contains a critical
// CVE with a fixed version + NVD CVSS vector, a high CVE with no fixed version,
// a medium, and a duplicate of the critical (same CVE+pkg) that must dedupe.
const sampleJSON = `{
  "ArtifactName": "/src",
  "Results": [
    {
      "Target": "package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-44228",
          "PkgName": "log4js",
          "InstalledVersion": "2.0.0",
          "FixedVersion": "2.0.5",
          "Severity": "CRITICAL",
          "Title": "log4js remote code execution",
          "Description": "A JNDI lookup allows remote code execution.",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-44228",
          "CVSS": {
            "nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "V3Score": 10.0},
            "redhat": {"V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", "V3Score": 9.0}
          }
        },
        {
          "VulnerabilityID": "CVE-2022-0001",
          "PkgName": "minimist",
          "InstalledVersion": "0.0.8",
          "FixedVersion": "",
          "Severity": "HIGH",
          "Title": "prototype pollution in minimist",
          "Description": "Prototype pollution via crafted arguments.",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-0001",
          "CVSS": {}
        },
        {
          "VulnerabilityID": "CVE-2021-44228",
          "PkgName": "log4js",
          "InstalledVersion": "2.0.0",
          "FixedVersion": "2.0.5",
          "Severity": "CRITICAL",
          "Title": "log4js remote code execution",
          "Description": "duplicate row that must be deduped",
          "CVSS": {}
        }
      ]
    },
    {
      "Target": "alpine:3.16",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-1234",
          "PkgName": "openssl",
          "InstalledVersion": "1.1.1",
          "FixedVersion": "1.1.1t",
          "Severity": "MEDIUM",
          "Title": "openssl info leak",
          "Description": "Timing side channel.",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-1234",
          "CVSS": {"ghsa": {"V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}}
        }
      ]
    }
  ]
}`

func TestParseTrivyJSON(t *testing.T) {
	findings := parseTrivyJSON(sampleJSON)

	// 4 raw vuln rows, one duplicate (CVE-2021-44228|log4js) deduped => 3.
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings (after dedupe), got %d: %v", len(findings), titles(findings))
	}

	byTitle := map[string]state.Finding{}
	for _, f := range findings {
		byTitle[f.Title] = f
		if !f.Validated {
			t.Errorf("finding %q: expected Validated=true", f.Title)
		}
		if f.CVSS != "" && !strings.HasPrefix(f.CVSS, "CVSS:3.1/") {
			t.Errorf("finding %q: CVSS = %q, want a v3.1 vector or empty", f.Title, f.CVSS)
		}
	}

	// Critical: severity mapped, NVD CVSS vector preferred over redhat, target =
	// the per-result Target (lockfile), CVE + pkg + fixed version in description.
	crit, ok := byTitle["log4js remote code execution (log4js)"]
	if !ok {
		t.Fatalf("missing critical finding; got titles: %v", titles(findings))
	}
	if crit.Severity != state.SeverityCritical {
		t.Errorf("critical: severity = %v, want critical", crit.Severity)
	}
	if crit.CVSS != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" {
		t.Errorf("critical: CVSS = %q, want the NVD vector", crit.CVSS)
	}
	if crit.Target != "package-lock.json" {
		t.Errorf("critical: Target = %q, want package-lock.json", crit.Target)
	}
	if !strings.Contains(crit.Description, "CVE-2021-44228") {
		t.Errorf("critical: Description = %q, want cve id", crit.Description)
	}
	if !strings.Contains(crit.Description, "fixed in 2.0.5") {
		t.Errorf("critical: Description = %q, want fixed version", crit.Description)
	}
	if !strings.Contains(crit.Evidence, "ref=https://avd.aquasec.com/nvd/cve-2021-44228") {
		t.Errorf("critical: Evidence = %q, want primary URL", crit.Evidence)
	}

	// High with no fixed version: description must say so honestly.
	high, ok := byTitle["prototype pollution in minimist (minimist)"]
	if !ok {
		t.Fatalf("missing high finding; got titles: %v", titles(findings))
	}
	if high.Severity != state.SeverityHigh {
		t.Errorf("high: severity = %v, want high", high.Severity)
	}
	if high.CVSS != "" {
		t.Errorf("high: CVSS = %q, want empty (no vector in sample)", high.CVSS)
	}
	if !strings.Contains(high.Description, "no fixed version") {
		t.Errorf("high: Description = %q, want 'no fixed version'", high.Description)
	}

	// Medium from the OS package set: CVSS vector picked from a non-nvd source.
	med, ok := byTitle["openssl info leak (openssl)"]
	if !ok {
		t.Fatalf("missing medium finding; got titles: %v", titles(findings))
	}
	if med.Severity != state.SeverityMedium {
		t.Errorf("medium: severity = %v, want medium", med.Severity)
	}
	if med.Target != "alpine:3.16" {
		t.Errorf("medium: Target = %q, want alpine:3.16", med.Target)
	}
	if med.CVSS == "" {
		t.Errorf("medium: CVSS empty, want the ghsa fallback vector")
	}
}

// TestParseTrivyJSON_Empty ensures non-JSON / empty output yields no findings
// (and no panic) rather than an error.
func TestParseTrivyJSON_Empty(t *testing.T) {
	for _, in := range []string{"", "   ", "not json at all", "{}", `{"Results":null}`} {
		if got := parseTrivyJSON(in); len(got) != 0 {
			t.Errorf("parseTrivyJSON(%q) = %d findings, want 0", in, len(got))
		}
	}
}

// TestTrivyMode pins target/param → subcommand inference.
func TestTrivyMode(t *testing.T) {
	cases := []struct {
		mode, target, want string
	}{
		{"", "nginx:1.21", "image"},
		{"", "alpine", "image"},
		{"", "/src/app", "fs"},
		{"", "./project", "fs"},
		{"", "C:\\Users\\dev\\app", "fs"},
		{"", "C:/Users/dev/app", "fs"},
		{"", "https://github.com/org/repo", "repo"},
		{"", "git@github.com:org/repo.git", "repo"},
		{"", "https://github.com/org/repo.git", "repo"},
		{"image", "/src/app", "image"},    // explicit mode overrides inference
		{"fs", "nginx:1.21", "fs"},        // explicit mode overrides inference
		{"repo", "anything", "repo"},      // explicit mode
		{"rootfs", "/mnt/root", "rootfs"}, // explicit mode
	}
	for _, c := range cases {
		if got := trivyMode(c.mode, c.target); got != c.want {
			t.Errorf("trivyMode(%q, %q) = %q, want %q", c.mode, c.target, got, c.want)
		}
	}
}

// TestExecute_GracefulDegrade exercises the path on a box WITHOUT trivy
// installed (CI/dev). Execute must succeed and emit the single "trivy not
// available" info finding rather than erroring.
//
// NOTE: the live shell-out path is NOT exercised here — by design there is no
// trivy present, so adapter.Detect returns "".
func TestExecute_GracefulDegrade(t *testing.T) {
	if adapter.Detect("trivy") != "" {
		t.Skip("trivy is installed; graceful-degrade path not applicable")
	}

	tool := New()
	res, err := tool.Execute(context.Background(), action.Action{
		ID:     "a1",
		Tool:   "trivyscan",
		Target: "nginx:1.21",
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
	if !strings.Contains(f.Title, "trivy not available") {
		t.Errorf("unexpected finding title: %q", f.Title)
	}
}

// TestToolMetadata pins the tool.Tool surface.
func TestToolMetadata(t *testing.T) {
	tool := New()
	if tool.Name() != "trivyscan" {
		t.Errorf("Name() = %q, want trivyscan", tool.Name())
	}
	if tool.Category() != action.CategoryScan {
		t.Errorf("Category() = %v, want CategoryScan", tool.Category())
	}
	if tool.MaxRisk() != action.RiskLow {
		t.Errorf("MaxRisk() = %v, want RiskLow", tool.MaxRisk())
	}
}

func titles(fs []state.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Title
	}
	return out
}
