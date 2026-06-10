package cvematch

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ulikunitz/xz"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// plainFeed has three cve_items for the nginx query (1.18.0):
//   - CVE-2024-0001: exact version 1.18.0           -> matches
//   - CVE-2024-0002: range versionEndExcluding 1.20.0 -> matches (1.18.0 in range)
//   - CVE-2024-0003: different product (apache)        -> no match
const plainFeed = `{
  "cve_items": [
    {
      "id": "CVE-2024-0001",
      "descriptions": [{"lang": "en", "value": "Exact-version flaw in nginx 1.18.0."}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", "vulnerable": true}
      ]}]}]
    },
    {
      "id": "CVE-2024-0002",
      "descriptions": [{"lang": "en", "value": "Range flaw affecting nginx before 1.20.0."}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": true, "versionEndExcluding": "1.20.0"}
      ]}]}]
    },
    {
      "id": "CVE-2024-0003",
      "descriptions": [{"lang": "en", "value": "Unrelated apache flaw."}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*", "vulnerable": true}
      ]}]}]
    }
  ]
}`

// xzFeed is a separate CVE for nginx 1.18.0, written .xz-compressed to prove
// the xz decode path runs.
const xzFeed = `{
  "cve_items": [
    {
      "id": "CVE-2024-9999",
      "descriptions": [{"lang": "en", "value": "Compressed-feed flaw in nginx 1.18.0."}],
      "metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 4.3, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", "vulnerable": true}
      ]}]}]
    }
  ]
}`

func writeXZ(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	w, err := xz.NewWriter(f)
	if err != nil {
		t.Fatalf("xz writer: %v", err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatalf("xz write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("xz close: %v", err)
	}
}

func TestExecuteMatchesPlainAndXZ(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "CVE-2024.json"), []byte(plainFeed), 0o644); err != nil {
		t.Fatal(err)
	}
	writeXZ(t, filepath.Join(dir, "CVE-2025.json.xz"), xzFeed)

	res, err := New().Execute(context.Background(), action.Action{
		ID:     "a1",
		Target: "example.test",
		Params: map[string]string{"product": "nginx", "version": "1.18.0", "nvd": dir},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, output=%q", res.Output)
	}

	ids := map[string]state.Finding{}
	for _, f := range res.Findings {
		// Every match is an inference, never directly validated.
		if f.Validated {
			t.Errorf("%s: Validated must be false (inference, not confirmed)", f.Title)
		}
		// Title is "CVE-... affects nginx 1.18.0"; key off the CVE id prefix.
		ids[f.Title] = f
	}

	want := map[string]struct {
		sev  state.Severity
		cvss string
	}{
		"CVE-2024-0001 affects nginx 1.18.0": {state.SeverityHigh, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		"CVE-2024-0002 affects nginx 1.18.0": {state.SeverityCritical, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		"CVE-2024-9999 affects nginx 1.18.0": {state.SeverityMedium, "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"},
	}
	if len(res.Findings) != len(want) {
		t.Fatalf("got %d findings, want %d: %v", len(res.Findings), len(want), res.Output)
	}
	for title, w := range want {
		f, ok := ids[title]
		if !ok {
			t.Errorf("missing expected finding %q", title)
			continue
		}
		if f.Severity != w.sev {
			t.Errorf("%s: severity=%v want %v", title, f.Severity, w.sev)
		}
		if f.CVSS != w.cvss {
			t.Errorf("%s: cvss=%q want %q", title, f.CVSS, w.cvss)
		}
		if f.Evidence == "" {
			t.Errorf("%s: expected non-empty CPE evidence", title)
		}
	}
	// The unrelated apache CVE must NOT appear.
	for title := range ids {
		if title == "CVE-2024-0003 affects nginx 1.18.0" {
			t.Errorf("apache CVE should not have matched nginx")
		}
	}
}

func TestExecuteNoFeeds(t *testing.T) {
	dir := t.TempDir() // empty
	res, err := New().Execute(context.Background(), action.Action{
		ID:     "a2",
		Target: "example.test",
		Params: map[string]string{"product": "nginx", "version": "1.18.0", "nvd": dir},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success {
		t.Fatal("expected success even with no feeds")
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != state.SeverityInfo {
		t.Fatalf("expected one info finding, got %+v", res.Findings)
	}
	if got := res.Findings[0].Title; got != "No NVD feeds available (set TYTO_NVD or download feeds)" {
		t.Fatalf("unexpected title %q", got)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.18.0", "1.18.0", 0},
		{"1.18.0", "1.20.0", -1},
		{"1.20.0", "1.18.0", 1},
		{"1.18", "1.18.0", 0}, // missing trailing segment == 0
		{"1.2", "1.10", -1},   // numeric, not lexical
		{"2.4.1", "2.4", 1},   // extra segment > 0
		{"1.0a", "1.0b", -1},  // non-numeric -> string compare
		{"1.0.0", "1.0.0", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseServerHeader(t *testing.T) {
	cases := []struct {
		in               string
		product, version string
		ok               bool
	}{
		{"nginx/1.18.0", "nginx", "1.18.0", true},
		{"nginx/1.18.0 (Ubuntu)", "nginx", "1.18.0", true},
		{"Apache/2.4.41 (Unix)", "Apache", "2.4.41", true},
		{"nginx", "nginx", "", true}, // product only, no version
		{"", "", "", false},
		{"   ", "", "", false},
	}
	for _, c := range cases {
		p, v, ok := parseServerHeader(c.in)
		if p != c.product || v != c.version || ok != c.ok {
			t.Errorf("parseServerHeader(%q)=(%q,%q,%v) want (%q,%q,%v)", c.in, p, v, ok, c.product, c.version, c.ok)
		}
	}
}

func TestParseCPE(t *testing.T) {
	p, v := parseCPE("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")
	if p != "nginx" || v != "1.18.0" {
		t.Fatalf("parseCPE got (%q,%q)", p, v)
	}
	if p, v := parseCPE("garbage"); p != "" || v != "" {
		t.Fatalf("expected empty for malformed CPE, got (%q,%q)", p, v)
	}
}
