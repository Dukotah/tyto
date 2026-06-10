package cveindex

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ulikunitz/xz"
)

// plainFeed is a {cve_items:[...]} fixture with three nginx CVEs and one apache
// CVE. CVE-NGINX-EXACT is pinned to nginx 1.18.0; CVE-NGINX-RANGE covers nginx
// < 1.20.0 (so 1.18.0 is in range); CVE-NGINX-OUTOFRANGE only covers >= 1.21.0
// (so 1.18.0 is NOT a match); CVE-APACHE-OTHER is a different product.
const plainFeed = `{
  "cve_items": [
    {
      "id": "CVE-NGINX-EXACT",
      "descriptions": [{"lang": "en", "value": "nginx exact version flaw"}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:N"}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", "vulnerable": true}
      ]}]}]
    },
    {
      "id": "CVE-NGINX-RANGE",
      "descriptions": [{"lang": "en", "value": "nginx range flaw"}],
      "metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.0/AV:N"}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": true, "versionEndExcluding": "1.20.0"}
      ]}]}]
    },
    {
      "id": "CVE-NGINX-OUTOFRANGE",
      "descriptions": [{"lang": "en", "value": "nginx newer-only flaw"}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:L"}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": true, "versionStartIncluding": "1.21.0"}
      ]}]}]
    },
    {
      "id": "CVE-APACHE-OTHER",
      "descriptions": [{"lang": "en", "value": "apache flaw"}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*", "vulnerable": true}
      ]}]}]
    }
  ]
}`

// xzFeed is a separate feed compressed with xz; it contributes one more nginx
// CVE (general, no bounds) so we can assert .xz-sourced rows are indexed too.
const xzFeed = `{
  "cve_items": [
    {
      "id": "CVE-NGINX-FROMXZ",
      "descriptions": [{"lang": "en", "value": "nginx flaw from xz feed"}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 6.5, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:A"}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": true}
      ]}]}]
    }
  ]
}`

func writeXZ(t *testing.T, path, content string) {
	t.Helper()
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatalf("xz NewWriter: %v", err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatalf("xz write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("xz close: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write xz file: %v", err)
	}
}

func TestBuildAndQuery(t *testing.T) {
	feedsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(feedsDir, "CVE-2021.json"), []byte(plainFeed), 0o600); err != nil {
		t.Fatalf("write plain feed: %v", err)
	}
	writeXZ(t, filepath.Join(feedsDir, "CVE-2022.json.xz"), xzFeed)
	// A junk file that must be skipped without aborting Build.
	if err := os.WriteFile(filepath.Join(feedsDir, "CVE-broken.json"), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write broken feed: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "cve.db")
	rows, err := Build(context.Background(), feedsDir, dbPath)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rows == 0 {
		t.Fatalf("Build inserted 0 rows, want > 0")
	}

	ix, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ix.Close()

	matches, err := ix.Query("nginx", "1.18.0")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	got := map[string]Match{}
	for _, m := range matches {
		if _, dup := got[m.CVEID]; dup {
			t.Fatalf("duplicate CVE in results: %s", m.CVEID)
		}
		got[m.CVEID] = m
	}

	// Expected: EXACT (1.18.0), RANGE (<1.20.0), FROMXZ (general). NOT
	// OUTOFRANGE (>=1.21.0) and NOT the apache CVE (different product).
	want := []string{"CVE-NGINX-EXACT", "CVE-NGINX-RANGE", "CVE-NGINX-FROMXZ"}
	if len(matches) != len(want) {
		t.Fatalf("got %d matches %v, want %d %v", len(matches), matches, len(want), want)
	}
	for _, id := range want {
		if _, ok := got[id]; !ok {
			t.Errorf("missing expected match %s; got %v", id, matches)
		}
	}
	if _, ok := got["CVE-NGINX-OUTOFRANGE"]; ok {
		t.Errorf("CVE-NGINX-OUTOFRANGE should not match nginx 1.18.0")
	}
	if _, ok := got["CVE-APACHE-OTHER"]; ok {
		t.Errorf("apache CVE should not match a nginx query")
	}

	// Sorted by score descending: RANGE(9.1) > EXACT(5.0)... and FROMXZ(6.5).
	// So order should be RANGE, FROMXZ, EXACT.
	if matches[0].CVEID != "CVE-NGINX-RANGE" {
		t.Errorf("expected highest-score CVE-NGINX-RANGE first, got %s", matches[0].CVEID)
	}
	for i := 1; i < len(matches); i++ {
		if matches[i-1].Score < matches[i].Score {
			t.Errorf("results not sorted by score desc: %v", matches)
		}
	}

	// CVSS fields carried through.
	if m := got["CVE-NGINX-RANGE"]; m.Severity != "CRITICAL" || m.Score != 9.1 || m.Vector != "CVSS:3.0/AV:N" {
		t.Errorf("CVSS not carried through for RANGE: %+v", m)
	}

	// A product with no rows yields an empty result, not an error.
	none, err := ix.Query("doesnotexist", "1.0")
	if err != nil {
		t.Fatalf("Query(no rows): %v", err)
	}
	if len(none) != 0 {
		t.Errorf("expected no matches for unknown product, got %v", none)
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
		{"1.2", "1.2.0", 0},      // missing segment treated as 0
		{"1.10", "1.9", 1},       // numeric, not lexical
		{"2", "1.9.9", 1},        // major dominates
		{"1.0.0a", "1.0.0b", -1}, // non-numeric segment, string compare
		{"1.0.0", "1.0.0a", -1},  // "0" vs "0a": string compare since one side non-numeric
		{"", "0", 0},             // empty == 0
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}
