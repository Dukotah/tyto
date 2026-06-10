package testssladapter

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// sampleJSON is a captured-style testssl.sh --jsonfile - array with a CRITICAL
// (heartbleed), a MEDIUM (weak cipher), plus OK and INFO entries that must be
// skipped as noise.
const sampleJSON = `[
  {"id":"heartbleed","severity":"CRITICAL","finding":"vulnerable (NOT ok)","cve":"CVE-2014-0160"},
  {"id":"cipher_x07","severity":"MEDIUM","finding":"Weak cipher TLS_RSA_WITH_RC4_128_SHA offered"},
  {"id":"protocol_tls1_2","severity":"OK","finding":"offered"},
  {"id":"service","severity":"INFO","finding":"HTTP"},
  {"id":"BREACH","severity":"LOW","finding":"potentially VULNERABLE","cve":"CVE-2013-3587"}
]`

func TestParseTestssl_FiltersAndMaps(t *testing.T) {
	findings := parseTestssl(sampleJSON)

	// Expect heartbleed (CRITICAL), cipher (MEDIUM), BREACH (LOW); OK + INFO skipped.
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(findings), findings)
	}

	byID := map[string]state.Finding{}
	for _, f := range findings {
		byID[strings.TrimPrefix(f.Title, "TLS: ")] = f
	}

	hb, ok := byID["heartbleed"]
	if !ok {
		t.Fatalf("heartbleed finding missing")
	}
	if hb.Severity != state.SeverityCritical {
		t.Errorf("heartbleed severity = %v, want critical", hb.Severity)
	}
	if hb.Description != "vulnerable (NOT ok)" {
		t.Errorf("heartbleed description = %q", hb.Description)
	}
	if !strings.Contains(hb.Evidence, "CVE-2014-0160") || !strings.Contains(hb.Evidence, "heartbleed") {
		t.Errorf("heartbleed evidence missing id+cve: %q", hb.Evidence)
	}
	if !hb.Validated {
		t.Errorf("heartbleed should be Validated")
	}

	cipher, ok := byID["cipher_x07"]
	if !ok {
		t.Fatalf("cipher finding missing")
	}
	if cipher.Severity != state.SeverityMedium {
		t.Errorf("cipher severity = %v, want medium", cipher.Severity)
	}
	// No CVE on this entry: evidence is just the id.
	if cipher.Evidence != "cipher_x07" {
		t.Errorf("cipher evidence = %q, want id only", cipher.Evidence)
	}

	breach, ok := byID["BREACH"]
	if !ok {
		t.Fatalf("BREACH finding missing")
	}
	if breach.Severity != state.SeverityLow {
		t.Errorf("BREACH severity = %v, want low", breach.Severity)
	}

	// OK / INFO entries must not appear.
	if _, bad := byID["protocol_tls1_2"]; bad {
		t.Errorf("OK entry should be skipped")
	}
	if _, bad := byID["service"]; bad {
		t.Errorf("INFO entry should be skipped")
	}
}

func TestParseTestssl_WarnMapsLow(t *testing.T) {
	findings := parseTestssl(`[{"id":"w","severity":"WARN","finding":"could not test"}]`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != state.SeverityLow {
		t.Errorf("WARN severity = %v, want low", findings[0].Severity)
	}
}

func TestParseTestssl_EmptyAndGarbage(t *testing.T) {
	for _, in := range []string{"", "   ", "not json", "{", "[}", "null", "[]"} {
		if got := parseTestssl(in); len(got) != 0 {
			t.Errorf("parseTestssl(%q) = %d findings, want 0", in, len(got))
		}
	}
}

func TestExecute_GracefulDegrade(t *testing.T) {
	// testssl.sh is not installed in this environment, so Execute must emit the
	// single "not available" info finding and succeed.
	tl := New()
	res, err := tl.Execute(context.Background(), action.Action{ID: "a1", Target: "example.com"})
	if err != nil {
		t.Fatalf("Execute returned err: %v", err)
	}
	if !res.Success {
		t.Errorf("Success = false, want true on graceful degrade")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo {
		t.Errorf("severity = %v, want info", f.Severity)
	}
	if !strings.Contains(f.Title, "not available") {
		t.Errorf("title = %q, want 'not available'", f.Title)
	}
}

func TestHostPort(t *testing.T) {
	cases := map[string]string{
		"example.com":             "example.com:443",
		"example.com:8443":        "example.com:8443",
		"https://example.com/foo": "example.com:443",
		"https://h:8443/x?q=1":    "h:8443",
		"":                        ":443",
		"1.2.3.4":                 "1.2.3.4:443",
	}
	for in, want := range cases {
		if got := hostPort(in); got != want {
			t.Errorf("hostPort(%q) = %q, want %q", in, got, want)
		}
	}
}
