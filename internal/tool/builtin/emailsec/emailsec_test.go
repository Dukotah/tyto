package emailsec

import (
	"context"
	"errors"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// fakeResolver is a network-free txtResolver. It returns canned TXT records
// keyed by query name; a name with no entry yields an error, which the tool
// treats as "record absent".
type fakeResolver struct {
	txt map[string][]string
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if recs, ok := f.txt[name]; ok {
		return recs, nil
	}
	return nil, errors.New("no such host")
}

// run executes the tool against a fake resolver with the given canned records.
func run(t *testing.T, txt map[string][]string) action.Result {
	t.Helper()
	tool := &Tool{res: fakeResolver{txt: txt}}
	res, err := tool.Execute(context.Background(), action.Action{ID: "A1", Target: "example.com"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected res.Success=true, got false (err=%q)", res.Err)
	}
	return res
}

// findFinding returns the first finding with the given title, or nil.
func findFinding(res action.Result, title string) *state.Finding {
	for i := range res.Findings {
		if res.Findings[i].Title == title {
			return &res.Findings[i]
		}
	}
	return nil
}

func assertFinding(t *testing.T, res action.Result, title string, sev state.Severity) {
	t.Helper()
	f := findFinding(res, title)
	if f == nil {
		t.Fatalf("expected a finding titled %q, none present", title)
	}
	if f.Severity != sev {
		t.Errorf("finding %q: severity = %v, want %v", title, f.Severity, sev)
	}
	if !f.Validated {
		t.Errorf("finding %q: Validated = false, want true", title)
	}
	if f.Target != "example.com" {
		t.Errorf("finding %q: Target = %q, want %q", title, f.Target, "example.com")
	}
}

func assertNoFinding(t *testing.T, res action.Result, title string) {
	t.Helper()
	if f := findFinding(res, title); f != nil {
		t.Errorf("did not expect a finding titled %q, but found one (sev=%v)", title, f.Severity)
	}
}

func TestExecute_NoSPFNoDMARC(t *testing.T) {
	// No TXT records anywhere -> both policies absent.
	res := run(t, map[string][]string{})

	assertFinding(t, res, "No SPF record (email spoofing risk)", state.SeverityMedium)
	assertFinding(t, res, "No DMARC record", state.SeverityMedium)
}

func TestExecute_PermissiveSPFAndDMARCNone(t *testing.T) {
	res := run(t, map[string][]string{
		"example.com":        {"some-verification=abc", "v=spf1 +all"},
		"_dmarc.example.com": {"v=DMARC1; p=none; rua=mailto:dmarc@example.com"},
	})

	assertFinding(t, res, "Overly permissive SPF (+all)", state.SeverityHigh)
	assertFinding(t, res, "DMARC policy is p=none (monitor only)", state.SeverityLow)

	// The weakness findings replace the "missing" ones.
	assertNoFinding(t, res, "No SPF record (email spoofing risk)")
	assertNoFinding(t, res, "No DMARC record")

	// Evidence should carry the offending records.
	if f := findFinding(res, "Overly permissive SPF (+all)"); f != nil && f.Evidence != "v=spf1 +all" {
		t.Errorf("SPF evidence = %q, want %q", f.Evidence, "v=spf1 +all")
	}
}

func TestExecute_StrictSPFAndDMARCReject(t *testing.T) {
	res := run(t, map[string][]string{
		"example.com":        {"v=spf1 include:_spf.example.net -all"},
		"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
	})

	// No weakness findings of any kind.
	assertNoFinding(t, res, "No SPF record (email spoofing risk)")
	assertNoFinding(t, res, "Overly permissive SPF (+all)")
	assertNoFinding(t, res, "No DMARC record")
	assertNoFinding(t, res, "DMARC policy is p=none (monitor only)")

	// The informational summary is always present.
	if findFinding(res, "Email-security DNS posture for example.com") == nil {
		t.Errorf("expected the informational summary finding to be present")
	}
}
