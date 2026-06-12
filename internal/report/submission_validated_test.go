package report

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/validate"
)

// fixedFetcher returns the same response for every re-fetch, so the validation
// brain's live re-proof is deterministic in tests (no network).
type fixedFetcher struct {
	header http.Header
	body   string
}

func (f fixedFetcher) Fetch(_ context.Context, _ string) (validate.Response, error) {
	return validate.Response{Status: 200, Header: f.header, Body: f.body}, nil
}

// findByTitle locates a submission finding across both buckets.
func findByTitle(s Submission, title string) (SubmissionFinding, string, bool) {
	for _, f := range s.Actionable {
		if f.Title == title {
			return f, "actionable", true
		}
	}
	for _, f := range s.Noise {
		if f.Title == title {
			return f, "noise", true
		}
	}
	return SubmissionFinding{}, "", false
}

// TestBuildSubmissionValidated_GatesAndRetains proves the adversarial gate:
// a finding that re-proves live is confirmed (Validated) and a finding that the
// re-proof refutes is NOT dropped — it is retained, tagged, in the noise bucket.
func TestBuildSubmissionValidated_GatesAndRetains(t *testing.T) {
	st := state.New()
	st.AddFinding(state.Finding{
		Title:    "Missing security header: Content-Security-Policy", // re-fetch shows no CSP -> confirmed
		Severity: state.SeverityHigh, Target: "http://app.test/", Tool: "webcheck",
	})
	st.AddFinding(state.Finding{
		Title:    "Missing security header: X-Frame-Options", // re-fetch shows XFO present -> refuted
		Severity: state.SeverityMedium, Target: "http://app.test/", Tool: "webcheck",
	})

	// The live re-fetch carries X-Frame-Options (so that "missing" claim is false)
	// but no Content-Security-Policy (so that "missing" claim still holds).
	hdr := http.Header{}
	hdr.Set("X-Frame-Options", "DENY")
	fetch := fixedFetcher{header: hdr}

	eng := &engagement.Engagement{ID: "e1", Client: "acme"}
	s := BuildSubmissionValidated(context.Background(), eng, st, fetch)

	// The CSP finding re-proved -> must be Validated, wherever triage placed it.
	csp, _, ok := findByTitle(s, "Missing security header: Content-Security-Policy")
	if !ok {
		t.Fatal("confirmed CSP finding missing from the submission entirely (it must be retained)")
	}
	if !csp.Validated {
		t.Errorf("CSP finding re-proved live but Validated=false; the gate failed to mark it confirmed")
	}

	// The X-Frame-Options finding was refuted -> must be RETAINED as noise (never
	// silently dropped) and clearly marked unvalidated with the reason.
	xfo, bucket, ok := findByTitle(s, "Missing security header: X-Frame-Options")
	if !ok {
		t.Fatal("refuted X-Frame-Options finding was dropped; the gate must retain set-aside findings")
	}
	if bucket != "noise" {
		t.Errorf("refuted finding should be in the noise bucket, got %q", bucket)
	}
	if xfo.Validated {
		t.Errorf("refuted finding must not be marked Validated")
	}
	if !xfo.Noise {
		t.Errorf("refuted finding should carry the Noise tag")
	}
	if !strings.Contains(strings.ToLower(xfo.Description), "refuted") {
		t.Errorf("refuted finding should record why it was set aside; description=%q", xfo.Description)
	}
}

// TestBuildSubmissionValidated_UnreachableIsRetainedNotConfirmed proves that
// when re-proof cannot run (target unreachable), findings are NOT confirmed
// (refute-by-default) yet are still retained for operator review.
func TestBuildSubmissionValidated_UnreachableIsRetainedNotConfirmed(t *testing.T) {
	st := state.New()
	st.AddFinding(state.Finding{
		Title: "Reflected XSS in parameter q", Severity: state.SeverityHigh,
		Target: "http://app.test/search?q=test", Tool: "webinject",
	})
	// A fetcher that never reflects the marker -> the XSS cannot re-prove.
	fetch := fixedFetcher{body: "<html>static</html>"}

	eng := &engagement.Engagement{ID: "e2", Client: "acme"}
	s := BuildSubmissionValidated(context.Background(), eng, st, fetch)

	if len(s.Actionable) != 0 {
		t.Errorf("an unreproved XSS must not be actionable (refute-by-default); got %d actionable", len(s.Actionable))
	}
	if _, _, ok := findByTitle(s, "Reflected XSS in parameter q"); !ok {
		t.Error("unreproved finding was dropped; it must be retained as noise for review")
	}
}
