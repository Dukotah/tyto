package report

import (
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
)

// The submission view must dedup an issue seen on many hosts into one finding
// listing all targets, surface the submission fields (CVSS, impact, repro,
// per-target evidence), and foreground noise separately without dropping it.
func TestRenderSubmissionDedupsAndShowsFields(t *testing.T) {
	eng := &engagement.Engagement{ID: "ENG-1", Client: "Acme"}
	st := state.New()

	for _, h := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		st.AddFinding(state.Finding{
			Title:       "TLS 1.0 enabled",
			Severity:    state.SeverityMedium,
			Target:      h,
			Tool:        "sslscan",
			Description: "Server negotiates the deprecated TLS 1.0 protocol.",
			Impact:      "An on-path attacker can downgrade and decrypt session traffic.",
			Repro:       "openssl s_client -tls1 -connect " + h + ":443",
			Evidence:    "TLSv1.0 accepted on " + h,
			CVSS:        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		})
	}
	// A noise finding that must be flagged, not foregrounded.
	st.AddFinding(state.Finding{
		Title: "IKEv2 detected", Severity: state.SeverityInfo, Target: "10.0.0.1", Tool: "nuclei",
	})

	out := RenderSubmission(eng, st)

	if !strings.Contains(out, "Actionable issues: 1") {
		t.Errorf("expected 1 actionable issue after dedup:\n%s", out)
	}
	// All three targets listed on the single correlated issue.
	for _, h := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if !strings.Contains(out, h) {
			t.Errorf("affected target %s missing from submission report", h)
		}
	}
	if !strings.Contains(out, "Affected target(s) (3)") {
		t.Errorf("expected affected-target count of 3:\n%s", out)
	}
	// Submission fields present.
	for _, want := range []string{"Impact:", "downgrade and decrypt", "Reproduction:", "openssl s_client", "Evidence:", "CVSS"} {
		if !strings.Contains(out, want) {
			t.Errorf("submission report missing %q", want)
		}
	}
	// Noise flagged separately, retained not dropped.
	if !strings.Contains(out, "Flagged as noise") || !strings.Contains(out, "IKEv2 detected") {
		t.Errorf("noise finding not flagged/retained:\n%s", out)
	}
}

func TestBuildSubmissionCVSSDerived(t *testing.T) {
	eng := &engagement.Engagement{ID: "E", Client: "C"}
	st := state.New()
	st.AddFinding(state.Finding{
		Title: "RCE", Severity: state.SeverityCritical, Target: "h", Tool: "exploit",
		CVSS: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	})
	s := BuildSubmission(eng, st)
	if len(s.Actionable) != 1 {
		t.Fatalf("expected 1 actionable, got %d", len(s.Actionable))
	}
	if got := s.Actionable[0].CVSS; got != 9.8 {
		t.Errorf("expected derived CVSS 9.8, got %v", got)
	}
}

// The standard Markdown report must surface the new Repro/Impact fields.
func TestRenderMarkdownShowsReproImpact(t *testing.T) {
	eng := &engagement.Engagement{ID: "E", Client: "C"}
	st := state.New()
	st.AddFinding(state.Finding{
		Title: "SSRF", Severity: state.SeverityHigh, Target: "http://h/", Tool: "webinject",
		Validated: true,
		Impact:    "Internal metadata endpoint reachable.",
		Repro:     "GET /fetch?url=http://169.254.169.254/",
	})
	out := Render(eng, st)
	if !strings.Contains(out, "impact: Internal metadata endpoint reachable.") {
		t.Errorf("markdown report missing impact field:\n%s", out)
	}
	if !strings.Contains(out, "repro: GET /fetch?url=") {
		t.Errorf("markdown report missing repro field:\n%s", out)
	}
}

// The HTML report must surface the new Repro/Impact fields (escaped).
func TestRenderHTMLShowsReproImpact(t *testing.T) {
	eng := &engagement.Engagement{ID: "E", Client: "C"}
	st := state.New()
	st.AddFinding(state.Finding{
		Title: "SSRF", Severity: state.SeverityHigh, Target: "http://h/", Tool: "webinject",
		Impact: "Cloud metadata exposure.",
		Repro:  "curl http://h/fetch?url=x",
	})
	data, err := RenderHTML(eng, st)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if !strings.Contains(out, "Impact") || !strings.Contains(out, "Cloud metadata exposure.") {
		t.Errorf("HTML report missing Impact field")
	}
	if !strings.Contains(out, "Reproduction") || !strings.Contains(out, "curl http://h/fetch") {
		t.Errorf("HTML report missing Reproduction field")
	}
}
