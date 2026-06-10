package report

import (
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
)

func TestRenderHTMLWellFormed(t *testing.T) {
	eng := &engagement.Engagement{ID: "ENG-2026-001", Client: "Acme Corp"}
	eng.Authorization.AuthorizedBy = "Jane Approver"
	eng.Authorization.AgreementRef = "MSA-42"

	st := state.New()
	st.AddFinding(state.Finding{
		Title:       "SQL injection",
		Severity:    state.SeverityHigh,
		Target:      "http://h/",
		Tool:        "webinject",
		Validated:   true,
		Description: "error-based SQLi in parameter q",
		Evidence:    "id=1' -> SQL syntax error",
		CVSS:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	})
	st.AddFinding(state.Finding{
		Title:    "Server version disclosed",
		Severity: state.SeverityLow,
		Target:   "http://h/",
		Tool:     "webcheck",
	})

	data, err := RenderHTML(eng, st)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)

	if len(out) == 0 {
		t.Fatal("rendered HTML is empty")
	}
	if !strings.Contains(out, "<html") {
		t.Error("output missing <html element")
	}
	if !strings.Contains(out, "ENG-2026-001") {
		t.Error("output missing engagement ID")
	}
	if !strings.Contains(out, "SQL injection") {
		t.Error("output missing finding title")
	}
	// report.Build derives the CVSS base score (9.8) from the vector via
	// internal/cvss; the report must show it.
	if !strings.Contains(out, "9.8") {
		t.Errorf("output missing CVSS score 9.8 derived from vector")
	}
}

func TestRenderHTMLEscapesFindingText(t *testing.T) {
	eng := &engagement.Engagement{ID: "E", Client: "C"}
	st := state.New()
	st.AddFinding(state.Finding{
		Title:    "<img src=x>",
		Severity: state.SeverityHigh,
		Target:   "http://h/",
		Tool:     "webinject",
	})

	data, err := RenderHTML(eng, st)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)

	if strings.Contains(out, "<img") {
		t.Error("untrusted finding title was NOT escaped: literal <img present in output")
	}
	if !strings.Contains(out, "&lt;img") {
		t.Error("expected escaped &lt;img in output")
	}
}
