package report

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/evidence"
	"github.com/dukotah/tyto/internal/state"
)

// A report built with an evidence store must render the captured request/response
// under the finding it is bound to (by finding ID), in both Markdown and JSON.
func TestRenderWithEvidenceAttachesCapturedTraffic(t *testing.T) {
	eng := &engagement.Engagement{ID: "ENG-1", Client: "Acme"}
	st := state.New()
	st.AddFinding(state.Finding{
		ID: "HTTP-x1", Title: "SSRF", Severity: state.SeverityHigh, Target: "http://h/",
		Tool: "webinject", Validated: true,
	})

	ev := evidence.NewMemStore()
	id := ev.Put(evidence.Record{
		Method:          http.MethodGet,
		URL:             "http://h/fetch?url=http://169.254.169.254/",
		Status:          200,
		RequestHeaders:  http.Header{"User-Agent": []string{"tyto-webinject"}},
		ResponseHeaders: http.Header{"Content-Type": []string{"text/plain"}},
		ResponseBody:    "ami-id\niam/security-credentials/",
	})
	ev.Associate("HTTP-x1", id)

	md := RenderWithEvidence(eng, st, ev)
	for _, want := range []string{
		"evidence (" + id + ")",
		"GET http://h/fetch?url=http://169.254.169.254/ -> 200",
		"```http",
		"User-Agent: tyto-webinject",
		"iam/security-credentials/",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown report missing %q:\n%s", want, md)
		}
	}

	raw, err := RenderJSONWithEvidence(eng, st, ev)
	if err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got.Findings))
	}
	recs := got.Findings[0].EvidenceRecords
	if len(recs) != 1 {
		t.Fatalf("expected 1 evidence record in JSON, got %d", len(recs))
	}
	if recs[0].EvidenceID != id {
		t.Errorf("JSON evidence_id = %q, want %q", recs[0].EvidenceID, id)
	}
	if recs[0].FindingID != "HTTP-x1" {
		t.Errorf("JSON finding_id = %q, want %q", recs[0].FindingID, "HTTP-x1")
	}
	if recs[0].Status != 200 {
		t.Errorf("JSON evidence status = %d, want 200", recs[0].Status)
	}
}

// A report built without an evidence store (or with a store that has no record
// for a finding) must render exactly as the plain renderers — no regressions.
func TestRenderWithoutEvidenceMatchesPlain(t *testing.T) {
	eng := &engagement.Engagement{ID: "E", Client: "C"}
	st := state.New()
	st.AddFinding(state.Finding{
		ID: "F-1", Title: "SSRF", Severity: state.SeverityHigh, Target: "http://h/",
		Tool: "webinject", Validated: true, Impact: "x", Repro: "y",
	})

	if RenderWithEvidence(eng, st, nil) != Render(eng, st) {
		t.Errorf("RenderWithEvidence(nil) diverged from Render")
	}
	// An empty store (no associations) must also be byte-identical to plain.
	if RenderWithEvidence(eng, st, evidence.NewMemStore()) != Render(eng, st) {
		t.Errorf("RenderWithEvidence(empty store) diverged from Render")
	}

	plainJSON, err := RenderJSON(eng, st)
	if err != nil {
		t.Fatal(err)
	}
	evJSON, err := RenderJSONWithEvidence(eng, st, evidence.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	if string(plainJSON) != string(evJSON) {
		t.Errorf("JSON with empty evidence store diverged from plain JSON")
	}
}
