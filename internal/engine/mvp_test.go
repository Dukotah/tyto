package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/planner"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/report"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool"
	"github.com/dukotah/tyto/internal/tool/builtin/httpprobe"
	"github.com/dukotah/tyto/internal/tool/builtin/webcheck"
)

// TestMVPPipelineEndToEnd drives the full v0.1 ship line against a real local
// HTTP server: fingerprint -> safe vuln checks -> validated, grouped report —
// every action passing through the Scope Guard. This is the MVP acceptance test.
func TestMVPPipelineEndToEnd(t *testing.T) {
	// An intentionally unhardened server (no security headers, versioned Server).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "test-srv/1.0")
		_, _ = w.Write([]byte("<html><title>Demo</title></html>"))
	}))
	defer srv.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))

	eng := &engagement.Engagement{
		ID: "MVP", Client: "Demo Co",
		Authorization: engagement.Authorization{AuthorizedBy: "Demo CISO", AgreementRef: "REF-MVP"},
		Scope:         engagement.Scope{InScope: []engagement.Target{{Type: engagement.TargetIP, Value: host}}},
		RoE:           engagement.RoE{MaxRisk: "medium", AllowedCategories: []string{"recon", "scan"}},
	}

	reg := tool.NewRegistry()
	reg.MustRegister(httpprobe.New())
	reg.MustRegister(webcheck.New())
	snap := map[string]guard.ToolMeta{}
	for _, tl := range reg.All() {
		snap[tl.Name()] = guard.ToolMeta{Category: tl.Category(), MaxRisk: tl.MaxRisk()}
	}

	// A scripted planner: fingerprint, then run the safe web checks. No Ollama
	// needed — the mock supplies the plan; the real tools do the work.
	plan := fmt.Sprintf(`{"actions":[
	  {"tool":"httpprobe","category":"recon","target":%q,"risk":"low","params":{},"rationale":"fingerprint"},
	  {"tool":"webcheck","category":"scan","target":%q,"risk":"low","params":{},"rationale":"safe checks"}
	]}`, srv.URL, srv.URL)

	st := state.New()
	eg := New(eng, guard.New(eng, snap, nil), planner.New(&llm.Mock{Responses: []string{plan}}),
		reg, st, audit.NewLog(io.Discard), io.Discard, Options{MaxCycles: 1})
	if err := eg.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	// The pipeline should have discovered the service and confirmed real issues.
	var validated, headerFindings int
	for _, f := range st.Findings() {
		if f.Validated {
			validated++
		}
		if strings.Contains(f.Title, "Missing security header") {
			headerFindings++
		}
	}
	if headerFindings == 0 {
		t.Fatalf("expected missing-security-header findings, got none of %d findings", len(st.Findings()))
	}
	if validated == 0 {
		t.Fatal("expected validated findings from direct observation")
	}

	// The report renders, groups by target, and separates validated findings.
	md := report.Render(eng, st)
	if !strings.Contains(md, "Validated findings") || !strings.Contains(md, srv.URL) {
		t.Fatalf("report missing expected sections:\n%s", md)
	}
	if !strings.Contains(md, "Scope hash:") {
		t.Fatal("report should bind the signed scope hash")
	}

	// JSON export is well-formed and carries the totals.
	jb, err := report.RenderJSON(eng, st)
	if err != nil || !strings.Contains(string(jb), `"validated"`) {
		t.Fatalf("json report: err=%v body=%s", err, jb)
	}

	// The guard still blocks an unauthorized action even mid-pipeline.
	d := guard.New(eng, snap, nil).Evaluate(action.Action{Tool: "webcheck", Target: "10.0.0.1"})
	if d.IsAllowed() {
		t.Fatal("out-of-scope target must still be denied")
	}
}
