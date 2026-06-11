package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/engine"
	"github.com/dukotah/tyto/internal/state"
)

const testEngagementPath = "../../configs/localhost.engagement.yaml"

// newTestConsole builds a console with a loaded engagement and a state holding a
// couple of findings, so the read/report handlers have something to project.
func newTestConsole(t *testing.T) *console {
	t.Helper()
	eng, err := engagement.Load(testEngagementPath)
	if err != nil {
		t.Fatalf("load engagement: %v", err)
	}
	st := state.New()
	st.AddFinding(state.Finding{
		Title: "Missing security headers", Severity: state.SeverityMedium,
		Target: "http://127.0.0.1:8080/", Tool: "webcheck", Validated: true,
		Description: "No Content-Security-Policy header.",
	})
	st.AddFinding(state.Finding{
		Title: "Server banner discloses version", Severity: state.SeverityLow,
		Target: "http://127.0.0.1:8080/", Tool: "httpprobe",
	})
	return &console{
		subs:    map[chan engine.Event]struct{}{},
		pending: map[string]chan bool{},
		eng:     eng,
		st:      st,
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		"ENG-LOCALHOST":     "ENG-LOCALHOST",
		"a b/c\\d":          "a-b-c-d",
		"../../etc/passwd":  "------etc-passwd",
		"name\"with;quotes": "name-with-quotes",
		"under_score-1":     "under_score-1",
	}
	for in, want := range cases {
		if got := sanitizeFilename(in); got != want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHandleReportFormats(t *testing.T) {
	c := newTestConsole(t)
	formats := []struct {
		q           string
		wantCT      string
		wantExt     string
		wantContain string
	}{
		{"md", "text/markdown", ".md", "Engagement report"},
		{"", "text/markdown", ".md", "Engagement report"}, // default
		{"html", "text/html", ".html", "<"},
		{"sarif", "application/sarif+json", ".sarif", "runs"},
		{"json", "application/json", ".json", "engagement_id"},
	}
	for _, f := range formats {
		req := httptest.NewRequest(http.MethodGet, "/api/report?format="+f.q, nil)
		rec := httptest.NewRecorder()
		c.handleReport(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("format %q: status %d, body %q", f.q, rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, f.wantCT) {
			t.Errorf("format %q: content-type %q, want contains %q", f.q, ct, f.wantCT)
		}
		if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, f.wantExt) || !strings.Contains(cd, "ENG-LOCALHOST") {
			t.Errorf("format %q: content-disposition %q, want ext %q + engagement id", f.q, cd, f.wantExt)
		}
		if body := rec.Body.String(); !strings.Contains(body, f.wantContain) {
			t.Errorf("format %q: body missing %q; got %.120q", f.q, f.wantContain, body)
		}
	}
}

func TestHandleReportNoEngagement(t *testing.T) {
	c := &console{subs: map[chan engine.Event]struct{}{}, pending: map[string]chan bool{}}
	req := httptest.NewRequest(http.MethodGet, "/api/report?format=md", nil)
	rec := httptest.NewRecorder()
	c.handleReport(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("no engagement: status %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestHandleReportBadFormat(t *testing.T) {
	c := newTestConsole(t)
	req := httptest.NewRequest(http.MethodGet, "/api/report?format=pdf", nil)
	rec := httptest.NewRecorder()
	c.handleReport(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad format: status %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleStatus(t *testing.T) {
	c := newTestConsole(t)
	c.history = []engine.Event{{Kind: "action"}, {Kind: "action"}, {Kind: "log"}}
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	c.handleStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		Running    bool           `json:"running"`
		Findings   int            `json:"findings"`
		Actions    int            `json:"actions"`
		BySeverity map[string]int `json:"bySeverity"`
		Engagement struct {
			ID string `json:"id"`
		} `json:"engagement"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Findings != 2 {
		t.Errorf("findings = %d, want 2", resp.Findings)
	}
	if resp.Actions != 2 {
		t.Errorf("actions = %d, want 2 (from history)", resp.Actions)
	}
	if resp.BySeverity["medium"] != 1 || resp.BySeverity["low"] != 1 {
		t.Errorf("bySeverity = %v, want medium:1 low:1", resp.BySeverity)
	}
	if resp.Engagement.ID != "ENG-LOCALHOST" {
		t.Errorf("engagement id = %q", resp.Engagement.ID)
	}
}

func TestHandleTools(t *testing.T) {
	c := newTestConsole(t)
	req := httptest.NewRequest(http.MethodGet, "/api/tools", nil)
	rec := httptest.NewRecorder()
	c.handleTools(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "portscan") {
		t.Fatalf("tools: status %d body %.200q", rec.Code, rec.Body.String())
	}
}

func TestHandleMethodology(t *testing.T) {
	c := newTestConsole(t)
	req := httptest.NewRequest(http.MethodGet, "/api/methodology", nil)
	rec := httptest.NewRecorder()
	c.handleMethodology(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("methodology status %d", rec.Code)
	}
	var rows []map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rows) == 0 {
		t.Error("methodology returned no entries")
	}
}

func TestHandleFindingsNoEngagement(t *testing.T) {
	c := &console{subs: map[chan engine.Event]struct{}{}, pending: map[string]chan bool{}}
	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	rec := httptest.NewRecorder()
	c.handleFindings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("findings status %d", rec.Code)
	}
}

func TestHandleApproveNoPending(t *testing.T) {
	c := newTestConsole(t)
	body := strings.NewReader(`{"action":"missing","approved":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/approve", body)
	rec := httptest.NewRecorder()
	c.handleApprove(rec, req)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] == nil {
		t.Fatalf("approve with no pending should return an error, got %v", resp)
	}
}

func TestHandleApproveDelivers(t *testing.T) {
	c := newTestConsole(t)
	ch := make(chan bool, 1)
	c.pending["act-1"] = ch
	body := strings.NewReader(`{"action":"act-1","approved":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/approve", body)
	rec := httptest.NewRecorder()
	c.handleApprove(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status %d", rec.Code)
	}
	select {
	case got := <-ch:
		if !got {
			t.Error("delivered approval = false, want true")
		}
	default:
		t.Error("approval was not delivered to the pending channel")
	}
}

func TestHandleApproveMethodGuard(t *testing.T) {
	c := newTestConsole(t)
	req := httptest.NewRequest(http.MethodGet, "/api/approve", nil)
	rec := httptest.NewRecorder()
	c.handleApprove(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/approve: status %d, want 405", rec.Code)
	}
}

// TestHandleChatStopFastPath verifies the control-command fast path cancels a
// running engagement WITHOUT calling the model (no Ollama needed in CI).
func TestHandleChatStopFastPath(t *testing.T) {
	c := newTestConsole(t)
	ctx, cancel := context.WithCancel(context.Background())
	c.runCancel = cancel
	c.running = true

	body := strings.NewReader(`{"message":"stop"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/chat", body)
	rec := httptest.NewRecorder()
	c.handleChat(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("chat stop status %d", rec.Code)
	}
	var resp struct {
		Reply   string `json:"reply"`
		Stopped bool   `json:"stopped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Stopped {
		t.Errorf("stop fast path: stopped=%v, reply=%q", resp.Stopped, resp.Reply)
	}
	select {
	case <-ctx.Done(): // cancelled as expected
	default:
		t.Error("run context was not cancelled by the stop command")
	}
}

func TestHandleChatStopNothingRunning(t *testing.T) {
	c := newTestConsole(t)
	body := strings.NewReader(`{"message":"stop"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/chat", body)
	rec := httptest.NewRecorder()
	c.handleChat(rec, req)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["stopped"] == true {
		t.Errorf("nothing running: stopped should be falsey, got %v", resp)
	}
	if !strings.Contains(strings.ToLower(resp["reply"].(string)), "nothing") {
		t.Errorf("expected a 'nothing running' reply, got %v", resp["reply"])
	}
}

func TestProfileFor(t *testing.T) {
	cases := []struct {
		in       string
		wantCats []string
		wantRisk string
		wantNorm string
	}{
		{"recon", []string{"recon"}, "low", "recon"},
		{"scan", []string{"recon", "scan"}, "medium", "scan"},
		{"internal", []string{"recon", "scan", "identity"}, "medium", "internal"},
		{"ad", []string{"recon", "scan", "identity"}, "medium", "internal"},
		{"full", []string{"recon", "scan", "identity", "exploit", "post-exploit"}, "high", "full"},
		{"", []string{"recon", "scan"}, "medium", "scan"},      // default
		{"bogus", []string{"recon", "scan"}, "medium", "scan"}, // unknown → safe default
		{" FULL ", []string{"recon", "scan", "identity", "exploit", "post-exploit"}, "high", "full"},
	}
	for _, c := range cases {
		gotCats, gotRisk, gotNorm := profileFor(c.in)
		if strings.Join(gotCats, ",") != strings.Join(c.wantCats, ",") {
			t.Errorf("profileFor(%q) cats = %v, want %v", c.in, gotCats, c.wantCats)
		}
		if gotRisk != c.wantRisk {
			t.Errorf("profileFor(%q) risk = %q, want %q", c.in, gotRisk, c.wantRisk)
		}
		if gotNorm != c.wantNorm {
			t.Errorf("profileFor(%q) norm = %q, want %q", c.in, gotNorm, c.wantNorm)
		}
	}
}

// TestHandleCreateEngagement_Profiles drives the in-console create path for each
// depth and asserts the written engagement carries the right allowed categories +
// risk ceiling and self-verifies. Created files are cleaned up.
func TestHandleCreateEngagement_Profiles(t *testing.T) {
	c := newTestConsole(t)
	var created []string
	t.Cleanup(func() {
		for _, p := range created {
			_ = os.Remove(p)
		}
		_ = os.Remove("configs") // removes only if now empty
	})

	for _, depth := range []string{"recon", "scan", "internal", "full"} {
		body := strings.NewReader(`{"url":"http://127.0.0.1:8080/","authorized":true,"depth":"` + depth + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/engagements/create", body)
		rec := httptest.NewRecorder()
		c.handleCreateEngagement(rec, req)
		var resp struct {
			OK    bool   `json:"ok"`
			Path  string `json:"path"`
			Depth string `json:"depth"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("depth %q: decode: %v (body %q)", depth, err, rec.Body.String())
		}
		if !resp.OK {
			t.Fatalf("depth %q: create failed: %s", depth, resp.Error)
		}
		created = append(created, resp.Path)

		eng, err := engagement.Load(resp.Path)
		if err != nil {
			t.Fatalf("depth %q: load created engagement: %v", depth, err)
		}
		wantCats, wantRisk, _ := profileFor(depth)
		if strings.Join(eng.RoE.AllowedCategories, ",") != strings.Join(wantCats, ",") {
			t.Errorf("depth %q: allowed = %v, want %v", depth, eng.RoE.AllowedCategories, wantCats)
		}
		if eng.RoE.MaxRisk != wantRisk {
			t.Errorf("depth %q: max_risk = %q, want %q", depth, eng.RoE.MaxRisk, wantRisk)
		}
		if _, err := eng.VerifiedGrants(); err != nil {
			t.Errorf("depth %q: self-signature did not verify: %v", depth, err)
		}
	}
}

func TestHandleCreateEngagement_RequiresAuthorization(t *testing.T) {
	c := newTestConsole(t)
	body := strings.NewReader(`{"url":"http://127.0.0.1:8080/","authorized":false,"depth":"scan"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/engagements/create", body)
	rec := httptest.NewRecorder()
	c.handleCreateEngagement(rec, req)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] == nil {
		t.Fatalf("create without authorization should error, got %v", resp)
	}
}

func TestHandleChatEmptyMessage(t *testing.T) {
	c := newTestConsole(t)
	body := strings.NewReader(`{"message":"  "}`)
	req := httptest.NewRequest(http.MethodPost, "/api/chat", body)
	rec := httptest.NewRecorder()
	c.handleChat(rec, req)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] == nil {
		t.Errorf("empty message should error, got %v", resp)
	}
}
