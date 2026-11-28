package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/bench"
	"github.com/dukotah/tyto/internal/bench/lab"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/state"
)

func runBench(t *testing.T, args ...string) bench.Result {
	t.Helper()
	out := filepath.Join(t.TempDir(), "result.json")
	cmd := newBenchCmd()
	cmd.SetArgs(append(args, "--out", out))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("bench %v: %v", args, err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var res bench.Result
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func foundSet(res bench.Result) map[string]bool {
	m := map[string]bool{}
	for _, it := range res.Items {
		if it.Found {
			m[it.ID] = true
		}
	}
	return m
}

// TestBenchOracleCeiling is the tool-regression gate: with every built-in tool
// aimed perfectly at the lab, these planted vulnerabilities MUST be found and
// proven, and no decoy may be reported. A tool that silently stops detecting its
// class (as the SSTI checker once did, with a wrong expected constant) fails here.
//
// The three items NOT listed are known to need an operator's reasoning — no
// built-in tool reports them. If a tool learns to, this test still passes.
func TestBenchOracleCeiling(t *testing.T) {
	res := runBench(t, "run", "--planner", "oracle")
	must := []string{
		"sec-headers", "cookie-flags", "cors-reflect", "http-methods", "server-banner",
		"env-file", "git-exposed", "dir-listing", "backup-dump", "js-secrets",
		"graphql-introspection", "weak-jwt",
		"xss-reflected", "sqli-error", "open-redirect", "ssti", "cmd-injection",
		"idor-invoice",
	}
	found := foundSet(res)
	for _, id := range must {
		if !found[id] {
			t.Errorf("oracle run no longer finds %q — a built-in tool regressed", id)
		}
	}
	for _, it := range res.Items {
		if it.Found && !it.Validated {
			t.Errorf("%q was found but not tool-validated in the oracle run", it.ID)
		}
	}
	if res.DecoysHit != 0 {
		t.Errorf("a built-in tool reported a decoy (false positive): %+v", res.FalsePositives)
	}
	if res.Effort == nil || res.Effort.Executed == 0 || res.Effort.Denied != 0 {
		t.Errorf("oracle effort unexpected: %+v", res.Effort)
	}
	if res.LabVersion != lab.Version {
		t.Errorf("lab version = %d, want %d", res.LabVersion, lab.Version)
	}
}

// The scripted floor must stay strictly below the ceiling: if it ever matches,
// the benchmark has stopped distinguishing a good planner from no planner.
func TestBenchScriptedFloorIsBelowCeiling(t *testing.T) {
	floor := runBench(t, "run", "--planner", "scripted", "--cycles", "6")
	if floor.Found == 0 {
		t.Fatal("scripted run found nothing — the lab or the script is broken")
	}
	if floor.DecoysHit != 0 {
		t.Errorf("scripted run reported a decoy: %+v", floor.FalsePositives)
	}
	if got := foundSet(floor); got["xss-reflected"] || got["admin-takeover"] {
		t.Errorf("the scripted floor is not expected to find injection/chain items; the benchmark has lost its headroom: %v", got)
	}
}

func TestBenchLabRefusesNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "192.0.2.10:8080", "example.com:80"} {
		if ln, err := loopbackListener(addr); err == nil {
			ln.Close()
			t.Errorf("lab must refuse to bind %q", addr)
		}
	}
}

func TestBenchScoreAndCompareCommands(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	_ = os.WriteFile(report, []byte(`{"findings":[{"severity":"high","title":"Reflected XSS in parameter q","target":"http://h/search?q=1","tool":"webinject","validated":true}]}`), 0o600)
	a := runBench(t, "score", "--report", report, "--label", "a")
	if a.Found != 1 || a.Label != "a" || a.Effort != nil {
		t.Fatalf("score command wrong: %+v", a)
	}
	ja, _ := json.Marshal(a)
	pa := filepath.Join(dir, "a.json")
	_ = os.WriteFile(pa, ja, 0o600)

	var buf bytes.Buffer
	cmd := newBenchCmd()
	cmd.SetArgs([]string{"compare", pa, pa})
	cmd.SetOut(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No planted vulnerability changed status") {
		t.Fatalf("comparing a result with itself should report no change:\n%s", buf.String())
	}
}

// An MCP agent's own conclusions must be recordable, in scope only, never as
// tool-validated, and must land in the live JSON report the scorer reads.
func TestMcpRecordFinding(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	dir := t.TempDir()
	engPath := filepath.Join(dir, "e.yaml")
	_ = os.WriteFile(engPath, []byte(labEngagementYAML(srv.URL)), 0o600)
	eng, err := engagement.Load(engPath)
	if err != nil {
		t.Fatal(err)
	}
	reg := defaultRegistry()
	var auditBuf bytes.Buffer
	s := &mcpServer{
		eng: eng, reg: reg, guard: guard.New(eng, toolSnapshot(reg), nil), state: state.New(),
		audit: audit.NewLog(&auditBuf), sessions: map[string]string{}, reportOut: filepath.Join(dir, "report.json"),
	}

	args := map[string]any{
		"title": "IDOR on invoices", "target": srv.URL + "/api/invoice?id=1002", "severity": "high",
		"description": "no authentication; any id returns another customer's invoice", "evidence": "Dana Whitfield",
	}
	if out, isErr := s.recordFinding(args); isErr || !strings.Contains(out, "Recorded") {
		t.Fatalf("in-scope finding should record: %q", out)
	}
	if out, isErr := s.recordFinding(args); isErr || !strings.Contains(out, "Already recorded") {
		t.Fatalf("duplicate should be reported, not double-counted: %q", out)
	}
	for name, bad := range map[string]map[string]any{
		"out of scope":    {"title": "x", "target": "http://example.com/", "severity": "high", "description": "d"},
		"bad severity":    {"title": "x", "target": srv.URL + "/", "severity": "catastrophic", "description": "d"},
		"missing details": {"title": "x", "target": srv.URL + "/", "severity": "high"},
	} {
		if out, isErr := s.recordFinding(bad); !isErr || !strings.Contains(out, "REJECTED") {
			t.Errorf("%s: must be rejected, got %q", name, out)
		}
	}

	fs := s.state.Findings()
	if len(fs) != 1 || fs[0].Validated || fs[0].Tool != "operator" {
		t.Fatalf("operator finding must be stored once, unvalidated: %+v", fs)
	}
	if !strings.Contains(auditBuf.String(), `"kind":"finding_recorded"`) {
		t.Fatal("recording a finding must be audited")
	}
	raw, err := os.ReadFile(s.reportOut)
	if err != nil {
		t.Fatalf("live report not written: %v", err)
	}
	findings, err := bench.ParseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	res := bench.Score("mcp", findings, nil)
	if got := foundSet(res); !got["idor-invoice"] || res.Validated != 0 {
		t.Fatalf("the recorded finding should score as found-but-not-proven: %+v", res)
	}
}
