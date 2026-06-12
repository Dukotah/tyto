package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/planner"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool"
)

// orderTool emits one asset + finding per target. Its Execute can block on a
// per-target delay so the test can force executions to FINISH in a different
// order than the planner proposed them, then assert COMMIT still happened in
// planner order. It also tracks peak in-flight concurrency so a test can prove
// the executor actually parallelises (or doesn't, when capped to one slot).
type orderTool struct{ rec *concRecorder }

func (orderTool) Name() string              { return "scanner" }
func (orderTool) Category() action.Category { return action.CategoryScan }
func (orderTool) MaxRisk() action.RiskLevel { return action.RiskMedium }

func (o orderTool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	o.rec.enter()
	defer o.rec.leave()
	if d := o.rec.delays[a.Target]; d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return action.Result{}, ctx.Err()
		}
	}
	return action.Result{
		ActionID: a.ID, Tool: "scanner", Success: true, Output: "scanned " + a.Target,
		Assets: []state.Asset{{ID: a.Target, Type: "host", Value: a.Target}},
		Findings: []state.Finding{{
			ID: a.Target, Title: "f-" + a.Target, Target: a.Target, Tool: "scanner",
			Severity: state.SeverityLow,
		}},
	}, nil
}

// concRecorder is shared across the concurrent executors; live/maxLive are atomic
// and delays is read-only after construction, so a clean -race run proves the
// engine confines all shared-state mutation to the serial ADMIT/COMMIT phases.
type concRecorder struct {
	delays  map[string]time.Duration
	live    int32
	maxLive int32
}

func (r *concRecorder) enter() {
	n := atomic.AddInt32(&r.live, 1)
	for {
		m := atomic.LoadInt32(&r.maxLive)
		if n <= m || atomic.CompareAndSwapInt32(&r.maxLive, m, n) {
			break
		}
	}
}
func (r *concRecorder) leave() { atomic.AddInt32(&r.live, -1) }

// concEngine builds an engine over three in-scope targets a,b,c with the given
// RoE concurrency cap and the order-tracking tool. The audit log is written to
// the returned buffer so the test can read back the COMMIT order from the
// "result" entries.
func concEngine(t *testing.T, plan string, maxConcurrent int, rec *concRecorder) (*Engine, *bytes.Buffer) {
	t.Helper()
	eng := &engagement.Engagement{
		ID: "e1", Client: "c",
		Scope: engagement.Scope{InScope: []engagement.Target{
			{Type: engagement.TargetDomain, Value: "a"},
			{Type: engagement.TargetDomain, Value: "b"},
			{Type: engagement.TargetDomain, Value: "c"},
		}},
		RoE: engagement.RoE{MaxRisk: "medium", MaxConcurrent: maxConcurrent},
	}
	reg := tool.NewRegistry()
	reg.MustRegister(orderTool{rec: rec})
	st := state.New()
	g := guard.New(eng, map[string]guard.ToolMeta{"scanner": {Category: action.CategoryScan, MaxRisk: action.RiskMedium}}, nil)
	var buf bytes.Buffer
	e := New(eng, g, planner.New(&llm.Mock{Responses: []string{plan}}), reg, st,
		audit.NewLog(&buf), &nopWriter{}, Options{MaxCycles: 1})
	return e, &buf
}

// nopWriter is a thread-safe sink for the engine's human-readable output. The
// concurrent EXECUTE phase never writes to it (writes are confined to the serial
// ADMIT/COMMIT phases), but a guarded sink keeps -race honest if that changes.
type nopWriter struct{ mu sync.Mutex }

func (w *nopWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(p), nil
}

// resultTargets parses the audit JSONL and returns, in order, the target of every
// COMMITTED action. The "result" audit entry is written in the serial COMMIT
// phase, so the order of "result" entries IS the commit order. Each carries an
// action ID, which we map back to a target via the "action" entries.
func resultTargets(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	idToTarget := map[string]string{}
	var order []string
	sc := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad audit line: %v", err)
		}
		switch e.Kind {
		case "action":
			id, _ := e.Data["action"].(string)
			tgt, _ := e.Data["target"].(string)
			if id != "" {
				idToTarget[id] = tgt
			}
		case "result":
			id, _ := e.Data["action"].(string)
			order = append(order, idToTarget[id])
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return order
}

// TestCommitOrderIsPlannerOrderUnderReversedExecution proves determinism: with
// "a" delayed longest and "c" not at all, executions FINISH c,b,a — but the
// engine must COMMIT (and audit) in planner order a,b,c.
func TestCommitOrderIsPlannerOrderUnderReversedExecution(t *testing.T) {
	rec := &concRecorder{delays: map[string]time.Duration{
		"a": 80 * time.Millisecond, "b": 40 * time.Millisecond, "c": 0,
	}}
	e, buf := concEngine(t, threeTargetPlan, 3, rec) // 3 slots: all run at once
	if err := e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := resultTargets(t, buf)
	want := []string{"a", "b", "c"}
	if len(got) != 3 {
		t.Fatalf("want 3 result records, got %d (%v)", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("COMMIT/audit order is not planner order: want %v, got %v", want, got)
		}
	}
	if rec.maxLive < 2 {
		t.Fatalf("with the delays, execution should have overlapped; maxLive=%d", rec.maxLive)
	}
}

// TestConcurrencyEngagesWhenAllowed proves the executor actually parallelises:
// with 3 RoE slots and equal delays, all three actions are in flight at once.
func TestConcurrencyEngagesWhenAllowed(t *testing.T) {
	rec := &concRecorder{delays: map[string]time.Duration{
		"a": 50 * time.Millisecond, "b": 50 * time.Millisecond, "c": 50 * time.Millisecond,
	}}
	e, _ := concEngine(t, threeTargetPlan, 3, rec)
	if err := e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec.maxLive < 3 {
		t.Fatalf("3 concurrency slots should let all three overlap; maxLive=%d", rec.maxLive)
	}
}

// TestConcurrencyCappedToOneIsSerial proves the throttle still serialises when the
// RoE allows only one in-flight action — and order is still planner order.
func TestConcurrencyCappedToOneIsSerial(t *testing.T) {
	rec := &concRecorder{delays: map[string]time.Duration{
		"a": 20 * time.Millisecond, "b": 20 * time.Millisecond, "c": 20 * time.Millisecond,
	}}
	e, buf := concEngine(t, threeTargetPlan, 1, rec)
	if err := e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec.maxLive != 1 {
		t.Fatalf("MaxConcurrent=1 must serialise execution; maxLive=%d", rec.maxLive)
	}
	if got := resultTargets(t, buf); len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("serial run not in planner order: %v", got)
	}
}

const threeTargetPlan = `{"actions":[
	{"tool":"scanner","category":"scan","target":"a","risk":"medium","params":{},"rationale":"x"},
	{"tool":"scanner","category":"scan","target":"b","risk":"medium","params":{},"rationale":"x"},
	{"tool":"scanner","category":"scan","target":"c","risk":"medium","params":{},"rationale":"x"}
]}`
