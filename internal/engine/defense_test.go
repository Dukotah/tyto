package engine

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool"
)

func TestClassifyDefense(t *testing.T) {
	cases := []struct {
		out, err, kind string
	}{
		{"HTTP/1.1 429 Too Many Requests", "", state.DefenseRateLimit},
		{"probe returned 429 after 40 requests", "", state.DefenseRateLimit},
		{"blocked: rate limit exceeded", "", state.DefenseRateLimit},
		{"got header Retry-After: 30", "", state.DefenseRateLimit},
		{"", "read tcp 10.0.0.1:443: connection reset by peer", state.DefenseConnReset},
		{"status: 503", "", state.DefenseUnavailable},
		{"503 Service Unavailable", "", state.DefenseUnavailable},

		// Must NOT be reported as a control: bare numbers and dead-service errors.
		{"open ports: 80, 443, 5030, 4291", "", ""},
		{"found 429 urls and 503 params", "", ""},
		{"", "dial tcp 10.0.0.1:81: connect: connection refused", ""},
		{"", "context deadline exceeded: i/o timeout", ""},
		{"HTTP/1.1 200 OK", "", ""},
	}
	for _, c := range cases {
		if kind, signal := classifyDefense(c.out, c.err); kind != c.kind {
			t.Errorf("classifyDefense(%q, %q) = %q (signal %q), want %q", c.out, c.err, kind, signal, c.kind)
		} else if kind != "" && signal == "" {
			t.Errorf("classifyDefense(%q, %q): a classification must name its signal", c.out, c.err)
		}
	}
}

// TestCommitRecordsDefensiveReaction drives the COMMIT phase directly: the third
// action against a host comes back rate-limited, and that must land in state (for
// the report) and in the audit trail (for the purple-team timeline), exactly once.
func TestCommitRecordsDefensiveReaction(t *testing.T) {
	eng := &engagement.Engagement{ID: "e1", Client: "c", RoE: engagement.RoE{MaxRisk: "medium"}}
	var buf bytes.Buffer
	st := state.New()
	e := New(eng, nil, nil, tool.NewRegistry(), st, audit.NewLog(&buf), io.Discard, Options{})

	run := func(id, output string) {
		t.Helper()
		ad := &admitted{a: action.Action{ID: id, Tool: "dirfuzz", Target: "http://app.test:8080/x"}, res: action.Result{Success: true, Output: output}}
		if _, err := e.commit(ad); err != nil {
			t.Fatal(err)
		}
	}
	run("a1", "12 paths found")
	run("a2", "3 paths found")
	run("a3", "stopped: HTTP/1.1 429 Too Many Requests")
	run("a4", "stopped: HTTP/1.1 429 Too Many Requests")

	ds := st.Defenses()
	if len(ds) != 1 {
		t.Fatalf("want one merged observation, got %+v", ds)
	}
	d := ds[0]
	if d.Target != "app.test" || d.Kind != state.DefenseRateLimit || d.AfterActions != 2 || d.Count != 2 || d.Tool != "dirfuzz" {
		t.Fatalf("observation wrong: %+v", d)
	}
	if n := strings.Count(buf.String(), `"kind":"defense_observed"`); n != 1 {
		t.Fatalf("the reaction must be audited once (first sight), got %d entries", n)
	}
	if !strings.Contains(buf.String(), `"after_actions":2`) {
		t.Fatalf("audit entry should carry after_actions=2:\n%s", buf.String())
	}
}
