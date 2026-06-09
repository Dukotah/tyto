package llm

import "context"

// Mock is a deterministic Client for tests and offline dry runs. It cycles
// through Responses, ignoring the prompt.
type Mock struct {
	Responses []string
	i         int
}

// Name implements Client.
func (m *Mock) Name() string { return "mock" }

// Generate implements Client by returning the next canned response.
func (m *Mock) Generate(_ context.Context, _, _ string) (string, error) {
	if len(m.Responses) == 0 {
		return `{"actions":[]}`, nil
	}
	r := m.Responses[m.i%len(m.Responses)]
	m.i++
	return r, nil
}

// NewDemoMock returns a Mock whose single response exercises the Scope Guard
// against the shipped example engagement: one in-scope action that should be
// ALLOWED, one out-of-scope target that should be DENIED, and one
// forbidden/over-ceiling action that should also be DENIED. Great for a first
// offline run with `strix run --engagement configs/engagement.example.yaml --dry-run`.
func NewDemoMock() *Mock {
	return &Mock{Responses: []string{`{
  "actions": [
    {
      "tool": "portscan",
      "category": "scan",
      "target": "203.0.113.10",
      "risk": "medium",
      "params": {"ports": "22,80,443"},
      "rationale": "Enumerate exposed services on a representative in-scope host."
    },
    {
      "tool": "portscan",
      "category": "scan",
      "target": "203.0.113.201",
      "risk": "medium",
      "params": {},
      "rationale": "Probe this host (which is actually out of scope - the guard should stop me)."
    },
    {
      "tool": "exploit-runner",
      "category": "exploit",
      "target": "203.0.113.10",
      "risk": "high",
      "params": {},
      "rationale": "Attempt deeper access (forbidden category and over the risk ceiling)."
    }
  ]
}`}}
}
