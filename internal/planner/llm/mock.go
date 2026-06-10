package llm

import (
	"context"
	"fmt"
	"strings"
)

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

// NewScriptedMock returns a Mock that drives a basic recon → scan → web-check
// pass over the given targets, deterministically and with NO model — useful for
// an offline demo of the full pipeline. Cycle 1 port-scans each target; cycle 2
// fingerprints and safety-checks each as an HTTP service.
func NewScriptedMock(targets []string) *Mock {
	var scan, web []string
	for _, t := range targets {
		scan = append(scan, fmt.Sprintf(`{"tool":"portscan","category":"scan","target":%q,"risk":"medium","params":{},"rationale":"enumerate services"}`, t))
		web = append(web,
			fmt.Sprintf(`{"tool":"httpprobe","category":"recon","target":%q,"risk":"low","params":{},"rationale":"fingerprint http"}`, t),
			fmt.Sprintf(`{"tool":"webcheck","category":"scan","target":%q,"risk":"low","params":{},"rationale":"safe web checks"}`, t),
			fmt.Sprintf(`{"tool":"webdiscover","category":"scan","target":%q,"risk":"low","params":{},"rationale":"sensitive-path discovery"}`, t),
			fmt.Sprintf(`{"tool":"secretscan","category":"scan","target":%q,"risk":"low","params":{},"rationale":"scan for exposed secrets"}`, t),
			fmt.Sprintf(`{"tool":"templatescan","category":"scan","target":%q,"risk":"low","params":{},"rationale":"run detection templates"}`, t),
			fmt.Sprintf(`{"tool":"webcrawl","category":"recon","target":%q,"risk":"low","params":{},"rationale":"discover endpoints"}`, t),
			fmt.Sprintf(`{"tool":"webinject","category":"scan","target":%q,"risk":"medium","params":{},"rationale":"injection testing"}`, t),
			// Exploitation tier — the Scope Guard runs these only if the engagement
			// is authorized for exploit/high-risk on the target.
			fmt.Sprintf(`{"tool":"sqliexploit","category":"exploit","target":%q,"risk":"high","params":{},"rationale":"extract data to prove SQLi impact"}`, t),
			fmt.Sprintf(`{"tool":"cmdexec","category":"exploit","target":%q,"risk":"high","params":{},"rationale":"execute commands to prove RCE impact"}`, t),
		)
	}
	return &Mock{Responses: []string{
		`{"actions":[` + strings.Join(scan, ",") + `]}`,
		`{"actions":[` + strings.Join(web, ",") + `]}`,
	}}
}

// NewDemoMock returns a Mock whose single response exercises the Scope Guard
// against the shipped example engagement: one in-scope action that should be
// ALLOWED, one out-of-scope target that should be DENIED, and one
// forbidden/over-ceiling action that should also be DENIED. Great for a first
// offline run with `tyto run --engagement configs/engagement.example.yaml --dry-run`.
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
