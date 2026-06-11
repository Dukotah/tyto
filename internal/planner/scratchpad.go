package planner

import (
	"fmt"
	"strings"
)

// Attempt is one action the engine has already run, or the guard has already
// ruled on, this run. The planner reads these back so it doesn't re-propose work
// that's done or that the guard will only deny again.
type Attempt struct {
	Tool    string
	Target  string
	Verdict string // "allow" | "deny" | "require_approval"
	Reason  string // guard reason (denials)
	Outcome string // short result note for allowed actions (e.g. "3 finding(s)")
}

// Scratchpad is the planner's short-term memory across cycles: what has been
// tried and what the guard denied. It is rendered into a SEPARATE prompt region
// from tool-sourced state, so the model never mistakes its own action history for
// evidence about the target. All methods are nil-safe — callers that don't track
// history (single-cycle eval, tests) pass nil.
type Scratchpad struct {
	attempts []Attempt
	seen     map[string]bool // tool|target|verdict, so the rendered list stays compact
}

// NewScratchpad returns an empty scratchpad.
func NewScratchpad() *Scratchpad { return &Scratchpad{seen: map[string]bool{}} }

// maxRendered bounds how many recent attempts feed the prompt, so a long run
// can't grow the context unbounded; the most recent are kept.
const maxRendered = 24

// Record adds an attempt, de-duplicated by (tool, target, verdict).
func (s *Scratchpad) Record(a Attempt) {
	if s == nil {
		return
	}
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	key := a.Tool + "|" + a.Target + "|" + a.Verdict
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	s.attempts = append(s.attempts, a)
}

// Render produces the prompt section (or "" when empty). Allowed actions are
// listed as "already done — don't repeat"; denials are listed with their reason
// so the model stops proposing out-of-scope / over-ceiling work.
func (s *Scratchpad) Render() string {
	if s == nil || len(s.attempts) == 0 {
		return ""
	}
	att := s.attempts
	if len(att) > maxRendered {
		att = att[len(att)-maxRendered:]
	}
	var done, denied []Attempt
	for _, a := range att {
		if a.Verdict == "allow" {
			done = append(done, a)
		} else {
			denied = append(denied, a)
		}
	}
	var b strings.Builder
	if len(done) > 0 {
		b.WriteString("\nALREADY DONE THIS RUN (do NOT re-propose the same tool on the same target — pick something new):\n")
		for _, a := range done {
			out := a.Outcome
			if out == "" {
				out = "ran"
			}
			fmt.Fprintf(&b, "  - %s on %s => %s\n", a.Tool, a.Target, out)
		}
	}
	if len(denied) > 0 {
		b.WriteString("\nALREADY DENIED BY THE GUARD (do NOT propose these again — they are out of bounds):\n")
		for _, a := range denied {
			reason := a.Reason
			if reason == "" {
				reason = a.Verdict
			}
			fmt.Fprintf(&b, "  - %s on %s — %s\n", a.Tool, a.Target, reason)
		}
	}
	return b.String()
}
