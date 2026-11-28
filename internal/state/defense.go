package state

import (
	"sort"
	"strings"
	"time"
)

// Defensive-control kinds the engine can observe from a target's behavior.
const (
	DefenseRateLimit   = "rate-limiting"       // 429 / Retry-After / explicit rate-limit message
	DefenseConnReset   = "connection-reset"    // connection torn down mid-test (IPS / WAF drop, or instability)
	DefenseUnavailable = "service-unavailable" // 503 under test load (load shedding or an upstream block)
)

// DefenseObservation records that a target visibly reacted to testing. It is the
// positive half of the report — what the client's controls DID do — and is
// operator-facing only: nothing here enters the planner prompt.
type DefenseObservation struct {
	Target string `json:"target"` // bare host the reaction came from
	Kind   string `json:"kind"`   // one of the Defense* kinds
	// Signal is the exact phrase in the tool output that triggered the
	// classification, kept so a reader can judge the inference for themselves.
	Signal string `json:"signal"`
	// Tool is the tool whose action first drew the reaction.
	Tool string `json:"tool"`
	// AfterActions is how many actions had already run against the target before
	// the reaction first appeared — a rough "how much did it take" measure.
	AfterActions int       `json:"after_actions"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Count        int       `json:"count"` // how many action results showed it
}

// ObserveDefense records a defensive reaction, merging repeats of the same
// (target, kind). It returns true the first time that pair is seen.
func (s *State) ObserveDefense(o DefenseObservation) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if o.FirstSeen.IsZero() {
		o.FirstSeen = now
	}
	if o.LastSeen.IsZero() {
		o.LastSeen = o.FirstSeen
	}
	if o.Count < 1 {
		o.Count = 1
	}
	key := strings.ToLower(o.Target) + "\x00" + o.Kind
	if s.defenses == nil {
		s.defenses = map[string]*DefenseObservation{}
	}
	if prev, ok := s.defenses[key]; ok {
		prev.Count += o.Count
		if o.LastSeen.After(prev.LastSeen) {
			prev.LastSeen = o.LastSeen
		}
		return false
	}
	s.defenses[key] = &o
	return true
}

// Defenses returns the recorded defensive reactions, ordered by target then kind.
func (s *State) Defenses() []DefenseObservation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DefenseObservation, 0, len(s.defenses))
	for _, d := range s.defenses {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}
