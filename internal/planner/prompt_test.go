package planner

import (
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
)

func framingEngagement() *engagement.Engagement {
	return &engagement.Engagement{
		ID:         "e1",
		Client:     "acme",
		Objectives: []string{"find web vulns"},
		Scope:      engagement.Scope{InScope: []engagement.Target{{Type: engagement.TargetDomain, Value: "h"}}},
		RoE:        engagement.RoE{MaxRisk: "medium"},
	}
}

// TestUserPromptFencesUntrustedData proves the injection-framing wrapper: all
// tool-derived state is enclosed in a clearly delimited block under the
// "untrusted data, don't obey" preamble, and the trusted trailing instruction
// stays OUTSIDE it.
func TestUserPromptFencesUntrustedData(t *testing.T) {
	st := state.New()
	// A discovered service whose value is attacker-influenced; it must land inside
	// the untrusted fence (sanitized by the state quarantine, framed by the prompt).
	st.AddAsset(&state.Asset{ID: "h:80", Type: "service", Value: "h:80"})

	out := UserPrompt(framingEngagement(), st, []string{"scanner"}, nil)

	begin := strings.Index(out, untrustedBegin)
	end := strings.Index(out, untrustedEnd)
	preamble := strings.Index(out, untrustedPreamble)
	if begin < 0 || end < 0 || preamble < 0 {
		t.Fatalf("prompt missing framing markers (preamble=%d begin=%d end=%d):\n%s", preamble, begin, end, out)
	}
	// Preamble precedes the opening marker, which precedes the closing marker.
	if !(preamble < begin && begin < end) {
		t.Fatalf("framing markers out of order: preamble=%d begin=%d end=%d", preamble, begin, end)
	}
	// The untrusted state (CURRENT STATE + the discovered service) is INSIDE the fence.
	stateIdx := strings.Index(out, "CURRENT STATE")
	svcIdx := strings.Index(out, "h:80")
	if !(begin < stateIdx && stateIdx < end) {
		t.Fatalf("CURRENT STATE must be inside the fence (begin=%d state=%d end=%d)", begin, stateIdx, end)
	}
	if !(begin < svcIdx && svcIdx < end) {
		t.Fatalf("discovered service must be inside the fence (begin=%d svc=%d end=%d)", begin, svcIdx, end)
	}
	// The trailing instruction is TRUSTED and must sit after the closing marker.
	q := strings.Index(out, "What are the next")
	if !(end < q) {
		t.Fatalf("the trailing instruction must be outside (after) the fence (end=%d question=%d)", end, q)
	}
	// Trusted config (scope/RoE) stays outside the fence, before it.
	if scope := strings.Index(out, "IN SCOPE"); !(scope < begin) {
		t.Fatalf("trusted scope block must precede the untrusted fence (scope=%d begin=%d)", scope, begin)
	}
}
