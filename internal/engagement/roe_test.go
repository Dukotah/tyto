package engagement

import (
	"math"
	"testing"
)

func TestRoEValidatePacingKnobs(t *testing.T) {
	if err := (RoE{MaxRisk: "low", MaxRPS: 5, MaxConcurrent: 2}).validate(); err != nil {
		t.Fatalf("valid pacing knobs rejected: %v", err)
	}
	bad := []RoE{
		{MaxRisk: "low", MaxRPS: -1},
		{MaxRisk: "low", MaxRPS: math.NaN()},
		{MaxRisk: "low", MaxRPS: math.Inf(1)},
		{MaxRisk: "low", MaxConcurrent: -1},
	}
	for i, r := range bad {
		if err := r.validate(); err == nil {
			t.Errorf("case %d: invalid pacing knob accepted: %+v", i, r)
		}
	}
}
