package llm

import (
	"strings"
	"testing"
)

const gibT = 1 << 30

func TestDefaultModelTiers(t *testing.T) {
	cases := []struct {
		ram      uint64
		ok       bool
		want     string
		degraded bool
	}{
		{8 * gibT, true, "qwen3:8b", false},
		{6 * gibT, true, "qwen3:8b", false},
		{15 * gibT, true, "qwen3:14b", false},
		{16 * gibT, true, "qwen3:14b", false},
		{24 * gibT, true, "qwen3:30b-a3b", false},
		{64 * gibT, true, "qwen3:30b-a3b", false},
		{0, false, "qwen3:4b", true},
	}
	for _, c := range cases {
		got := DefaultModel(c.ram, c.ok)
		if got.Model != c.want || got.Degraded != c.degraded {
			t.Errorf("DefaultModel(%dGiB, ok=%v) = {%s, degraded=%v}, want {%s, degraded=%v}",
				c.ram/gibT, c.ok, got.Model, got.Degraded, c.want, c.degraded)
		}
	}
}

// The "never default to Llama" invariant, swept across a wide RAM range.
func TestDefaultModelNeverLlama(t *testing.T) {
	for g := uint64(0); g <= 128; g++ {
		if m := DefaultModel(g*gibT, true); strings.Contains(m.Model, "llama") {
			t.Fatalf("must never default to llama, got %q at %dGiB", m.Model, g)
		}
	}
}
