package llm

import "fmt"

// ModelTier is a coarse hardware class used to pick a default local model.
type ModelTier int

const (
	TierCPUOnly ModelTier = iota
	Tier8GB
	Tier16GB
	Tier24GB
)

// ModelChoice is the resolved default model plus why it was chosen, so the run
// banner can explain itself (and flag a degraded CPU-only fallback).
type ModelChoice struct {
	Model    string
	Tier     ModelTier
	Degraded bool
	Reason   string
}

func (c ModelChoice) String() string { return fmt.Sprintf("%s (%s)", c.Model, c.Reason) }

const gib = 1 << 30

// DefaultModel maps detected physical RAM to a default Qwen3 size. It NEVER
// returns a Llama model (a license/AUP trap for offensive use). detectOK=false
// (RAM detection failed) forces the degraded CPU-only floor rather than guessing.
//
//	<14GiB  -> qwen3:8b      (8GB tier; also the floor for low-RAM boxes)
//	>=14GiB -> qwen3:14b     (16GB tier — the headline default; tolerant boundary)
//	>=24GiB -> qwen3:30b-a3b (24GB+ tier, MoE with light active params)
func DefaultModel(totalRAMBytes uint64, detectOK bool) ModelChoice {
	if !detectOK {
		return ModelChoice{
			Model: "qwen3:4b", Tier: TierCPUOnly, Degraded: true,
			Reason: "CPU-only floor — RAM detection failed; GPU/Apple-Silicon strongly recommended, DEGRADED",
		}
	}
	switch {
	case totalRAMBytes >= 24*gib:
		return ModelChoice{Model: "qwen3:30b-a3b", Tier: Tier24GB, Reason: "24GB+ tier"}
	case totalRAMBytes >= 14*gib: // a "16GB" box often reports a little under 16GiB
		return ModelChoice{Model: "qwen3:14b", Tier: Tier16GB, Reason: "16GB tier"}
	default:
		return ModelChoice{Model: "qwen3:8b", Tier: Tier8GB, Reason: "8GB tier"}
	}
}
