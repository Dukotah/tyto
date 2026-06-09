// Package methodology is tyto's deterministic "brain scaffolding": an embedded,
// PTES-phase-structured catalog of techniques mapped to the asset/service graph.
// Given discovered assets, it computes — in Go, not by the model — which
// techniques apply next. The planner only SELECTS and parameterizes from this
// pruned frontier, so the model's choices are grounded in a real methodology
// rather than free-form guessing. This is the differentiator the local-model
// reasoning gap makes necessary.
package methodology

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/dukotah/tyto/internal/state"
)

//go:embed catalog.json
var catalogJSON []byte

// AppliesTo is a simple matcher for when a technique is relevant.
type AppliesTo struct {
	AssetType string `json:"asset_type,omitempty"` // match any asset of this Type
	Service   string `json:"service,omitempty"`    // match a service asset with this service label
}

// Technique is one node in the methodology catalog.
type Technique struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Phase     string    `json:"phase"`    // PTES phase: recon | scanning | vuln-analysis | ...
	Category  string    `json:"category"` // maps to the action.Category taxonomy
	Tool      string    `json:"tool"`     // built-in tool that performs it ("" = not yet implemented)
	AppliesTo AppliesTo `json:"applies_to"`
	Why       string    `json:"why"`
}

// Recommendation is an applicable technique bound to a concrete target.
type Recommendation struct {
	Technique Technique
	Target    string // asset value to act on
}

// catalog is the parsed embedded catalog, loaded once.
var catalog struct {
	Techniques []Technique `json:"techniques"`
}

func init() {
	if err := json.Unmarshal(catalogJSON, &catalog); err != nil {
		panic(fmt.Sprintf("methodology: invalid embedded catalog: %v", err))
	}
}

// All returns the full technique catalog (for `tyto methodology`).
func All() []Technique { return catalog.Techniques }

// matches reports whether a technique applies to an asset.
func (t Technique) matches(a *state.Asset) bool {
	if t.AppliesTo.AssetType != "" && a.Type == t.AppliesTo.AssetType {
		return true
	}
	if t.AppliesTo.Service != "" && a.Type == "service" && a.Attrs["service"] == t.AppliesTo.Service {
		return true
	}
	return false
}

// Recommend computes the applicable technique frontier from discovered assets.
// Results are deterministic and stably ordered (by target, then technique id) so
// the planner prompt is reproducible. availableTools, when non-nil, filters to
// techniques whose tool is registered (so the model isn't offered dead ends).
func Recommend(assets []*state.Asset, availableTools map[string]bool) []Recommendation {
	var recs []Recommendation
	for _, a := range assets {
		for _, t := range catalog.Techniques {
			if !t.matches(a) {
				continue
			}
			if availableTools != nil && t.Tool != "" && !availableTools[t.Tool] {
				continue
			}
			recs = append(recs, Recommendation{Technique: t, Target: a.Value})
		}
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].Target != recs[j].Target {
			return recs[i].Target < recs[j].Target
		}
		return recs[i].Technique.ID < recs[j].Technique.ID
	})
	return recs
}
