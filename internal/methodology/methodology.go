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
	// Rank so the planner sees the highest-VALUE techniques first: actual
	// bug-finding (exploitation/vuln-analysis phases — injection, secrets, known
	// CVEs) outranks enabling work (scanning/recon — fingerprinting, crawling).
	// Without this the prompt was alphabetical, so a slow local model burned its
	// early cycles on recon and rarely reached the tools that find real findings.
	// Within the same rank, order is stable by target then technique id so the
	// prompt stays reproducible.
	sort.SliceStable(recs, func(i, j int) bool {
		if pi, pj := techRank(recs[i].Technique), techRank(recs[j].Technique); pi != pj {
			return pi > pj
		}
		// Within a phase, prefer FAST native tools over slow Kali shell-outs, so a
		// run gets through discovery + the bug-finders quickly instead of stalling
		// on a 90s nmap/nuclei. The slow tools still appear (just lower) for depth.
		if si, sj := slowTool(recs[i].Technique.Tool), slowTool(recs[j].Technique.Tool); si != sj {
			return !si // fast (false) sorts before slow (true)
		}
		if recs[i].Target != recs[j].Target {
			return recs[i].Target < recs[j].Target
		}
		return recs[i].Technique.ID < recs[j].Technique.ID
	})
	return recs
}

// slowTools are the external Kali shell-out adapters: high-value but each costs
// seconds-to-minutes per run (process spawn + WSL round-trip + their own scans).
// Native Go tools run in-process in milliseconds, so they go first.
var slowTools = map[string]bool{
	"nmapscan": true, "nucleiscan": true, "nikto": true, "whatweb": true,
	"ffuf": true, "gobuster": true, "wpscan": true, "sqlmap": true,
	"testssl": true, "subfinder": true, "hydra": true, "metasploit": true,
}

func slowTool(tool string) bool { return slowTools[tool] }

// gatewayTools are prerequisites that UNLOCK high-value testing: webcrawl and
// jsmine discover the parameterized endpoints that every injection tool
// (webinject, ssti, redircheck, sqliexploit) needs. Without them those tools
// find "no parameters to test", so the gateways must run BEFORE them — even
// though discovery is only a "scanning" phase, its value here is exploitation-tier.
var gatewayTools = map[string]bool{"webcrawl": true, "jsmine": true}

// techRank is the effective planner priority for a technique: gateway discovery
// tools are boosted above everything (run them first to enable injection), else
// it falls back to the phase weight.
func techRank(t Technique) int {
	if gatewayTools[t.Tool] {
		return 5
	}
	return phaseRank(t.Phase)
}

// phaseRank weights PTES phases by how directly they produce findings, so the
// planner prompt front-loads the techniques that actually find vulnerabilities.
// Scanning still ranks above recon (it discovers the endpoints that exploitation
// then targets), so discovery isn't starved.
func phaseRank(phase string) int {
	switch phase {
	case "exploitation":
		return 4
	case "vuln-analysis":
		return 3
	case "scanning":
		return 2
	case "recon":
		return 1
	default:
		return 0
	}
}
