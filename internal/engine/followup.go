package engine

import (
	"strings"

	"github.com/dukotah/tyto/internal/action"
)

// injectionTools are the parameter-level testers the engine dispatches against
// every discovered endpoint, deterministically and independent of the planner.
// This closes the recon->exploitation seam: webcrawl/jsmine/apidocs emit
// `endpoint` assets, but a fixed planner targets only the base host and `hunt`
// deliberately omits injection — so without this the discovered parameters are
// never tested, and real injection vulns on parameterized endpoints go unfound.
var injectionTools = []string{"webinject", "ssti", "sqliexploit", "redircheck"}

// endpointInjectionActions returns the injection actions to run against every
// discovered `endpoint` asset. It is deterministic and planner-independent: the
// same principle as seedAssets, applied to runtime discoveries instead of the
// initial scope. The engine still routes each action through the Scope Guard, so
// an endpoint that is out of scope or a tool that is over the risk ceiling is
// denied exactly as any other action. The admit phase dedups by canonical key
// (tool + target), so each (tool, endpoint) pair runs once across the whole run;
// the e.seen pre-check here just keeps already-done actions out of the proposal.
func (e *Engine) endpointInjectionActions() []action.Action {
	var out []action.Action
	for _, as := range e.state.Assets() {
		if as.Type != "endpoint" {
			continue
		}
		target := strings.TrimSpace(as.Value)
		if target == "" {
			continue
		}
		for _, name := range injectionTools {
			t, ok := e.tools.Get(name)
			if !ok {
				continue // tool not in this build's arsenal
			}
			a := action.Action{
				ID:        "auto-inj-" + name + "-" + target,
				Tool:      name,
				Category:  t.Category().String(),
				Target:    target,
				Risk:      t.MaxRisk(),
				Rationale: "methodology: test parameters of discovered endpoint " + target,
			}
			if e.seen[a.CanonicalKey()] {
				continue
			}
			out = append(out, a)
		}
	}
	return out
}
