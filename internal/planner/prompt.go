package planner

import (
	"fmt"
	"strings"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
)

// SystemPrompt is the planner's standing instructions.
func SystemPrompt() string {
	return strings.TrimSpace(`
You are tyto, an autonomous operator running a strictly authorized penetration test.
Your job is to decide the next concrete actions, choosing an approach that fits the
client's objectives, scope, and rules of engagement.

Hard rules:
- Only ever target assets that are in scope.
- Never exceed the stated risk ceiling or use forbidden categories.
- A separate enforcement layer will reject anything out of bounds; do not rely on
  it as a safety net — propose only actions you believe are permitted.
- Prefer the least intrusive action that advances an objective. Escalate gradually.

Respond with JSON ONLY, no prose, in exactly this shape:
{"actions":[
  {"tool":"<one of the available tools>",
   "category":"<recon|scan|exploit|...>",
   "target":"<host, ip, cidr, or url that is in scope>",
   "risk":"<passive|low|medium|high>",
   "params":{"key":"value"},
   "rationale":"<one sentence: why this advances an objective>"}
]}
Propose between 1 and 3 actions.`)
}

// RepairPrompt re-prompts the model after its previous output failed validation,
// quoting the bad output and the exact error so it can correct itself. Kept
// terse: the schema/grammar already constrains structure; this fixes semantic
// slips like an out-of-taxonomy category.
func RepairPrompt(prev string, validationErr error) string {
	return fmt.Sprintf(`Your previous response was rejected by the validator.

ERROR: %s

YOUR PREVIOUS RESPONSE:
%s

Reply again with corrected JSON ONLY, in the required shape. Use only the
allowed category values, and only tools from the available list.`, validationErr, prev)
}

// UserPrompt renders the live engagement context for one planning cycle.
func UserPrompt(eng *engagement.Engagement, st *state.State, tools []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ENGAGEMENT %s for client %q\n", eng.ID, eng.Client)
	if eng.Description != "" {
		fmt.Fprintf(&b, "Description: %s\n", eng.Description)
	}

	b.WriteString("\nOBJECTIVES:\n")
	for _, o := range eng.Objectives {
		fmt.Fprintf(&b, "  - %s\n", o)
	}

	b.WriteString("\nIN SCOPE:\n")
	for _, t := range eng.Scope.InScope {
		fmt.Fprintf(&b, "  - %s: %s\n", t.Type, t.Value)
	}
	b.WriteString("OUT OF SCOPE (never touch):\n")
	for _, t := range eng.Scope.OutOfScope {
		fmt.Fprintf(&b, "  - %s: %s\n", t.Type, t.Value)
	}

	fmt.Fprintf(&b, "\nRULES OF ENGAGEMENT:\n  max_risk: %s\n  allowed_categories: %s\n  forbidden_categories: %s\n",
		eng.RoE.MaxRisk,
		strings.Join(eng.RoE.AllowedCategories, ", "),
		strings.Join(eng.RoE.ForbiddenCategories, ", "),
	)

	fmt.Fprintf(&b, "\nAVAILABLE TOOLS: %s\n", strings.Join(tools, ", "))

	b.WriteString("\nCURRENT STATE:\n")
	b.WriteString(st.Summary())

	// The frontier is computed in Go from discovered service assets; it tells the
	// model what is worth doing next so it never has to parse raw output to find it.
	if fr := st.Frontier(); len(fr) > 0 {
		b.WriteString("\nDISCOVERED SERVICES (suggested next steps):\n")
		for _, f := range fr {
			fmt.Fprintf(&b, "  - %s", f.Value)
			if f.Service != "" {
				fmt.Fprintf(&b, " (%s)", f.Service)
			}
			if len(f.Suggested) > 0 {
				fmt.Fprintf(&b, " → %s", strings.Join(f.Suggested, "; "))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n\nWhat are the next 1-3 actions?")
	return b.String()
}
