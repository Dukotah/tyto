// Package report turns engagement state into a human-readable report. Markdown
// today; SARIF/JSON/PDF are on the roadmap.
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
)

// Render produces a Markdown report for an engagement and its findings.
func Render(eng *engagement.Engagement, st *state.State) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Engagement report — %s\n\n", eng.ID)
	fmt.Fprintf(&b, "**Client:** %s  \n", eng.Client)
	fmt.Fprintf(&b, "**Authorized by:** %s  \n", eng.Authorization.AuthorizedBy)
	fmt.Fprintf(&b, "**Agreement:** %s\n\n", eng.Authorization.AgreementRef)

	findings := st.Findings()
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Severity > findings[j].Severity
	})

	assets := st.Assets()
	fmt.Fprintf(&b, "## Summary\n\n- Assets discovered: %d\n- Findings: %d\n\n", len(assets), len(findings))

	if len(findings) == 0 {
		b.WriteString("No findings recorded.\n")
		return b.String()
	}

	b.WriteString("## Findings\n")
	for _, f := range findings {
		fmt.Fprintf(&b, "\n### [%s] %s\n", strings.ToUpper(f.Severity.String()), f.Title)
		fmt.Fprintf(&b, "- **Target:** %s\n- **Tool:** %s\n", f.Target, f.Tool)
		if f.Description != "" {
			fmt.Fprintf(&b, "- **Detail:** %s\n", f.Description)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "- **Evidence:** `%s`\n", f.Evidence)
		}
	}
	return b.String()
}
