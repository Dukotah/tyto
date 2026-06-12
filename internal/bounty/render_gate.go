package bounty

import (
	"fmt"
	"strings"
)

// RenderGate renders the full tiered submission report to Markdown: the
// actionable body (VALIDATED then CANDIDATE, each clearly tagged and ranked),
// followed by a separate, never-in-the-submit-body list of retained NOISE.
//
// title is the report heading (e.g. an engagement id or "tyto bounty sweep").
func RenderGate(title string, g Gate) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# %s — submission gate\n\n", strings.TrimSpace(title))
	fmt.Fprintf(&b, "Validated: %d  |  Candidate: %d  |  Noise (retained, not submitted): %d\n\n",
		len(g.Validated), len(g.Candidate), len(g.Noise))

	actionable := g.Actionable()
	if len(actionable) == 0 {
		b.WriteString("No actionable findings after the submission gate.\n\n")
	} else {
		b.WriteString("## Actionable (submit these)\n\n")
		for _, iss := range actionable {
			// Each issue's Writeup already begins with its own "## " heading and
			// carries the tier tag, so emit it verbatim — paste-ready per issue.
			b.WriteString(iss.Writeup)
			if !strings.HasSuffix(iss.Writeup, "\n\n") {
				b.WriteString("\n")
			}
			b.WriteString("---\n\n")
		}
	}

	if len(g.Noise) > 0 {
		b.WriteString("## Retained as noise (never submitted)\n\n")
		b.WriteString("_Low-value / non-submittable (missing headers, version banners, info-only). Kept for the audit trail; not part of any submission._\n\n")
		for _, iss := range g.Noise {
			fmt.Fprintf(&b, "- **[%s]** %s (`%s`) — %d target(s) — class: %s\n",
				strings.ToUpper(iss.Severity.String()), strings.TrimSpace(iss.Title),
				iss.Tool, len(iss.Targets), iss.Class.label())
		}
		b.WriteString("\n")
	}

	return b.String()
}
