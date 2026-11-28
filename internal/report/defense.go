package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/attack"
	"github.com/dukotah/tyto/internal/purple"
	"github.com/dukotah/tyto/internal/state"
)

// DefenseView is one defensive control the engagement ran into — the positive
// half of the report: what the client's defenses demonstrably did.
type DefenseView struct {
	Target  string `json:"target"`
	Control string `json:"control"`
	// Basis says how tyto knows: the exact signal and how much testing preceded
	// it, so the reader can weigh the inference.
	Basis string `json:"basis"`
}

// UnchallengedView is a target that received attack-like activity and showed no
// visible defensive reaction.
type UnchallengedView struct {
	Target string   `json:"target"`
	Tools  []string `json:"tools"` // the attack-like tools that ran against it
}

var defenseLabels = map[string]string{
	state.DefenseRateLimit:   "Rate limiting",
	state.DefenseConnReset:   "Connection reset mid-test (active blocking by an IPS/WAF, or service instability)",
	state.DefenseUnavailable: "Service unavailable under test load (load shedding, or an upstream block)",
}

// buildDefense derives the defensive-controls view from state: reactions the
// engine observed, WAF/CDN fingerprints from wafdetect, and the hosts that took
// attack-like activity with no visible reaction.
func buildDefense(st *state.State) (controls []DefenseView, unchallenged []UnchallengedView) {
	reacted := map[string]bool{}
	for _, d := range st.Defenses() {
		label := defenseLabels[d.Kind]
		if label == "" {
			label = d.Kind
		}
		basis := fmt.Sprintf("%s output contained %q, first after %d prior action(s) against this host; seen in %d result(s)", d.Tool, d.Signal, d.AfterActions, d.Count)
		controls = append(controls, DefenseView{Target: d.Target, Control: label, Basis: basis})
		reacted[d.Target] = true
	}
	for _, f := range st.Findings() {
		if f.Tool != "wafdetect" || strings.HasPrefix(f.Title, "No WAF/CDN") {
			continue
		}
		host := purple.HostOf(f.Target)
		controls = append(controls, DefenseView{
			Target: host, Control: strings.TrimPrefix(f.Title, "WAF/CDN detected: ") + " (WAF/CDN)", Basis: "fingerprinted by wafdetect: " + f.Description,
		})
		reacted[host] = true
	}
	sort.SliceStable(controls, func(i, j int) bool { return controls[i].Target < controls[j].Target })

	loud := map[string]map[string]bool{}
	for _, c := range st.Coverage() {
		if c.Kind != state.CoverageAction || !attack.ExpectsReaction(c.Ref) {
			continue
		}
		host := purple.HostOf(c.AssetRef)
		if host == "" || reacted[host] {
			continue
		}
		if loud[host] == nil {
			loud[host] = map[string]bool{}
		}
		loud[host][c.Ref] = true
	}
	for host, tools := range loud {
		u := UnchallengedView{Target: host}
		for t := range tools {
			u.Tools = append(u.Tools, t)
		}
		sort.Strings(u.Tools)
		unchallenged = append(unchallenged, u)
	}
	sort.Slice(unchallenged, func(i, j int) bool { return unchallenged[i].Target < unchallenged[j].Target })
	return controls, unchallenged
}

// writeDefense renders the defensive-controls section in Markdown. It writes
// nothing when there is nothing to say.
func writeDefense(b *strings.Builder, r Report) {
	if len(r.DefensiveControls) == 0 && len(r.Unchallenged) == 0 {
		return
	}
	b.WriteString("## Defensive controls observed\n\n")
	if len(r.DefensiveControls) > 0 {
		b.WriteString("Controls that visibly reacted to testing:\n\n")
		for _, d := range r.DefensiveControls {
			fmt.Fprintf(b, "- **%s** — %s\n  - %s\n", d.Target, d.Control, d.Basis)
		}
		b.WriteString("\n")
	}
	if len(r.Unchallenged) > 0 {
		b.WriteString("Targets that took attack-like activity with **no visible reaction** (no rate limiting, block, or WAF fingerprint):\n\n")
		for _, u := range r.Unchallenged {
			fmt.Fprintf(b, "- **%s** — %s\n", u.Target, strings.Join(u.Tools, ", "))
		}
		b.WriteString("\n")
	}
	b.WriteString("_These are inferences from how targets responded, not a control inventory. A control that only logs or alerts is invisible from the attacker's side — use `tyto purple score` with the SOC's alert export to measure detection._\n\n")
}
