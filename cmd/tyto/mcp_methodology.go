package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/methodology"
	"github.com/dukotah/tyto/internal/state"
)

// This file bridges tyto's methodology engine to the MCP operator. Without it, a
// frontier model driving tyto over MCP sees only raw tool execution and must
// invent its own method — so it wanders, repeats work, and declares "done" with
// whole phases untested. tyto_methodology hands the model the same governed,
// ranked frontier the autonomous engine uses, plus live coverage and a
// full-scope playbook (external → web → internal → AD → post-exploitation) so a
// full-scope engagement is actually walked end to end, and the audit can show
// what was and wasn't covered.

// phaseOrder is the PTES-grounded order the recommended frontier is presented in.
// The catalog today populates the first four; the rest are driven through the
// existing arsenal (see fullScopePlaybook) until native tools land.
var phaseOrder = []string{"recon", "scanning", "vuln-analysis", "exploitation"}

var phaseTitle = map[string]string{
	"recon":         "Recon / attack surface",
	"scanning":      "Scanning & enumeration",
	"vuln-analysis": "Vulnerability analysis",
	"exploitation":  "Exploitation & impact",
}

// coverKey normalizes a (target, tool) pair so a technique recommended for an
// asset answers the same as the action anchor the engine/MCP recorded when it
// ran. Mirrors the loose matching the engine uses (AssetRef = action target,
// Ref = tool name).
func coverKey(target, tool string) string {
	return strings.ToLower(strings.TrimSpace(target)) + "\x00" + strings.ToLower(strings.TrimSpace(tool))
}

// methodologyText renders the coverage-aware, full-scope methodology view for the
// driving model. It reads only current engagement state — no actions are taken.
func (s *mcpServer) methodologyText() string {
	avail := map[string]bool{}
	for _, n := range s.reg.Names() {
		avail[n] = true
	}
	recs := methodology.Recommend(s.state.Assets(), avail)

	// What's already been done, from action-coverage anchors.
	covered := map[string]bool{}
	for _, c := range s.state.Coverage() {
		if c.Kind == state.CoverageAction {
			covered[coverKey(c.AssetRef, c.Ref)] = true
		}
	}

	// Partition the frontier into done / to-do, grouped by phase. recs is already
	// value-ranked by Recommend, so within a phase the order is meaningful.
	type grouped struct {
		todo []methodology.Recommendation
		done int
	}
	byPhase := map[string]*grouped{}
	for _, r := range recs {
		g := byPhase[r.Technique.Phase]
		if g == nil {
			g = &grouped{}
			byPhase[r.Technique.Phase] = g
		}
		if covered[coverKey(r.Target, r.Technique.Tool)] {
			g.done++
		} else {
			g.todo = append(g.todo, r)
		}
	}

	var b strings.Builder
	b.WriteString("TYTO METHODOLOGY — governed full-scope frontier\n")
	b.WriteString("Walk every phase that has in-scope assets. Each line is a technique bound\n")
	b.WriteString("to a discovered asset: run it with tyto_execute (tool + target shown).\n")
	b.WriteString("Do NOT finalize tyto_report while a phase below still lists to-do items.\n\n")

	nAssets := len(s.state.Assets())
	if nAssets == 0 {
		b.WriteString("No assets discovered yet. Seed the frontier first:\n")
		b.WriteString("  • Web target in scope?  tyto_execute httpprobe <url>  (then webcrawl, jsmine)\n")
		b.WriteString("  • Domain in scope?       tyto_execute dnsenum <domain> (then subfinder)\n")
		b.WriteString("  • CIDR / internal range? tyto_execute netsweep <cidr>  (then portscan)\n\n")
	}

	// Phases present in the catalog frontier, in PTES order.
	anyTodo := false
	for _, ph := range phaseOrder {
		g := byPhase[ph]
		if g == nil {
			continue
		}
		title := phaseTitle[ph]
		if title == "" {
			title = ph
		}
		fmt.Fprintf(&b, "## %s  (%d to-do, %d done)\n", title, len(g.todo), g.done)
		if len(g.todo) == 0 {
			b.WriteString("  ✓ covered for all current assets\n\n")
			continue
		}
		anyTodo = true
		// Cap per phase so the view stays readable; the model re-calls as state grows.
		const cap = 12
		for i, r := range g.todo {
			if i == cap {
				fmt.Fprintf(&b, "  … +%d more\n", len(g.todo)-cap)
				break
			}
			fmt.Fprintf(&b, "  • %-14s %-26s %s\n", r.Technique.Tool, r.Target, r.Technique.Why)
		}
		b.WriteString("\n")
	}

	if !anyTodo && nAssets > 0 {
		b.WriteString("All catalog techniques are covered for the assets found so far. Expand the\n")
		b.WriteString("surface (crawl deeper, enumerate more hosts) or move to the phases below.\n\n")
	}

	b.WriteString(fullScopePlaybook())
	return b.String()
}

// fullScopePlaybook is the part of a real engagement the asset-triggered catalog
// does not yet model as native techniques: internal network, Active Directory,
// and post-exploitation. These are driven through the existing arsenal — native
// enumerators where they exist, otherwise tyto_kali (the full distro, every
// state-changing command human-approved and audited). Surfacing it here means the
// model is guided through the WHOLE kill chain, not just the web layer, with
// governance intact.
func fullScopePlaybook() string {
	lines := []struct{ phase, how string }{
		{"Internal discovery", "netsweep <cidr> → portscan/nmapscan each live host  [native]"},
		{"Service enumeration", "smbenum / ldapenum / ftpcheck / sshcheck per service  [native, nxc-backed]"},
		{"Credential access", "kerberoast (AS-REP + Kerberoast), defaultcreds, hydra  [native, gated]"},
		{"AD attack paths", "tyto_kali: bloodhound-python/nxc collect → analyze for paths  [kali, gated]"},
		{"Poisoning / relay", "tyto_kali: responder / ntlmrelayx — only if RoE permits  [kali, gated]"},
		{"Lateral movement", "tyto_kali: nxc / impacket (psexec, wmiexec, winrm) with creds  [kali, gated]"},
		{"Privilege escalation", "tyto_kali: winpeas / linpeas / GTFOBins checks  [kali, gated]"},
		{"Pivoting", "tyto_kali: ligolo-ng / chisel to reach deeper segments  [kali, gated]"},
		{"Post-ex / looting", "tyto_kali: scoped collection; persistence only if RoE permits  [kali, gated]"},
	}
	var b strings.Builder
	b.WriteString("## Full-scope phases (internal / AD / post-exploitation)\n")
	b.WriteString("Beyond the web layer. Gated steps block on human approval and are audited;\n")
	b.WriteString("every action is still scope-checked. Pursue these once you have a foothold\n")
	b.WriteString("or an internal range in scope:\n")
	for _, l := range lines {
		fmt.Fprintf(&b, "  • %-21s %s\n", l.phase, l.how)
	}
	return b.String()
}

// phasesWithTodo is a small helper used by tests to assert the frontier
// partitions deterministically.
func phasesWithTodo(recs []methodology.Recommendation, covered map[string]bool) []string {
	seen := map[string]bool{}
	for _, r := range recs {
		if covered[coverKey(r.Target, r.Technique.Tool)] {
			continue
		}
		seen[r.Technique.Phase] = true
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
