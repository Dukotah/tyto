// Package hunt is tyto's deterministic, NO-LLM breadth-first sweep planner: the
// overnight engine for winning an automated bug bounty on a wildcard scope
// (*.example.com).
//
// The local CPU model is a TAX, not a brain. For the payable-for-an-automated-
// tool classes — subdomain takeover, exposed .git / secrets / config, and
// known-CVE/version templates — no reasoning is required, only a disciplined
// crawl + DNS + regex sweep across hundreds of hosts. So hunt computes the
// ENTIRE ordered action list in Go, with zero model calls, from just the asset
// graph + scope + the set of already-done actions.
//
// Plan is a pure function: same (state, scope, done) always yields the same
// plan. No randomness, no clock, no network. It is breadth-first (every host
// clears a stage before any host advances), idempotent/resumable (anything in
// done is skipped), and bounded (a max-hosts cap, with an explicit note action
// when it bites — never a silent truncation).
//
// Precision over recall: on a fresh bounty account a single false positive gets
// you banned, so this mode emits ONLY the high-signal payable-class probes and
// deliberately omits the noisy/low-value tools (no fuzzing, no injection, no
// nmap).
package hunt

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
)

// Tool names this planner emits. They are the existing built-in tools; hunt
// never invents a tool the registry doesn't have.
const (
	toolSubfinder = "subfinder"
	toolHTTPProbe = "httpprobe"

	// Payable-class probes, in priority order. This ordering is the product
	// thesis: a subdomain takeover is the single most reliably-payable finding an
	// automated tool produces, then an exposed .git / secret / config, then a
	// known-CVE template match. Content discovery (webdiscover) is last because it
	// is the broadest and most likely to overlap the others.
	toolSubtakeover  = "subtakeover"
	toolDotgit       = "dotgit"
	toolSecretScan   = "secretscan"
	toolTemplateScan = "templatescan"
	toolWebDiscover  = "webdiscover"
)

// payableProbes is the per-live-host probe battery in priority order. Only
// these run in hunt mode — the high-precision, payable-for-an-automated-tool
// classes. Order is load-bearing: it is the sequence a host is swept in.
var payableProbes = []string{
	toolSubtakeover,
	toolDotgit,
	toolSecretScan,
	toolTemplateScan,
	toolWebDiscover,
}

// noteTool is a synthetic, non-executable marker the engine surfaces to the
// operator (and never dispatches to a real tool). hunt emits one when the
// host cap truncates the sweep, so a capped run is loud, not silent.
const noteTool = "hunt-note"

// DefaultMaxHosts caps how many live hosts the per-host payable battery fans out
// across in a single plan, so an overnight run over a huge wildcard scope stays
// bounded and predictable. Callers override via Options.MaxHosts.
const DefaultMaxHosts = 500

// Options tunes a hunt plan. The zero value is valid and uses DefaultMaxHosts.
type Options struct {
	// MaxHosts bounds the number of live hosts the per-host payable battery is
	// fanned out across. <= 0 means DefaultMaxHosts. When more live hosts exist
	// than the cap, Plan covers the first cap hosts (deterministic order) and
	// emits a single note action so the truncation is explicit.
	MaxHosts int
}

func (o Options) maxHosts() int {
	if o.MaxHosts <= 0 {
		return DefaultMaxHosts
	}
	return o.MaxHosts
}

// Plan computes the next batch of deterministic, no-LLM sweep actions for an
// overnight breadth-first bug-bounty hunt.
//
// It is a PURE function of (state, scope, done): no clock, no randomness, no
// network. Given the same inputs it returns byte-identical output.
//
// Stages, run strictly breadth-first (a stage is fully emitted for every
// eligible target before the next stage contributes a single action):
//
//  1. enumerate — subfinder on every in-scope ROOT domain.
//  2. liveness  — httpprobe on every discovered subdomain/domain in scope.
//  3. payable   — per LIVE host, the payable-class probe battery in priority
//     order: subtakeover, dotgit, secretscan, templatescan, webdiscover. No
//     fuzzing, no injection, no nmap.
//
// Resumability: any action whose CanonicalKey is in done is skipped, so calling
// Plan repeatedly as work completes walks the sweep forward and returns nil once
// the whole scope is exhausted.
//
// Boundedness: the per-host stage fans out across at most opts.MaxHosts live
// hosts (deterministic order). If more exist, Plan appends ONE note action
// (Tool == NoteTool, returned by IsNote) naming the overflow — it never silently
// drops hosts.
func Plan(st *state.State, scope engagement.Scope, done map[string]bool, opts Options) []action.Action {
	if done == nil {
		done = map[string]bool{}
	}

	var assets []*state.Asset
	if st != nil {
		assets = st.Assets()
	}

	var out []action.Action
	emit := func(a action.Action) {
		if done[a.CanonicalKey()] {
			return
		}
		out = append(out, a)
	}

	// Stage 1: enumerate — subfinder on each in-scope root domain.
	for _, root := range rootDomains(scope) {
		emit(action.Action{
			ID:        "hunt-enum-" + root,
			Tool:      toolSubfinder,
			Category:  action.CategoryRecon.String(),
			Target:    root,
			Risk:      action.RiskPassive,
			Rationale: "hunt: enumerate subdomains of in-scope root " + root,
		})
	}

	// Stage 2: liveness — httpprobe every in-scope discovered subdomain/domain.
	for _, host := range probeHosts(assets, scope) {
		emit(action.Action{
			ID:        "hunt-probe-" + host,
			Tool:      toolHTTPProbe,
			Category:  action.CategoryRecon.String(),
			Target:    host,
			Risk:      action.RiskLow,
			Rationale: "hunt: probe liveness/fingerprint of " + host,
		})
	}

	// Stage 3: payable-class battery per LIVE host, breadth-first across hosts
	// (every host gets probe #1 before any host gets probe #2), bounded by the
	// host cap.
	live := liveHosts(assets, scope)
	maxHosts := opts.maxHosts()
	capped := len(live) > maxHosts
	if capped {
		live = live[:maxHosts]
	}
	for _, probe := range payableProbes {
		for _, host := range live {
			emit(action.Action{
				ID:        "hunt-" + probe + "-" + host,
				Tool:      probe,
				Category:  action.CategoryScan.String(),
				Target:    host,
				Risk:      action.RiskLow,
				Rationale: "hunt: " + probe + " on live host " + host,
			})
		}
	}

	// Boundedness: if the cap truncated the live set, say so loudly. The note is
	// emitted through the same dedup path, so a resumed plan won't repeat it.
	if capped {
		total := len(liveHosts(assets, scope))
		emit(action.Action{
			ID:       "hunt-note-cap",
			Tool:     noteTool,
			Category: action.CategoryRecon.String(),
			Target:   "scope",
			Risk:     action.RiskPassive,
			Rationale: fmt.Sprintf(
				"hunt: host cap reached — swept %d of %d live in-scope hosts; raise Options.MaxHosts (currently %d) to cover the rest",
				maxHosts, total, maxHosts),
		})
	}

	return out
}

// IsNote reports whether an action is the synthetic hunt note marker (a message
// for the operator, not a tool to dispatch). The engine MUST NOT execute it.
func IsNote(a action.Action) bool { return a.Tool == noteTool }

// NoteTool is the synthetic tool name carried by note actions, exported so the
// engine can route them to the operator instead of the tool registry.
const NoteTool = noteTool

// rootDomains returns the in-scope ROOT domains to enumerate, lowercased,
// de-duplicated, and sorted. Only TargetDomain entries are roots: a wildcard
// bounty scope is expressed as in-scope domains (the "*.example.com" root is the
// domain "example.com"), and only a domain can be fed to subfinder. IP/CIDR/URL
// entries are not enumerable roots and are skipped here. Out-of-scope roots are
// dropped so we never enumerate a domain the client excluded.
func rootDomains(scope engagement.Scope) []string {
	seen := map[string]bool{}
	var roots []string
	for _, t := range scope.InScope {
		if t.Type != engagement.TargetDomain {
			continue
		}
		d := normalizeHost(t.Value)
		if d == "" || seen[d] {
			continue
		}
		// Respect out-of-scope: don't enumerate an explicitly excluded root.
		if !scope.Contains(d) {
			continue
		}
		seen[d] = true
		roots = append(roots, d)
	}
	sort.Strings(roots)
	return roots
}

// probeHosts returns the in-scope hostnames worth an httpprobe: every discovered
// domain/host asset that falls in scope. Sorted + de-duplicated for determinism.
// IP host assets are included (a bare IP is a valid probe target); service/url/
// endpoint assets are not — those mean the host is already known live and are
// handled by the per-host battery, not re-probed for liveness.
func probeHosts(assets []*state.Asset, scope engagement.Scope) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, a := range assets {
		if a == nil {
			continue
		}
		var h string
		switch a.Type {
		case "domain", "host":
			h = normalizeHost(a.Value)
		default:
			continue
		}
		if h == "" || seen[h] {
			continue
		}
		if !scope.Contains(h) {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// liveHosts returns the in-scope hosts confirmed reachable — the targets for the
// payable battery. A host is LIVE when the asset graph carries evidence of a
// reachable web service for it:
//
//   - a `service` asset (httpprobe/portscan emit these for a confirmed service),
//     keyed by the host it belongs to; or
//   - a `domain`/`host` asset explicitly flagged live via Attrs (live / alive /
//     up == "true"/"1"/"yes", or status_code present), as a liveness probe would
//     stamp it.
//
// Bare discovered domains with no such evidence are NOT swept — running the
// payable battery against an unresolved name wastes the overnight budget and, on
// a parked/NXDOMAIN host, is exactly the kind of noise that risks false signals.
// Output is the bare host, de-duplicated and sorted for a deterministic,
// breadth-first fan-out.
func liveHosts(assets []*state.Asset, scope engagement.Scope) []string {
	seen := map[string]bool{}
	var hosts []string
	add := func(h string) {
		h = normalizeHost(h)
		if h == "" || seen[h] || !scope.Contains(h) {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	for _, a := range assets {
		if a == nil {
			continue
		}
		switch a.Type {
		case "service":
			add(hostOf(a.Value))
		case "domain", "host":
			if assetLive(a) {
				add(a.Value)
			}
		}
	}
	sort.Strings(hosts)
	return hosts
}

// assetLive reports whether a domain/host asset has been explicitly flagged as
// reachable by a liveness probe. Conservative: absent an affirmative flag, a
// host is NOT considered live.
func assetLive(a *state.Asset) bool {
	if a == nil || a.Attrs == nil {
		return false
	}
	for _, k := range []string{"live", "alive", "up"} {
		if isTrueish(a.Attrs[k]) {
			return true
		}
	}
	// A recorded HTTP status code is direct evidence the host answered.
	if strings.TrimSpace(a.Attrs["status_code"]) != "" {
		return true
	}
	return false
}

func isTrueish(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "y", "up", "live", "alive":
		return true
	}
	return false
}

// normalizeHost extracts and lowercases the bare host from a value that may be a
// URL, host:port, or bare hostname/IP, trimming a trailing dot. Returns "" for
// anything without a host.
func normalizeHost(v string) string {
	h := hostOf(v)
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	return h
}

// hostOf strips scheme, path, and port from a target that may be a URL or
// host:port pair, returning the bare host. Mirrors engagement.hostOf so hunt's
// scope checks line up with the guard's.
func hostOf(target string) string {
	t := strings.TrimSpace(target)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	return t
}
