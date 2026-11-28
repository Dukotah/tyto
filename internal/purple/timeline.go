// Package purple turns tyto's audit trail into blue-team deliverables: an attack
// timeline a SOC can replay against its own telemetry, a detection-coverage
// scorecard that correlates the defender's alerts with what tyto actually did,
// and an ATT&CK Navigator layer of the result.
//
// Everything here is derived, offline, from the hash-chained audit log — it never
// touches a target and needs no model. The audit log is the ground truth for
// "what the attacker did and when"; the defender's alert export is the ground
// truth for "what was noticed". The gap between the two is the deliverable.
package purple

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/attack"
	"github.com/dukotah/tyto/internal/audit"
)

// Activity is one executed action, as a defender should think about it: a time
// window, a destination, a technique, and where it ought to have shown up.
type Activity struct {
	Seq      int       `json:"seq"`       // 1-based order of execution
	ActionID string    `json:"action_id"` // the audit log's action id
	Tool     string    `json:"tool"`
	Target   string    `json:"target"`
	Host     string    `json:"host"` // bare host/IP/CIDR extracted from Target
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	// Techniques / Telemetry come from the attack package. Mapped is false for
	// free-form tools (kali) whose technique depends on the command.
	Techniques []attack.Technique `json:"techniques,omitempty"`
	Telemetry  []string           `json:"expected_telemetry,omitempty"`
	Mapped     bool               `json:"mapped"`
	// OffTarget activity never contacted client infrastructure, so no client
	// sensor could have seen it. It is listed for completeness but never scored.
	OffTarget bool `json:"off_target,omitempty"`
	Success   bool `json:"success"`
	Findings  int  `json:"findings"`
	// Incomplete is true when the log holds no result for the action (the run was
	// interrupted mid-action). End then equals Start.
	Incomplete bool `json:"incomplete,omitempty"`
}

// Marker is the engagement traffic marker tyto stamped on in-scope HTTP
// requests, when one was active. A SOC filters on it to separate test traffic
// from a real attack.
type Marker struct {
	Header string `json:"header"`
	Value  string `json:"value"`
}

// DefenseEvent is a defensive reaction tyto observed during the run (rate
// limiting, a block, a dropped connection), read back from the audit log.
type DefenseEvent struct {
	Time         time.Time `json:"time"`
	Target       string    `json:"target"`
	Kind         string    `json:"kind"`
	Detail       string    `json:"detail,omitempty"`
	AfterActions int       `json:"after_actions,omitempty"`
}

// Timeline is the full attacker-side record of an engagement.
type Timeline struct {
	EngagementID string `json:"engagement_id,omitempty"`
	Client       string `json:"client,omitempty"`
	// Source is where the test traffic came from (operator-supplied: the audit log
	// cannot know the egress address the client saw).
	Source string  `json:"source,omitempty"`
	Marker *Marker `json:"traffic_marker,omitempty"`
	// ChainVerified reports whether the audit hash chain was intact. A timeline
	// built from a broken chain is still produced, but must not be trusted as
	// evidence; ChainError says where it broke.
	ChainVerified bool           `json:"audit_chain_verified"`
	ChainError    string         `json:"audit_chain_error,omitempty"`
	Start         time.Time      `json:"start"`
	End           time.Time      `json:"end"`
	Activities    []Activity     `json:"activities"`
	Defenses      []DefenseEvent `json:"defenses_observed,omitempty"`
	// Resolved maps an activity hostname to the IP addresses it resolved to when
	// the timeline was built (only with --resolve), so alerts keyed by IP can be
	// matched to activity keyed by name.
	Resolved map[string][]string `json:"resolved,omitempty"`
}

// BuildOptions tunes timeline construction.
type BuildOptions struct {
	Source string
	// Resolve, when non-nil, is used to resolve activity hostnames to IPs.
	Resolve func(host string) []string
}

// Build derives a Timeline from audit entries. Only actions that were actually
// executed appear: guard denials, approval refusals and dry-run proposals never
// touched a target and are not attacker activity.
func Build(entries []audit.Entry, opts BuildOptions) Timeline {
	tl := Timeline{Source: opts.Source, ChainVerified: true}
	if err := audit.Verify(entries); err != nil {
		tl.ChainVerified = false
		tl.ChainError = err.Error()
	}

	// An action id can recur (across cycles or resumed runs), so each result is
	// paired with the oldest still-open action of the same id.
	open := map[string][]int{}
	for _, e := range entries {
		switch e.Kind {
		case "info":
			switch str(e.Data, "event") {
			case "engagement_start":
				if tl.EngagementID == "" {
					tl.EngagementID, tl.Client = str(e.Data, "id"), str(e.Data, "client")
				}
			case "traffic_marker":
				if h, v := str(e.Data, "header"), str(e.Data, "value"); h != "" {
					tl.Marker = &Marker{Header: h, Value: v}
				}
			}
		case "action":
			id, toolName, target := str(e.Data, "action"), str(e.Data, "tool"), str(e.Data, "target")
			a := Activity{
				Seq: len(tl.Activities) + 1, ActionID: id, Tool: toolName, Target: target,
				Host: HostOf(target), Start: e.Time, End: e.Time, Incomplete: true,
			}
			if mp, ok := attack.ForTool(toolName); ok {
				a.Mapped, a.Techniques, a.Telemetry, a.OffTarget = true, mp.Techniques, mp.Telemetry, mp.OffTarget
			}
			tl.Activities = append(tl.Activities, a)
			open[id] = append(open[id], len(tl.Activities)-1)
		case "result":
			id := str(e.Data, "action")
			q := open[id]
			if len(q) == 0 {
				continue // a result for a skipped/unknown action — nothing ran
			}
			a := &tl.Activities[q[0]]
			open[id] = q[1:]
			a.End, a.Incomplete = e.Time, false
			a.Success, _ = e.Data["success"].(bool)
			a.Findings = num(e.Data, "findings")
		case "defense_observed":
			tl.Defenses = append(tl.Defenses, DefenseEvent{
				Time: e.Time, Target: str(e.Data, "target"), Kind: str(e.Data, "kind"),
				Detail: str(e.Data, "detail"), AfterActions: num(e.Data, "after_actions"),
			})
		}
	}

	for i, a := range tl.Activities {
		if i == 0 || a.Start.Before(tl.Start) {
			tl.Start = a.Start
		}
		if a.End.After(tl.End) {
			tl.End = a.End
		}
	}

	if opts.Resolve != nil {
		tl.Resolved = map[string][]string{}
		for _, a := range tl.Activities {
			if a.Host == "" || a.OffTarget || isIPOrCIDR(a.Host) {
				continue
			}
			if _, done := tl.Resolved[a.Host]; done {
				continue
			}
			ips := opts.Resolve(a.Host)
			sort.Strings(ips)
			tl.Resolved[a.Host] = ips
		}
	}
	return tl
}

// NetResolver resolves a hostname with the system resolver, returning nil on
// failure (an unresolvable name simply contributes no IP aliases).
func NetResolver(host string) []string {
	ips, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	return ips
}

// HostOf reduces a target (URL, host:port, bare host, IP, or CIDR) to the bare
// lower-cased host, IP, or CIDR a defender's alert would name.
func HostOf(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	if _, err := netip.ParsePrefix(t); err == nil {
		return t
	}
	if _, err := netip.ParseAddr(t); err == nil {
		return strings.ToLower(t)
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	return strings.ToLower(strings.Trim(t, "[]"))
}

func isIPOrCIDR(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(h)
	return err == nil
}

func str(d map[string]any, k string) string {
	if v, ok := d[k]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}
	return ""
}

func num(d map[string]any, k string) int {
	switch v := d[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}
