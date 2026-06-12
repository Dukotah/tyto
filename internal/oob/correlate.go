package oob

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/state"
)

// classProfile holds the per-vuln-class report wording for a confirmed OOB
// callback. An out-of-band callback is direct, attacker-uncontrollable proof
// that injected input reached a sink that performed network egress, so every
// class below is reported Critical and Validated — there is no "candidate"
// state for an OOB hit, the box phoned home.
type classProfile struct {
	title  string
	desc   string
	impact string
	cvss   string // CVSS v3.1 vector
}

// profileFor returns the report wording for a vuln class. Unknown/empty classes
// fall back to a generic out-of-band-interaction profile so a callback is never
// silently dropped just because the registering tool used a novel class label.
func profileFor(class string) classProfile {
	switch strings.ToLower(strings.TrimSpace(class)) {
	case "ssrf":
		return classProfile{
			title:  "Blind SSRF (out-of-band callback confirmed)",
			desc:   "Injected input caused the target to make an attacker-controlled outbound request, confirmed by an out-of-band callback to the collaborator. The application can be coerced into issuing requests to arbitrary hosts (server-side request forgery).",
			impact: "Server-side request forgery enables access to internal-only services, cloud metadata endpoints, and other resources reachable from the server, often leading to credential theft or further pivoting.",
			cvss:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
		}
	case "blind-xss":
		return classProfile{
			title:  "Blind XSS (out-of-band callback confirmed)",
			desc:   "Injected script executed in a victim context and beaconed back to the collaborator, confirming stored/blind cross-site scripting. The payload ran JavaScript in a browser that rendered attacker-controlled data.",
			impact: "Blind XSS executes in privileged user or administrator sessions, allowing session hijacking, account takeover, and actions performed as the victim.",
			cvss:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
		}
	case "cmd-injection":
		return classProfile{
			title:  "OOB command injection (likely RCE)",
			desc:   "Injected input was executed by a server-side shell, confirmed by an out-of-band callback raised from the command (e.g. nslookup/curl of the collaborator domain). This demonstrates arbitrary OS command execution.",
			impact: "Operating-system command injection typically yields full remote code execution on the host, enabling complete compromise of the server and the data it can reach.",
			cvss:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		}
	case "sqli-oob":
		return classProfile{
			title:  "Out-of-band SQL injection (DNS/UNC exfil)",
			desc:   "Injected SQL triggered an out-of-band interaction (DNS resolution or UNC/file fetch) to the collaborator, confirming SQL injection on a path where results are not returned in-band.",
			impact: "Out-of-band SQL injection allows exfiltration of database contents and, depending on the DBMS, file read/write or command execution, even when responses are blind.",
			cvss:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
		}
	default:
		return classProfile{
			title:  "Out-of-band interaction confirmed",
			desc:   "Injected input caused an out-of-band callback to the collaborator, confirming that attacker-controlled data reached a sink performing network egress.",
			impact: "An out-of-band interaction confirms injection reached a dangerous sink; the concrete impact depends on the sink (SSRF, RCE, data exfiltration).",
			cvss:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
		}
	}
}

// Confirm turns a token that received at least one callback into a validated,
// Critical state.Finding. An OOB callback is unforgeable proof that the injected
// probe reached a network-egress sink, so the finding is always Validated.
// Returns (Finding{}, false) when the token has no recorded hits (or is unknown).
//
// Evidence carries the raw callback details (Proto + RemoteAddr + Detail) and is
// a quarantined field on Finding — it is attacker-influenced and must never enter
// a planner prompt. Repro records the callback Domain/URL plus the injected
// Param/Target so an operator can reproduce the interaction.
func (c *Collaborator) Confirm(token string) (state.Finding, bool) {
	hits := c.Poll(token)
	if len(hits) == 0 {
		return state.Finding{}, false
	}
	it, _ := c.Lookup(token)
	p := profileFor(it.Class)

	// Evidence: enumerate every callback so the report shows the full proof.
	var ev strings.Builder
	for i, h := range hits {
		if i > 0 {
			ev.WriteString("\n")
		}
		fmt.Fprintf(&ev, "[%s] %s from %s: %s", h.Proto, h.At.UTC().Format(time.RFC3339), h.RemoteAddr, h.Detail)
	}

	repro := fmt.Sprintf("Callback domain: %s", it.Domain)
	if it.URL != "" {
		repro += fmt.Sprintf("\nCallback URL: %s", it.URL)
	}
	if it.Target != "" {
		repro += fmt.Sprintf("\nTarget: %s", it.Target)
	}
	if it.Param != "" {
		repro += fmt.Sprintf("\nInjected parameter: %s", it.Param)
	}

	foundAt := hits[0].At
	for _, h := range hits[1:] {
		if h.At.Before(foundAt) {
			foundAt = h.At
		}
	}
	if foundAt.IsZero() {
		foundAt = time.Now().UTC()
	}

	return state.Finding{
		ID:          "oob-" + token,
		Title:       p.title,
		Severity:    state.SeverityCritical,
		Target:      it.Target,
		Description: p.desc,
		Evidence:    ev.String(),
		Tool:        "oobcheck",
		Repro:       repro,
		Impact:      p.impact,
		CVSS:        p.cvss,
		Validated:   true,
		FoundAt:     foundAt.UTC(),
	}, true
}

// ConfirmAll returns one validated finding per token that received at least one
// callback, stable-ordered by token so report output is deterministic.
func (c *Collaborator) ConfirmAll() []state.Finding {
	c.mu.RLock()
	tokens := make([]string, 0, len(c.hits))
	for tok, hs := range c.hits {
		if len(hs) > 0 {
			tokens = append(tokens, tok)
		}
	}
	c.mu.RUnlock()

	sort.Strings(tokens)

	out := make([]state.Finding, 0, len(tokens))
	for _, tok := range tokens {
		if f, ok := c.Confirm(tok); ok {
			out = append(out, f)
		}
	}
	return out
}
