package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/engagement"
)

// pentestVerbs map an opening verb to a default depth, so a plain "pentest X" or
// "recon X" routes deterministically — no model call needed to start a run.
var pentestVerbs = map[string]string{
	"pentest": "scan", "pen-test": "scan", "scan": "scan", "assess": "scan",
	"attack": "scan", "enumerate": "scan", "enum": "scan", "audit": "scan",
	"recon": "recon", "footprint": "recon", "exploit": "full",
}

// targetRe extracts the first URL, CIDR, IPv4, dotted hostname, or localhost[:port]
// from a message.
var targetRe = regexp.MustCompile(`(?i)(https?://[^\s]+|(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?::\d+)?|localhost(?::\d+)?(?:/[^\s]*)?|(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/[^\s]*)?)`)

// parsePentestIntent recognizes "pentest/scan/recon <target>" without the model.
// It only fires when the FIRST word is a pentest verb AND a target token is
// present, so plain questions ("scan the wordlists for X") fall through to the
// model. Returns the target, default depth, and whether it matched.
func parsePentestIntent(msg string) (target, depth string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(msg))
	if len(fields) < 2 {
		return "", "", false
	}
	d, isVerb := pentestVerbs[strings.ToLower(strings.Trim(fields[0], ".,!:"))]
	if !isVerb {
		return "", "", false
	}
	m := strings.TrimRight(targetRe.FindString(msg), ".,!")
	if m == "" {
		return "", "", false
	}
	// A "full"/"exploit" signal anywhere upgrades to full depth (exploitation),
	// so "fully pentest X" or "pentest X and exploit it" reaches the exploit tier.
	low := strings.ToLower(msg)
	if strings.Contains(low, "full") || strings.Contains(low, "exploit") {
		d = "full"
	}
	return m, d, true
}

// The conversational on-ramp: "pentest 10.0.0.5" in the chat builds an authorized
// engagement on the fly and turns the guarded autonomous engine loose — tools
// running in Kali — instead of requiring a hand-written engagement YAML first.
//
// Safety stays intact via the SCOPE check, which is absolute: an ad-hoc
// engagement is self-attested (the operator attests authorization for bug-bounty
// / self-directed testing, where no client signs a grant), so the Scope Guard
// permits exploit/high-risk actions — but ONLY against the single in-scope target.
// Anything off that target is still denied. The operator must explicitly confirm
// authorization before a run starts, and the attestation is recorded in the
// engagement's authorization record.

// pentestReq is a target+depth held pending the operator's authorization confirmation.
type pentestReq struct {
	Target string
	Depth  string
}

// normalizeAdHocDepth resolves a requested depth for the ad-hoc path. Because the
// ad-hoc engagement is self-attested (operator-authorized), "full"/exploit depth
// is allowed — the Scope Guard still bounds every action to the in-scope target.
// The note flags when a run will reach weaponized exploitation so the operator
// sees what they're authorizing.
func normalizeAdHocDepth(requested string) (depth, note string) {
	_, _, norm := profileFor(requested)
	if norm == "full" {
		return "full", "(This is full depth: I'm authorized to attempt exploitation/post-exploitation against the in-scope target to confirm findings. The Scope Guard keeps every action on that target.) "
	}
	return norm, ""
}

// buildAdHocEngagement constructs an in-memory, validated engagement for a single
// target at the given depth. Returns an error message string (not error) for
// direct use in a chat reply.
func (c *console) buildAdHocEngagement(target, depth string) (*engagement.Engagement, string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, "no target given"
	}
	ttype, ok := detectTargetType("auto", target)
	if !ok {
		return nil, fmt.Sprintf("I couldn't tell what kind of target %q is (expected an IP, CIDR, domain, or URL).", target)
	}
	allowed, maxRisk, norm := profileFor(depth)
	eng := &engagement.Engagement{
		ID:          "adhoc-" + sanitizeID(target) + "-" + time.Now().UTC().Format("150405"),
		Client:      "ad-hoc (operator-authorized via console)",
		Description: "Conversational " + norm + " assessment launched from the tyto console.",
		Authorization: engagement.Authorization{
			// Self-attested: the operator attests authorization (bug-bounty /
			// self-directed testing). This permits exploit/high-risk actions without a
			// client-signed grant — but the Scope Guard still bounds every action to
			// the single in-scope target below. The attestation is recorded here.
			Mode:         "self-attested",
			AuthorizedBy: "operator (tyto console)",
			AuthorizedOn: time.Now().UTC().Format("2006-01-02"),
			AgreementRef: "operator-asserted authorization in console session",
		},
		Scope: engagement.Scope{
			InScope: []engagement.Target{{Type: ttype, Value: target}},
		},
		RoE: engagement.RoE{
			MaxRisk:           maxRisk,
			AllowedCategories: allowed,
			MaxRPS:            5,
			MaxConcurrent:     2,
		},
	}
	if err := eng.Validate(); err != nil {
		return nil, "I couldn't build a valid engagement: " + err.Error()
	}
	return eng, ""
}

// launchPentest builds the ad-hoc engagement and starts the autonomous run.
// Returns the chat reply and whether it started.
func (c *console) launchPentest(target, depth string) (string, bool) {
	eng, errMsg := c.buildAdHocEngagement(target, depth)
	if errMsg != "" {
		return errMsg, false
	}
	objective := "Run a thorough authorized " + depth + " assessment of " + target +
		": enumerate hosts and services, fingerprint them, find and validate vulnerabilities, and report findings."
	if msg := c.launchEngagement(eng, objective, "ollama", 8, depth, false, false, false); msg != "" {
		return "I couldn't start the assessment: " + msg, false
	}
	// The operator authorized this target; remember it for the session so a later
	// "scan it again" / follow-up doesn't re-prompt for the same confirmation.
	c.rememberAuthorized(target)
	return "Starting an authorized " + depth + " assessment of " + target +
		" — tools are running in Kali and the Scope Guard is enforcing bounds. Watch me work in the live panel; say 'stop' anytime.", true
}

// authMode returns the engagement's authorization mode for the audit record,
// normalizing the empty default to its explicit name so the trail is unambiguous.
func authMode(eng *engagement.Engagement) string {
	if eng.Authorization.SelfAttested() {
		return "self-attested"
	}
	return "client-grant"
}

// sanitizeID makes a target safe to embed in an engagement ID.
func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" {
		id = "target"
	}
	if len(id) > 40 {
		id = id[:40]
	}
	return id
}
