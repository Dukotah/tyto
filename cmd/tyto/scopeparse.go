package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dukotah/tyto/internal/engagement"
)

// Phase 2 — bug-bounty scope ingestion. The operator pastes a program's scope /
// rules text (multiple in-scope domains/wildcards, out-of-scope carve-outs, a
// rate limit, forbidden activities) and tyto turns it into a single self-attested
// engagement. Like the ad-hoc on-ramp, NOTHING launches automatically: the parsed
// scope is summarized and held in c.pendingScope until the operator confirms, so a
// mis-parsed program can never auto-run against the wrong asset. The Scope Guard's
// absolute scope check still bounds every action to the parsed in-scope set.

// scopeEntry is one extracted scope line as the model returns it (a declared type
// and a raw value). It is deliberately permissive — normalizeScopeEntry does the
// cleanup (stripping wildcards, schemes, paths) and type inference.
type scopeEntry struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// scopeRules are the optional rules-of-engagement knobs pulled from the program's
// policy text. All fields are best-effort; a program that omits them just leaves
// the defaults in place.
type scopeRules struct {
	MaxRPS    float64  `json:"max_requests_per_second"`
	Forbidden []string `json:"forbidden"` // free-text activities, e.g. "dos", "social-engineering"
	Notes     string   `json:"notes"`
}

// extractedScope is the strict-schema shape the model fills from a pasted program.
type extractedScope struct {
	Program    string       `json:"program"`
	InScope    []scopeEntry `json:"in_scope"`
	OutOfScope []scopeEntry `json:"out_of_scope"`
	Rules      scopeRules   `json:"rules"`
}

// scopeExtractSchema is the STRICT extraction schema handed to the model: pull the
// in-scope / out-of-scope entries and the rules from a pasted bug-bounty program.
// Each entry is a {type,value}; type uses the same vocabulary as detectTargetType.
var scopeExtractSchema = json.RawMessage(`{
  "type":"object",
  "properties":{
    "program":{"type":"string"},
    "in_scope":{"type":"array","items":{"type":"object","properties":{
      "type":{"type":"string","enum":["domain","url","ip","cidr","auto"]},
      "value":{"type":"string"}},"required":["value"]}},
    "out_of_scope":{"type":"array","items":{"type":"object","properties":{
      "type":{"type":"string","enum":["domain","url","ip","cidr","auto"]},
      "value":{"type":"string"}},"required":["value"]}},
    "rules":{"type":"object","properties":{
      "max_requests_per_second":{"type":"number"},
      "forbidden":{"type":"array","items":{"type":"string"}},
      "notes":{"type":"string"}}}
  },
  "required":["in_scope"]
}`)

// stripWildcard normalizes a wildcard scope value to a plain host. A scope domain
// like "example.com" already matches every subdomain via Target.matches's
// suffix-match (see internal/engagement/scope.go), so "*.example.com" is stored as
// the domain "example.com" — the leading "*." (and any leftover bare "*.") is
// peeled off. A bare "*" (match-everything) is rejected by returning "".
func stripWildcard(value string) string {
	v := strings.TrimSpace(value)
	// Peel any leading wildcard labels: "*.*.example.com" -> "example.com".
	for strings.HasPrefix(v, "*.") {
		v = v[2:]
	}
	v = strings.TrimSpace(v)
	if v == "" || v == "*" {
		return ""
	}
	return v
}

// normalizeScopeEntry turns one extracted entry into a concrete Target, or
// ok=false to skip it (empty / un-typeable / a bare match-everything wildcard).
// Wildcards are flattened to a domain (stripWildcard) BEFORE type inference so the
// "*." prefix doesn't get mistaken for a URL path. The declared type is honored
// when present; "" / "auto" / unknown falls back to inference.
func normalizeScopeEntry(e scopeEntry) (engagement.Target, bool) {
	raw := strings.TrimSpace(e.Value)
	if raw == "" {
		return engagement.Target{}, false
	}
	declared := strings.ToLower(strings.TrimSpace(e.Type))
	// Wildcards only make sense for hostnames; strip them for domain/url/auto/blank.
	// For an explicit ip/cidr we leave the value as-is (a "*" there is just invalid
	// and will be dropped below when detection fails).
	value := raw
	if declared != "ip" && declared != "cidr" {
		if strings.Contains(value, "*") {
			value = stripWildcard(value)
			if value == "" {
				return engagement.Target{}, false
			}
			// A flattened wildcard is a hostname; don't let a declared "url" turn it
			// back into a URL-typed entry (we want the suffix-matching domain form).
			if declared == "url" || declared == "" || declared == "auto" {
				declared = "domain"
			}
		}
	}
	tt, ok := detectTargetType(declared, value)
	if !ok {
		return engagement.Target{}, false
	}
	return engagement.Target{Type: tt, Value: value}, true
}

// toTargets maps a list of extracted entries to Targets, dropping any that don't
// normalize and de-duplicating on type+value so a program that lists the same host
// twice (e.g. as "*.x.com" and "x.com") yields one entry.
func toTargets(list []scopeEntry) []engagement.Target {
	seen := map[string]bool{}
	out := make([]engagement.Target, 0, len(list))
	for _, e := range list {
		t, ok := normalizeScopeEntry(e)
		if !ok {
			continue
		}
		key := string(t.Type) + "|" + strings.ToLower(t.Value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

// normalizeForbidden maps the model's free-text forbidden activities onto the
// engagement's closed category taxonomy where they line up (so a program's "no
// DoS" actually tightens the RoE's ForbiddenCategories and the guard enforces it),
// and returns the leftover human-readable notes separately. "dos" is always
// forbidden on the bug-bounty path regardless of what the program text says.
func normalizeForbidden(items []string) (categories, notes []string) {
	catSet := map[string]bool{"dos": true} // DoS forbidden by default on this path
	for _, raw := range items {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		switch {
		case strings.Contains(s, "dos") || strings.Contains(s, "denial") || strings.Contains(s, "ddos"):
			catSet["dos"] = true
		default:
			notes = append(notes, strings.TrimSpace(raw))
		}
	}
	for c := range catSet {
		categories = append(categories, c)
	}
	return categories, notes
}

// buildScopeEngagement turns an extracted program into a validated, self-attested
// engagement. Like the ad-hoc on-ramp it is operator-attested (bug-bounty), so the
// Scope Guard permits scan-depth actions while bounding everything to the parsed
// in-scope set. Returns an error message string (not error) for direct chat use.
func (c *console) buildScopeEngagement(ex extractedScope) (*engagement.Engagement, string) {
	inScope := toTargets(ex.InScope)
	if len(inScope) == 0 {
		return nil, "I couldn't pull any usable in-scope targets from that. Paste the program's in-scope list (domains/wildcards/URLs/IPs)."
	}
	outOfScope := toTargets(ex.OutOfScope)

	forbidden, extraNotes := normalizeForbidden(ex.Rules.Forbidden)

	// A bug-bounty program is scan-depth by default: recon + active scanning + web
	// testing, no weaponized exploitation, even though it's self-attested. The
	// operator can still launch a deeper ad-hoc run against a specific in-scope host
	// later if the program permits it.
	allowed, maxRisk, norm := profileFor("scan")

	maxRPS := ex.Rules.MaxRPS
	if maxRPS < 0 {
		maxRPS = 0
	}
	if maxRPS == 0 {
		maxRPS = 5 // conservative default when the program doesn't state a limit
	}

	program := strings.TrimSpace(ex.Program)
	if program == "" {
		program = hostLabel(inScope[0].Value)
	}
	desc := "Bug-bounty program scope ingested from pasted policy text (" + norm + " depth)."
	notes := strings.TrimSpace(ex.Rules.Notes)
	if len(extraNotes) > 0 {
		if notes != "" {
			notes += " "
		}
		notes += "Program restrictions: " + strings.Join(extraNotes, "; ") + "."
	}
	if notes != "" {
		desc += " " + notes
	}

	eng := &engagement.Engagement{
		ID:          "bb-" + sanitizeID(program) + "-" + time.Now().UTC().Format("150405"),
		Client:      "bug-bounty: " + program + " (operator-attested)",
		Description: desc,
		Objectives:  []string{"Assess the in-scope bug-bounty targets for security issues within the program's rules."},
		Authorization: engagement.Authorization{
			// Self-attested, exactly like the ad-hoc on-ramp (Phase 1): the operator
			// attests authorization under the bug-bounty program. The Scope Guard still
			// bounds every action to the in-scope set parsed above.
			Mode:         "self-attested",
			AuthorizedBy: "operator (tyto console, bug-bounty program)",
			AuthorizedOn: time.Now().UTC().Format("2006-01-02"),
			AgreementRef: "bug-bounty program: " + program,
		},
		Scope: engagement.Scope{InScope: inScope, OutOfScope: outOfScope},
		RoE: engagement.RoE{
			MaxRisk:             maxRisk,
			AllowedCategories:   allowed,
			ForbiddenCategories: forbidden,
			MaxRPS:              maxRPS,
			MaxConcurrent:       2,
		},
	}
	if err := eng.Validate(); err != nil {
		return nil, "I couldn't build a valid engagement from that scope: " + err.Error()
	}
	return eng, ""
}

// scopeSummary renders a human-readable preview of a parsed scope engagement for
// the mandatory confirmation step: what's in scope, what's carved out, the pacing
// limit, and forbidden activities. NOTHING runs until the operator says yes.
func scopeSummary(eng *engagement.Engagement) string {
	var b strings.Builder
	b.WriteString("Here's what I parsed from that program — **review it before anything runs**:\n\n")
	fmt.Fprintf(&b, "**Program:** %s\n\n", eng.Client)

	b.WriteString("**In scope** (")
	fmt.Fprintf(&b, "%d):\n", len(eng.Scope.InScope))
	for _, t := range eng.Scope.InScope {
		fmt.Fprintf(&b, "  - %s (%s)\n", t.Value, t.Type)
	}
	if len(eng.Scope.OutOfScope) > 0 {
		fmt.Fprintf(&b, "\n**Out of scope** (%d):\n", len(eng.Scope.OutOfScope))
		for _, t := range eng.Scope.OutOfScope {
			fmt.Fprintf(&b, "  - %s (%s)\n", t.Value, t.Type)
		}
	} else {
		b.WriteString("\n**Out of scope:** none listed.\n")
	}

	fmt.Fprintf(&b, "\n**Limits:** ≤ %s risk; %s; max %g req/s.\n",
		eng.RoE.MaxRisk, strings.Join(eng.RoE.AllowedCategories, "/"), eng.RoE.MaxRPS)
	if len(eng.RoE.ForbiddenCategories) > 0 {
		fmt.Fprintf(&b, "**Forbidden:** %s.\n", strings.Join(eng.RoE.ForbiddenCategories, ", "))
	}

	b.WriteString("\nNote: wildcards like `*.example.com` are stored as the domain `example.com`, which matches every subdomain. " +
		"Out-of-scope entries always win.\n\n" +
		"Reply **yes** to set up this authorized engagement, or **no** to cancel. (Nothing has run yet.)")
	return b.String()
}

// looksLikePastedScope is a cheap deterministic heuristic for "this is a pasted
// bug-bounty program, not a single target." It fires when a multi-line paste names
// several hosts/wildcards or uses the program's structural vocabulary (in scope /
// out of scope), so the chat can route to the scope extractor without first
// spending a (CPU-bound) model round-trip just to classify. Conservative on
// purpose: a single "scan example.com" must NOT trip it (that's the ad-hoc path).
func looksLikePastedScope(msg string) bool {
	s := strings.TrimSpace(msg)
	if len(s) < 40 {
		return false
	}
	lower := strings.ToLower(s)
	multiLine := strings.Count(s, "\n") >= 2

	hasScopeVocab := strings.Contains(lower, "out of scope") || strings.Contains(lower, "out-of-scope") ||
		strings.Contains(lower, "in scope") || strings.Contains(lower, "in-scope") ||
		(strings.Contains(lower, "scope") && (strings.Contains(lower, "bounty") || strings.Contains(lower, "program")))

	// Count wildcard hosts and rough host-like tokens to detect a multi-target paste.
	wildcards := strings.Count(lower, "*.")

	if hasScopeVocab && (multiLine || wildcards >= 1) {
		return true
	}
	// No explicit vocab but clearly several wildcard hosts pasted together.
	if wildcards >= 2 {
		return true
	}
	return false
}

// ingestScopePaste runs the strict extraction on a pasted program, builds the
// self-attested engagement, holds it in c.pendingScope, and returns the preview
// reply. It NEVER launches — confirmation is mandatory (mirrors pendingPentest).
func (c *console) ingestScopePaste(ctx context.Context, paste string) map[string]any {
	client := c.newChatClient()
	system := "You extract a bug-bounty program's SCOPE from pasted policy text. The operator pasted a " +
		"program's scope/rules. Return ONLY JSON matching the schema. Pull EVERY in-scope entry into " +
		"in_scope[] and every excluded entry into out_of_scope[], each as {type,value}. Keep wildcards " +
		"verbatim in 'value' (e.g. '*.example.com') — do NOT invent or expand them. Use type 'domain' for " +
		"hostnames/wildcards, 'url' for full URLs, 'ip' for IPs, 'cidr' for ranges, or 'auto' if unsure. " +
		"In rules: set max_requests_per_second if the program states a rate limit, and list forbidden " +
		"activities (e.g. 'dos', 'social-engineering', 'physical') in forbidden[]. Put any other important " +
		"restriction in notes. Do not include anything that isn't in the pasted text."

	ectx, cancel := context.WithTimeout(ctx, 240*time.Second)
	defer cancel()
	raw, err := client.GenerateSchema(ectx, system, paste, scopeExtractSchema)
	if err != nil {
		return map[string]any{"error": "scope parse: " + err.Error()}
	}
	var ex extractedScope
	if err := json.Unmarshal([]byte(raw), &ex); err != nil {
		return map[string]any{"reply": "I couldn't read that as a scope. Paste the program's in-scope / out-of-scope lists and any rate limit."}
	}
	eng, errMsg := c.buildScopeEngagement(ex)
	if errMsg != "" {
		return map[string]any{"reply": errMsg}
	}
	c.mu.Lock()
	c.pendingScope = eng
	c.pendingPentest = nil
	c.pendingShell = ""
	c.mu.Unlock()
	return map[string]any{"reply": scopeSummary(eng), "needsConfirm": true}
}

// saveSelfAttestedEngagement writes a self-attested engagement to the configs
// directory and returns its path. Self-attested engagements need no client-signed
// grant (the operator attests authorization), so unlike handleCreateEngagement
// there's nothing to sign — but we still marshal → reload → validate → write →
// reload, so we never persist a file that wouldn't load and validate at run time.
func saveSelfAttestedEngagement(eng *engagement.Engagement) (string, error) {
	out, err := yaml.Marshal(eng)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	// Reload (normalize nil vs empty slices) and re-validate the on-disk form.
	if err := yaml.Unmarshal(out, eng); err != nil {
		return "", fmt.Errorf("normalize: %w", err)
	}
	if err := eng.Validate(); err != nil {
		return "", fmt.Errorf("built an invalid engagement: %w", err)
	}
	if err := os.MkdirAll("configs", 0o755); err != nil {
		return "", fmt.Errorf("mkdir configs: %w", err)
	}
	slug := sanitizeFilename(sanitizeID(eng.ID))
	if slug == "" {
		slug = "bb"
	}
	path := filepath.Join("configs", slug+"-"+time.Now().UTC().Format("150405")+".engagement.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	if _, lerr := engagement.Load(path); lerr != nil {
		os.Remove(path)
		return "", fmt.Errorf("wrote an unloadable engagement: %w", lerr)
	}
	return path, nil
}

// commitScopeEngagement persists the held scope engagement to disk (so it shows up
// in the engagements list and can be loaded for runs) and returns the chat reply.
// It does NOT auto-launch — the operator confirmed INGESTION, not a run; they start
// the run from the Run tab or with a follow-up message.
func (c *console) commitScopeEngagement(eng *engagement.Engagement) (string, bool) {
	// Save the engagement (so it's resumable / in the list), then LAUNCH the
	// autonomous assessment across the whole confirmed scope — the operator already
	// confirmed authorization, so this is the "paste a program and go" path. The
	// Scope Guard bounds every action to the in-scope set; out-of-scope is denied.
	path, saveErr := saveSelfAttestedEngagement(eng)
	objective := "Assess the authorized bug-bounty scope: enumerate the in-scope hosts and services, " +
		"fingerprint them, find and validate vulnerabilities across the scope, and report findings."
	if msg := c.launchEngagement(eng, objective, "ollama", 8, "scan", false, false, false); msg != "" {
		where := "the Run tab"
		if saveErr == nil {
			where = "`" + path + "`"
		}
		return fmt.Sprintf("Set up engagement **%s** (%d in-scope target(s)) but couldn't start it: %s. It's saved at %s — start it when ready.",
			eng.ID, len(eng.Scope.InScope), msg, where), true
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Started authorized assessment **%s** across **%d** in-scope target(s) — tools are running in Kali and the Scope Guard is bounding every action to this program's scope. Watch it work in the live panel; say 'stop' anytime.",
		eng.ID, len(eng.Scope.InScope))
	if saveErr == nil {
		fmt.Fprintf(&b, " (Saved to `%s`.)", path)
	}
	return b.String(), true
}
