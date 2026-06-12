package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/engagement"
)

// engageReq is the structured "New Assessment" form the console panel posts: an
// explicit, deliberate authorization act that REPLACES the chat's inferred
// re-confirm dance. The operator types the scope, picks a mode, and ticks the
// self-attestation box — that IS the verified authorization, recorded to the
// audit log and enforced by the Scope Guard. No chat back-and-forth required.
type engageReq struct {
	Scope    string `json:"scope"`    // newline/comma-separated targets / wildcards
	Depth    string `json:"depth"`    // recon | scan | full
	Hunt     bool   `json:"hunt"`     // true = deterministic no-LLM payable-class sweep
	Attested bool   `json:"attested"` // operator attests authorization (required)
}

// handleEngage builds a self-attested engagement from the panel form, records the
// scope as authorized for the session (so chat never re-confirms an in-scope
// target), and launches the run — a guarded model-driven assessment, or the fast
// deterministic hunt sweep.
func (c *console) handleEngage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req engageReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"error": "bad request: " + err.Error()})
		return
	}
	if !req.Attested {
		writeJSON(w, map[string]any{"error": "authorization required: tick the attestation box to confirm you're authorized to test these targets"})
		return
	}
	targets := splitScope(req.Scope)
	if len(targets) == 0 {
		writeJSON(w, map[string]any{"error": "no targets — enter at least one domain, host, CIDR, or URL in scope"})
		return
	}

	depth := req.Depth
	if req.Hunt {
		depth = "scan" // the hunt battery is recon/scan-tier; profile gives it the categories
	}
	eng, errMsg := c.buildScopedEngagement(targets, depth)
	if errMsg != "" {
		writeJSON(w, map[string]any{"error": errMsg})
		return
	}

	// The form IS the attestation: remember every in-scope target (and its parent
	// domain) so the chat confirm gate never fires for them this session.
	for _, t := range targets {
		c.rememberAuthorized(t)
	}

	mode := "guarded " + depth + " assessment"
	if req.Hunt {
		mode = "deterministic payable-class hunt sweep"
	}
	if msg := c.launchEngagement(eng, "", "ollama", huntCycles(req.Hunt), depth, false, false, req.Hunt); msg != "" {
		writeJSON(w, map[string]any{"error": msg})
		return
	}
	writeJSON(w, map[string]any{
		"started": true,
		"reply":   "Launched a " + mode + " over " + strings.Join(targets, ", ") + ". Watch it stream live.",
	})
}

func huntCycles(hunt bool) int {
	if hunt {
		return 200 // the sweep self-terminates; give it room to cover the scope
	}
	return 8
}

// splitScope parses a free-form scope blob (newlines / commas / spaces) into a
// deduped target list.
func splitScope(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' || r == ';'
	})
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// buildScopedEngagement constructs an in-memory, validated, self-attested
// engagement covering every supplied target at the given depth. Mirrors
// buildAdHocEngagement but for the multi-target panel.
func (c *console) buildScopedEngagement(targets []string, depth string) (*engagement.Engagement, string) {
	allowed, maxRisk, norm := profileFor(depth)
	var inScope []engagement.Target
	for _, t := range targets {
		ttype, ok := detectTargetType("auto", t)
		if !ok {
			return nil, "I couldn't tell what kind of target " + t + " is (expected an IP, CIDR, domain, or URL)."
		}
		inScope = append(inScope, engagement.Target{Type: ttype, Value: t})
	}
	label := targets[0]
	if len(targets) > 1 {
		label = targets[0] + "+" + itoaSmall(len(targets)-1)
	}
	eng := &engagement.Engagement{
		ID:          "adhoc-" + sanitizeID(label) + "-" + time.Now().UTC().Format("150405"),
		Client:      "ad-hoc (operator-authorized via console)",
		Description: "Console " + norm + " assessment over " + itoaSmall(len(targets)) + " in-scope target(s).",
		Authorization: engagement.Authorization{
			Mode:         "self-attested",
			AuthorizedBy: "operator (tyto console)",
			AuthorizedOn: time.Now().UTC().Format("2006-01-02"),
			AgreementRef: "operator-asserted authorization via console engagement panel",
		},
		Scope: engagement.Scope{InScope: inScope},
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

// itoaSmall renders a small non-negative int without importing strconv here.
func itoaSmall(n int) string {
	if n <= 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
