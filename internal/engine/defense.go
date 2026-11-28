package engine

import (
	"regexp"
	"strings"

	"github.com/dukotah/tyto/internal/state"
)

// classifyDefense decides whether a tool result shows the target's defenses
// reacting, and names the phrase that says so.
//
// This is deliberately STRICTER than the noise governor's troubleSignal. The
// governor may over-match freely (a false positive only slows the run down); a
// defensive-control observation is printed in the client's report, so it must
// not be raised by a bare "429" inside a port list or by a refused connection to
// a closed port. Only explicit status phrasing and unambiguous messages count,
// and timeouts / refused connections — which a dead service produces just as
// readily as a firewall — are never reported as a control.
func classifyDefense(output, errText string) (kind, signal string) {
	hay := strings.ToLower(output + "\n" + errText)
	for _, s := range []string{"too many requests", "rate limit", "rate-limit", "ratelimit", "retry-after"} {
		if strings.Contains(hay, s) {
			return state.DefenseRateLimit, s
		}
	}
	if m := status429.FindString(hay); m != "" {
		return state.DefenseRateLimit, strings.TrimSpace(m)
	}
	for _, s := range []string{"connection reset", "reset by peer", "econnreset"} {
		if strings.Contains(hay, s) {
			return state.DefenseConnReset, s
		}
	}
	if strings.Contains(hay, "service unavailable") {
		return state.DefenseUnavailable, "service unavailable"
	}
	if m := status503.FindString(hay); m != "" {
		return state.DefenseUnavailable, strings.TrimSpace(m)
	}
	return "", ""
}

// A status code only counts when it is introduced as one ("HTTP/1.1 429",
// "status 429", "code: 503", "-> 429"), never as a bare number.
var (
	status429 = regexp.MustCompile(`(?:http/\d(?:\.\d)?|status(?:[ _-]?code)?|code|response|returned|->|=>)[ :=]*429\b`)
	status503 = regexp.MustCompile(`(?:http/\d(?:\.\d)?|status(?:[ _-]?code)?|code|response|returned|->|=>)[ :=]*503\b`)
)
