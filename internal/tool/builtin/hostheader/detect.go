package hostheader

import (
	"fmt"
	"net/url"
	"strings"
)

// reflectKind is what a vector's response told us about marker reflection.
type reflectKind int

const (
	reflectNone     reflectKind = iota
	reflectBody                 // marker host in an absolute URL in the body
	reflectLocation             // marker host in the Location redirect header
)

// result is the outcome of classifying one injected response against baseline.
type result struct {
	kind     reflectKind
	evidence string // redacted snippet showing where the marker reflected
}

// repro renders operator-reproducible steps for a confirmed vector.
func (r result) repro(target string, v vector, marker string) string {
	if v.header == "Host" {
		return fmt.Sprintf("curl -s -o /dev/null -D - %q -H %q  (the app reflects the injected Host %q)", target, "Host: "+marker, marker)
	}
	val := marker
	if v.header == "Forwarded" {
		val = "host=" + marker
	}
	return fmt.Sprintf("curl -s -o /dev/null -D - %q -H %q  (the app reflects the injected %s)", target, v.header+": "+val, v.header)
}

// classify applies baseline subtraction. A Location reflection ranks above a
// body reflection (it's the higher-severity, directly-exploitable signal).
// Nothing is flagged if the baseline already contained the marker (we can't
// attribute the reflection to our injection) — caller passes baselineHasMarker.
func classify(baseBody, baseLoc, injBody, injLoc, marker string, baselineHasMarker bool) result {
	if baselineHasMarker {
		return result{kind: reflectNone}
	}
	// Location is the strongest signal: marker absent from baseline Location,
	// present in the injected one.
	if !locationReflectsHost(baseLoc, marker) && locationReflectsHost(injLoc, marker) {
		return result{kind: reflectLocation, evidence: redact("Location: " + injLoc)}
	}
	// Body: marker absent from baseline body, present as an absolute-URL host
	// in the injected body.
	if !bodyReflectsHost(baseBody, marker) && bodyReflectsHost(injBody, marker) {
		return result{kind: reflectBody, evidence: redact(bodySnippet(injBody, marker))}
	}
	return result{kind: reflectNone}
}

// locationReflectsHost reports whether the Location header is an absolute URL
// (or protocol-relative //host) whose host equals the marker. A bare relative
// path never matches, so a legit local redirect can't false-positive.
func locationReflectsHost(loc, marker string) bool {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return false
	}
	return hostEquals(loc, marker)
}

// bodyReflectsHost reports whether ANY absolute URL in the body has the marker
// as its host. This is the security-relevant position: only hosts that the
// browser would actually contact (scheme://MARKER/... or //MARKER/...), not an
// incidental textual mention. We scan for both a scheme-qualified and a
// protocol-relative occurrence and confirm the host component matches exactly.
func bodyReflectsHost(body, marker string) bool {
	for _, cand := range absoluteURLCandidates(body, marker) {
		if hostEquals(cand, marker) {
			return true
		}
	}
	return false
}

// absoluteURLCandidates pulls substrings around each marker occurrence that
// look like absolute-URL prefixes (https://MARKER, http://MARKER, //MARKER),
// so hostEquals can validate the host boundary precisely.
func absoluteURLCandidates(body, marker string) []string {
	var out []string
	for _, prefix := range []string{"https://", "http://", "//"} {
		needle := prefix + marker
		from := 0
		for {
			i := indexFold(body[from:], needle)
			if i < 0 {
				break
			}
			start := from + i
			// Grab the candidate URL up to the next URL-terminating character.
			end := start + len(needle)
			for end < len(body) && !isURLBoundary(body[end]) {
				end++
			}
			out = append(out, body[start:end])
			from = start + len(needle)
		}
	}
	return out
}

// hostEquals parses a candidate absolute URL (scheme:// or //) and reports
// whether its host (sans port) equals marker. Parsing — not substring matching
// — is what stops "tyto-hh-1.example.evil.com" or a path segment from matching.
func hostEquals(candidate, marker string) bool {
	c := strings.TrimSpace(candidate)
	if strings.HasPrefix(c, "//") {
		c = "http:" + c // give url.Parse a scheme so Host populates
	}
	u, err := url.Parse(c)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return strings.EqualFold(h, marker)
}

// bodySnippet returns a short window of the body around the first marker
// occurrence, for human-facing evidence.
func bodySnippet(body, marker string) string {
	i := indexFold(body, marker)
	if i < 0 {
		return ""
	}
	start := i - 40
	if start < 0 {
		start = 0
	}
	end := i + len(marker) + 40
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(body[start:end])
}

// redact collapses whitespace and caps length so evidence stays a tidy,
// bounded snippet rather than a raw page dump.
func redact(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const max = 200
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

func isURLBoundary(b byte) bool {
	switch b {
	case '"', '\'', '<', '>', ' ', '\t', '\r', '\n', ')', '}', '\\':
		return true
	}
	return false
}

// indexFold is a case-insensitive strings.Index.
func indexFold(s, sub string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(sub))
}
