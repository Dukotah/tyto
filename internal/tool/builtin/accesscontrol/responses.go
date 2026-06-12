package accesscontrol

import (
	"regexp"
	"strconv"
	"strings"
)

// verdict is the result of a pure differential check.
type verdict struct {
	flag     bool   // true => emit a finding
	reason   string // human explanation (also used for honest negative notes)
	evidence string // redacted differential evidence for the finding
}

// --- tunables (pure-function thresholds) ---

const (
	// minRealBody is the minimum byte length for a baseline response to count as
	// a "real resource" worth reasoning about (avoids flagging empty/stub pages).
	minRealBody = 64
	// bacSimilarity is the Jaccard-token similarity at/above which the anonymous
	// body is "substantially equivalent" to the authenticated body (BAC flag).
	bacSimilarity = 0.85
	// idorMaxSimilarity is the similarity at/BELOW which a mutated-id body is
	// "materially different" from the baseline (a distinct object, not the same).
	idorMaxSimilarity = 0.70
	// idorMinSimilarity guards against flagging a totally unrelated error page:
	// a real sibling record usually shares structure with the baseline, so we
	// require the mutated body to retain SOME similarity to the baseline object.
	idorMinSimilarity = 0.10
)

// errSigRe matches error / not-found / forbidden / login signatures. A mutated-id
// response that matches is NOT a valid sibling object — it is a refusal — so the
// IDOR check refutes. Kept deliberately broad and case-insensitive.
var errSigRe = regexp.MustCompile(`(?i)(not[\s_-]?found|no such|does not exist|doesn't exist|404|forbidden|403|unauthorized|401|access denied|permission denied|not[\s_-]?authorized|invalid (id|identifier|object|record|request|token)|object not found|record not found|page not found|login|sign[\s_-]?in|please authenticate|session expired)`)

// hasErrorSignature reports whether a body looks like an error / denial / login
// page rather than a real object. Only the leading window is scanned so a long
// legitimate document that merely mentions a word like "login" deep in content
// is not misclassified.
func hasErrorSignature(body string) bool {
	head := body
	if len(head) > 2048 {
		head = head[:2048]
	}
	return errSigRe.MatchString(head)
}

// looksDenied reports whether a status code is an auth/redirect denial (used by
// the BAC check to refute when the anonymous request is blocked).
func looksDenied(status int) bool {
	switch {
	case status == 401, status == 403:
		return true
	case status >= 300 && status < 400: // redirect (typically to a login)
		return true
	default:
		return false
	}
}

// evaluateBAC decides whether an endpoint is accessible without authentication.
// auth is the authenticated baseline; anon is the no-cookie response. It flags
// only when the baseline is a real resource AND the anonymous response is the
// SAME status with a substantially-equivalent body. Refute-by-default.
func evaluateBAC(auth, anon response) verdict {
	if auth.status < 200 || auth.status >= 300 {
		return verdict{reason: "authenticated baseline is not a 2xx resource (status " + strconv.Itoa(auth.status) + "); nothing to compare"}
	}
	if len(strings.TrimSpace(auth.body)) < minRealBody {
		return verdict{reason: "authenticated baseline body is trivially small; not a meaningful protected resource"}
	}
	if looksDenied(anon.status) {
		return verdict{reason: "anonymous request was denied/redirected (status " + strconv.Itoa(anon.status) + "); auth is enforced"}
	}
	if anon.status != auth.status {
		return verdict{reason: "anonymous status (" + strconv.Itoa(anon.status) + ") differs from authenticated (" + strconv.Itoa(auth.status) + "); auth appears enforced"}
	}
	if len(strings.TrimSpace(anon.body)) < minRealBody {
		return verdict{reason: "anonymous body is empty/trivial; not the protected resource"}
	}
	if hasErrorSignature(anon.body) && !hasErrorSignature(auth.body) {
		return verdict{reason: "anonymous body matches an error/login signature; auth appears enforced"}
	}
	sim := similarity(auth.body, anon.body)
	if sim >= bacSimilarity {
		return verdict{
			flag:     true,
			reason:   "anonymous body is " + pct(sim) + " similar to the authenticated body at the same status",
			evidence: "auth status " + strconv.Itoa(auth.status) + " (" + strconv.Itoa(len(auth.body)) + "B) vs anonymous status " + strconv.Itoa(anon.status) + " (" + strconv.Itoa(len(anon.body)) + "B); body similarity " + pct(sim),
		}
	}
	return verdict{reason: "anonymous body only " + pct(sim) + " similar to authenticated body; not equivalent"}
}

// evaluateIDOR decides whether a mutated-id response is a different, valid object
// (IDOR) versus the same object, an error, or a denial. baseline is the
// authenticated original-id response; mut is the mutated-id response.
func evaluateIDOR(baseline, mut response) verdict {
	if mut.status != 200 {
		return verdict{reason: "mutated-id response is not 200 (status " + strconv.Itoa(mut.status) + "); refuted"}
	}
	if len(strings.TrimSpace(mut.body)) < minRealBody {
		return verdict{reason: "mutated-id body is empty/trivial; not a valid object"}
	}
	if hasErrorSignature(mut.body) {
		return verdict{reason: "mutated-id body matches an error/not-found/forbidden signature; refuted"}
	}
	// Require the baseline to itself be a real object so the diff is meaningful.
	if baseline.status != 200 || len(strings.TrimSpace(baseline.body)) < minRealBody {
		return verdict{reason: "baseline object is not a real 200 resource; cannot differentiate"}
	}
	sim := similarity(baseline.body, mut.body)
	if sim > idorMaxSimilarity {
		return verdict{reason: "mutated-id body is " + pct(sim) + " similar to baseline; likely the same object (or no record), not a distinct one"}
	}
	if sim < idorMinSimilarity {
		return verdict{reason: "mutated-id body is only " + pct(sim) + " similar to baseline; too dissimilar to be a sibling record (likely an unrelated page)"}
	}
	return verdict{
		flag:     true,
		reason:   "mutated-id returned a 200 with a body " + pct(sim) + " similar to baseline — a distinct, structurally-similar record",
		evidence: "baseline 200 (" + strconv.Itoa(len(baseline.body)) + "B) vs mutated 200 (" + strconv.Itoa(len(mut.body)) + "B); body similarity " + pct(sim) + " (distinct object)",
	}
}

// --- id detection + mutation ---

var (
	numericRe = regexp.MustCompile(`^\d+$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// idParamNames are conventional object-identifier parameter names. A param with
// one of these names is treated as an id even if we only mutate numeric values.
var idParamNames = map[string]bool{
	"id": true, "user": true, "userid": true, "user_id": true,
	"account": true, "accountid": true, "account_id": true,
	"order": true, "orderid": true, "order_id": true,
	"uid": true, "pid": true, "oid": true, "gid": true,
	"customer": true, "customer_id": true, "doc": true, "docid": true,
	"document": true, "document_id": true, "invoice": true, "invoice_id": true,
	"record": true, "record_id": true, "object": true, "object_id": true,
	"file": true, "fileid": true, "file_id": true,
}

// paginationNames are numeric query parameters that are NOT object identifiers —
// mutating them just pages/filters and would produce a distinct-but-valid 200
// that the IDOR heuristic wrongly flags. They are excluded even if numeric and
// even if they happen to end in "id" (e.g. a hypothetical "gridid" is still not
// an object id here). This is the key false-positive guard for the IDOR check.
var paginationNames = map[string]bool{
	"page": true, "page_size": true, "pagesize": true, "per_page": true,
	"perpage": true, "limit": true, "offset": true, "start": true, "size": true,
	"count": true, "num": true, "number": true, "year": true, "month": true,
	"day": true, "rows": true, "top": true, "skip": true, "page_token": true,
	"from": true, "to": true, "max": true, "min": true, "length": true,
}

// looksLikeIDParam reports whether a parameter name suggests an object id worth
// testing for IDOR. Pagination/filter names are rejected first (they are numeric
// but not identifiers), then conventional id names / *id suffixes are accepted.
func looksLikeIDParam(name string) bool {
	low := strings.ToLower(name)
	if paginationNames[low] {
		return false
	}
	if idParamNames[low] {
		return true
	}
	// generic *_id / *id suffixes
	return strings.HasSuffix(low, "_id") || strings.HasSuffix(low, "id")
}

// mutateID returns up to max nearby identifier values to try for a parameter,
// or nil if the parameter is not a sequential/object identifier worth testing.
// Only NUMERIC identifiers are mutated (high-confidence, sequential). Opaque /
// UUID ids are intentionally left alone (lower confidence — see package doc),
// returning nil so the IDOR check skips them.
func mutateID(name, value string, max int) []string {
	// Gate on the parameter NAME first: only identifier-style params are mutated.
	// A numeric value alone is not enough — page=2 / limit=10 / offset=20 are
	// numeric but not object ids, and mutating them yields IDOR false positives.
	if !looksLikeIDParam(name) {
		return nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	// UUID: opaque, not sequentially enumerable — skip honestly.
	if uuidRe.MatchString(value) {
		return nil
	}
	if numericRe.MatchString(value) {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil
		}
		// Mutate to nearby values: +1, -1, +2, -2 (bounded, sequential).
		deltas := []int64{1, -1, 2, -2}
		out := make([]string, 0, max)
		seen := map[string]bool{value: true}
		for _, d := range deltas {
			if len(out) >= max {
				break
			}
			m := n + d
			if m < 0 {
				continue
			}
			s := strconv.FormatInt(m, 10)
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
		return out
	}
	// Non-numeric, non-UUID value: only treat as an id if the NAME says so, and
	// even then we have no safe sequential mutation, so skip (lower-confidence).
	return nil
}

// --- similarity ---

// similarity returns a token-set Jaccard similarity in [0,1] between two bodies,
// after normalizing whitespace. It is intentionally length/structure aware
// rather than exact-match, so dynamic boilerplate (timestamps, csrf tokens) does
// not defeat the comparison. Two empty bodies are defined as fully similar.
func similarity(a, b string) float64 {
	ta := tokenSet(a)
	tb := tokenSet(b)
	if len(ta) == 0 && len(tb) == 0 {
		return 1
	}
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	inter := 0
	for tok := range ta {
		if tb[tok] {
			inter++
		}
	}
	union := len(ta) + len(tb) - inter
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}

// tokenSet splits a body into a set of whitespace-delimited, lowercased tokens.
var wsRe = regexp.MustCompile(`\s+`)

func tokenSet(s string) map[string]bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return nil
	}
	fields := wsRe.Split(s, -1)
	set := make(map[string]bool, len(fields))
	for _, f := range fields {
		if f != "" {
			set[f] = true
		}
	}
	return set
}

// pct renders a [0,1] ratio as a percentage string.
func pct(r float64) string {
	return strconv.Itoa(int(r*100+0.5)) + "%"
}

// redact trims an identifier value for evidence output (ids are usually short;
// this guards against an unexpectedly long opaque token leaking in full).
func redact(s string) string {
	if len(s) <= 24 {
		return s
	}
	return s[:24] + "...(truncated)"
}
