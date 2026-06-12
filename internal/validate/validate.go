// Package validate is tyto's adversarial validation brain: a refute-by-default
// gate that re-proves findings before they reach the report body.
//
// The discipline is simple and deliberately pessimistic. A scanner produced a
// finding; this package does NOT trust it. It re-runs a class-specific,
// active re-verification against the live target through an injected Fetcher
// (so it is fully testable with no network), and the finding is allowed to
// remain "confirmed" ONLY if the re-verifier can independently re-observe the
// condition right now. Anything it cannot actively re-prove is downgraded:
//   - a verifier ran but the condition is absent / looks like a false positive
//     -> StatusRefuted
//   - no verifier knows how to re-prove this class, or the re-proof was
//     inconclusive (e.g. the target was unreachable) -> StatusInconclusive
//
// Nothing stays confirmed by default. The caller (the report finalize path)
// uses Verdict.Confirmed() to decide what enters the main report body.
//
// Where a benign baseline is meaningful (reflected XSS, error-based SQLi) the
// re-verifier subtracts a benign-baseline fetch: it first confirms the marker
// / error signature is NOT already present in an un-injected response, so a
// static page that merely echoes a fixed string can never be mistaken for an
// active reflection or a real DB error.
package validate

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/state"
)

// Status is the outcome of adversarially re-verifying a single finding.
type Status string

const (
	// StatusConfirmed means a class re-verifier actively re-observed the
	// condition against the live target. Only these reach the report body.
	StatusConfirmed Status = "confirmed"
	// StatusRefuted means a re-verifier ran and the condition is absent / looks
	// like a false positive (e.g. a marker that is not actually reflected, a
	// header that is now present, a placeholder secret).
	StatusRefuted Status = "refuted"
	// StatusInconclusive means the finding could not be actively re-proved:
	// either no verifier handles this class, or the re-proof attempt itself was
	// indeterminate (target unreachable, transport error). Treated as
	// NOT-confirmed — it never enters the report body.
	StatusInconclusive Status = "inconclusive"
)

// Class identifies the vulnerability class a finding belongs to, which selects
// the re-verifier. Findings that match no known class are inconclusive.
type Class string

const (
	ClassReflectedXSS   Class = "reflected-xss"
	ClassErrorSQLi      Class = "error-sqli"
	ClassMissingHeader  Class = "missing-security-header"
	ClassExposedSecret  Class = "exposed-secret"
	ClassUnknown        Class = "unknown"
)

// Response is the minimal view of an HTTP response the re-verifiers need. It
// deliberately avoids *http.Response so a fake Fetcher is trivial to build in
// tests with no network and no live server.
type Response struct {
	Status  int
	Header  http.Header
	Body    string
}

// Fetcher performs an HTTP GET against rawURL and returns the response. It is
// the single seam between the validation brain and the network: production
// wiring supplies an *http.Client-backed implementation (see HTTPFetcher);
// tests supply a deterministic fake. An error means the target was
// unreachable, which the re-verifiers treat as inconclusive (never confirmed).
type Fetcher interface {
	Fetch(ctx context.Context, rawURL string) (Response, error)
}

// Verdict is the result of re-verifying one finding: the original finding, the
// adversarial Status, and a human-readable reason explaining the decision.
type Verdict struct {
	Finding state.Finding
	Class   Class
	Status  Status
	// Reason explains the decision (e.g. "marker reflected unencoded on
	// re-fetch", "marker absent from baseline and injected response").
	Reason string
	// Evidence is fresh, re-verification-time evidence (the live proof), kept
	// separate from the original scanner Evidence so the report can show the
	// adversarial re-proof, not just the original claim.
	Evidence string
}

// Confirmed reports whether the finding actively re-proved and may enter the
// main report body. Refute-by-default: only StatusConfirmed returns true.
func (v Verdict) Confirmed() bool { return v.Status == StatusConfirmed }

// Validator is the adversarial validation brain. It holds the injected Fetcher
// and the ordered set of class re-verifiers.
type Validator struct {
	fetch     Fetcher
	verifiers []verifier
}

// verifier is one class re-verifier: it claims findings it recognizes and
// actively re-proves them through the Fetcher.
type verifier interface {
	// class returns the class this verifier handles (for diagnostics).
	class() Class
	// handles reports whether this verifier recognizes the finding.
	handles(f state.Finding) bool
	// verify actively re-proves the finding and returns a Verdict. It must be
	// refute-by-default: it returns StatusConfirmed ONLY on a live re-proof.
	verify(ctx context.Context, fetch Fetcher, f state.Finding) Verdict
}

// New returns a Validator wired with the built-in per-class re-verifiers
// (reflected XSS, error-based SQLi, missing security header, exposed secret).
// The Fetcher is injected so the same brain runs against a live client or a
// deterministic test fake.
func New(fetch Fetcher) *Validator {
	return &Validator{
		fetch: fetch,
		verifiers: []verifier{
			reflectedXSSVerifier{},
			errorSQLiVerifier{},
			missingHeaderVerifier{},
			exposedSecretVerifier{},
		},
	}
}

// Validate re-verifies a single finding. Refute-by-default: if no verifier
// handles the finding's class, the verdict is StatusInconclusive.
func (v *Validator) Validate(ctx context.Context, f state.Finding) Verdict {
	for _, ver := range v.verifiers {
		if ver.handles(f) {
			return ver.verify(ctx, v.fetch, f)
		}
	}
	return Verdict{
		Finding: f,
		Class:   ClassUnknown,
		Status:  StatusInconclusive,
		Reason:  "no re-verifier handles this finding class; cannot actively re-prove",
	}
}

// ValidateAll re-verifies every finding and returns one Verdict per finding,
// in the same order. It is the entry point the report finalize path calls.
func (v *Validator) ValidateAll(ctx context.Context, findings []state.Finding) []Verdict {
	out := make([]Verdict, 0, len(findings))
	for _, f := range findings {
		out = append(out, v.Validate(ctx, f))
	}
	return out
}

// Confirmed returns only the findings that actively re-proved, with their
// Validated flag forced true and their Evidence augmented with the live
// re-proof. This is the slice the report body should be built from.
func Confirmed(verdicts []Verdict) []state.Finding {
	var out []state.Finding
	for _, vd := range verdicts {
		if !vd.Confirmed() {
			continue
		}
		f := vd.Finding
		f.Validated = true
		if vd.Evidence != "" {
			if f.Evidence != "" {
				f.Evidence += " | "
			}
			f.Evidence += "re-verified: " + vd.Evidence
		}
		out = append(out, f)
	}
	return out
}

// Partition splits verdicts into confirmed / refuted / inconclusive buckets,
// so a finalize path can report (and audit) what was set aside, not silently
// drop it.
func Partition(verdicts []Verdict) (confirmed, refuted, inconclusive []Verdict) {
	for _, vd := range verdicts {
		switch vd.Status {
		case StatusConfirmed:
			confirmed = append(confirmed, vd)
		case StatusRefuted:
			refuted = append(refuted, vd)
		default:
			inconclusive = append(inconclusive, vd)
		}
	}
	return
}

// Classify reports the class a finding belongs to (the same logic the
// re-verifiers use), exposed for diagnostics/wiring.
func Classify(f state.Finding) Class {
	for _, ver := range []verifier{
		reflectedXSSVerifier{},
		errorSQLiVerifier{},
		missingHeaderVerifier{},
		exposedSecretVerifier{},
	} {
		if ver.handles(f) {
			return ver.class()
		}
	}
	return ClassUnknown
}

// ---- shared helpers -------------------------------------------------------

// targetURL returns the URL to re-fetch for a finding: its Target if it already
// looks like a URL, else the bare host upgraded to http:// for the re-fetch.
func targetURL(f state.Finding) string {
	t := strings.TrimSpace(f.Target)
	if t == "" {
		return ""
	}
	if strings.Contains(t, "://") {
		return t
	}
	// bare host[:port] — assume http for re-fetch; the Fetcher may upgrade.
	return "http://" + t
}

// containsFold reports a case-insensitive substring match.
func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// dedupeSorted returns sorted unique non-empty strings (deterministic output).
func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// defaultTimeout bounds a single re-verification fetch when the caller did not
// supply a deadline. Production wiring should pass a context with a deadline.
const defaultTimeout = 8 * time.Second
