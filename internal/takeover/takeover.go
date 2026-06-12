// Package takeover is a high-precision subdomain-takeover detection engine.
//
// A subdomain is takeover-prone when its DNS points (via CNAME) at a
// third-party service that no longer claims the name: fetching the host then
// returns a known "unclaimed / not-found" fingerprint served by that provider,
// and an attacker can register the unclaimed resource to serve content on the
// victim's subdomain.
//
// The single design rule here is PRECISION over recall. A false positive on a
// fresh bug-bounty account gets the researcher banned, so every emitted finding
// must be near-certain. The engine therefore DOUBLE-GATES every report:
//
//	(a) the host's CNAME chain must point at a fingerprinted service, AND
//	(b) an HTTP fetch of the host must return that service's exact
//	    unclaimed-fingerprint string (or a service-specific DNS unclaimed
//	    signal, e.g. NXDOMAIN on the CNAME target for providers where that
//	    alone is definitive).
//
// NEVER flag on a CNAME alone: a live, claimed page also carries the CNAME, so
// CNAME-only is the classic false positive. The fingerprint is what proves the
// resource is actually unclaimed. This double gate is the near-zero-FP
// guarantee.
//
// The DNS resolver and HTTP fetcher are injected as interfaces, so the engine
// is fully unit-testable with no network.
package takeover

import (
	"context"
	"errors"
	"strings"
)

// Resolver resolves the CNAME chain and (for providers whose unclaimed signal
// is a dangling target) the A/AAAA records of a host. It is the single DNS seam
// so tests inject a deterministic fake with no network.
//
// LookupCNAME mirrors net.Resolver.LookupCNAME: it returns the canonical name
// the host ultimately resolves to (the final CNAME target), or the host itself
// when there is no CNAME. An error means the lookup failed.
//
// LookupHost mirrors net.Resolver.LookupHost: it returns the resolved
// addresses, or an error. A "no such host" (NXDOMAIN) error is the
// service-specific unclaimed signal for some providers; callers detect it via
// IsNotFound.
type Resolver interface {
	LookupCNAME(ctx context.Context, host string) (cname string, err error)
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
}

// Fetcher performs an HTTP GET and returns the status code and (bounded) body.
// It is the single HTTP seam: production wiring supplies an *http.Client-backed
// implementation (see HTTPFetcher); tests supply a deterministic fake. An error
// means the host was unreachable, which the engine treats as NOT vulnerable
// (refute-by-default — an unreachable host is never reported as a takeover).
type Fetcher interface {
	Fetch(ctx context.Context, host string) (status int, body string, err error)
}

// ErrNotFound is the sentinel a Resolver implementation may return (or wrap)
// from LookupHost to signal NXDOMAIN / "no such host" — the DNS-level unclaimed
// signal for providers that 404 the resource by failing to resolve the CNAME
// target itself. Tests and the net-backed adapter both use it.
var ErrNotFound = errors.New("takeover: no such host")

// IsNotFound reports whether err represents an NXDOMAIN / "no such host"
// condition. It recognizes ErrNotFound (and anything wrapping it) plus the
// common textual signatures the standard net resolver emits, so a net-backed
// adapter that returns a raw *net.DNSError is still understood.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNotFound) {
		return true
	}
	// A net.DNSError implements IsNotFound (Go 1.13+); honor it without
	// importing net here. SERVFAIL/timeout do NOT set it, so we never mistake a
	// transient resolver failure for a definitive NXDOMAIN.
	var nf interface{ IsNotFound() bool }
	if errors.As(err, &nf) {
		return nf.IsNotFound()
	}
	// Fallback for resolvers that only surface a textual error.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such host") || strings.Contains(msg, "nxdomain")
}

// Result is the outcome of checking one host for a subdomain takeover.
type Result struct {
	// Host is the host that was checked (as supplied, lowercased/trimmed).
	Host string
	// Vulnerable is true ONLY when the double gate is satisfied: a fingerprinted
	// CNAME AND the matching unclaimed signal (body fingerprint or DNS signal).
	Vulnerable bool
	// Service is the fingerprinted provider's name (e.g. "GitHub Pages"), set
	// whenever the CNAME matched a provider, even if not ultimately vulnerable.
	Service string
	// CNAME is the resolved CNAME target the host points at (lowercased,
	// trailing dot trimmed), or "" if the host has no CNAME.
	CNAME string
	// Evidence is a compact, human-readable proof string: the matched
	// fingerprint or DNS signal that satisfied gate (b).
	Evidence string
	// Confidence is "high" for a confirmed double-gated takeover; "" otherwise.
	// The engine only ever emits "high" — it does not report low-confidence
	// guesses, by design.
	Confidence string
	// Reason explains the verdict for audit/diagnostics, including WHY a
	// CNAME-matched host was NOT flagged (the critical FP-guard path).
	Reason string
}

// Confidence levels. Only ConfidenceHigh is ever assigned to a Vulnerable=true
// result; the engine refuses to emit anything lower.
const (
	ConfidenceHigh = "high"
)

// maxFingerprintEvidence bounds the evidence substring length.
const maxFingerprintEvidence = 160

// Engine checks hosts for subdomain takeovers using an injected Resolver and
// Fetcher. The zero value is not usable; construct with New.
type Engine struct {
	res Resolver
	fet Fetcher
	db  []Fingerprint
}

// New returns an Engine backed by the given resolver and fetcher and seeded
// with the built-in high-precision fingerprint database.
func New(res Resolver, fet Fetcher) *Engine {
	return &Engine{res: res, fet: fet, db: Fingerprints()}
}

// NewWithDB returns an Engine using a caller-supplied fingerprint database
// (for testing or extension). An empty db means nothing can ever be flagged.
func NewWithDB(res Resolver, fet Fetcher, db []Fingerprint) *Engine {
	return &Engine{res: res, fet: fet, db: db}
}

// Check evaluates a single host and returns its Result. It is refute-by-default:
// it returns Vulnerable=true ONLY when both gates pass. Any DNS/HTTP error, a
// CNAME to a non-fingerprinted host, a missing CNAME, or a fingerprinted CNAME
// whose page does NOT show the unclaimed signal all yield Vulnerable=false with
// a Reason explaining the verdict.
//
// The injected resolver/fetcher are used when the Engine's own ones are nil,
// allowing a stateless call site to pass per-call dependencies; normally New
// supplies them and the arguments are nil.
func (e *Engine) Check(ctx context.Context, host string, res Resolver, fet Fetcher) Result {
	if res == nil {
		res = e.res
	}
	if fet == nil {
		fet = e.fet
	}
	host = normalizeHost(host)
	r := Result{Host: host}
	if host == "" {
		r.Reason = "empty host"
		return r
	}
	if res == nil || fet == nil {
		r.Reason = "no resolver/fetcher configured"
		return r
	}

	// --- Gate (a): resolve the CNAME chain and match a fingerprinted service.
	cname := ""
	if c, err := res.LookupCNAME(ctx, host); err == nil {
		cname = normalizeHost(c)
		// net.Resolver.LookupCNAME returns the host itself when there is no
		// CNAME; treat that as "no CNAME".
		if cname == host {
			cname = ""
		}
	}
	r.CNAME = cname
	if cname == "" {
		r.Reason = "host has no CNAME; a takeover requires a dangling CNAME to a third-party service"
		return r
	}

	fp, ok := e.matchCNAME(cname)
	if !ok {
		r.Reason = "CNAME points at " + cname + ", which is not a fingerprinted takeover-able service"
		return r
	}
	r.Service = fp.Service

	// --- Gate (b): independently confirm the resource is UNCLAIMED.
	//
	// Two acceptable unclaimed signals, in order of strength:
	//   1. DNS signal: for providers where the CNAME target itself NXDOMAINs
	//      when unclaimed, an NXDOMAIN on the CNAME target is definitive and we
	//      need no HTTP body. (Only honored when the fingerprint opts in.)
	//   2. HTTP body fingerprint: the fetched page contains the provider's exact
	//      unclaimed-fingerprint string. This is the primary, general gate.
	//
	// We require ONE of these. A fingerprinted CNAME with NEITHER signal is the
	// FP-guard path: a live, claimed page — explicitly NOT flagged.

	if fp.NXDomainUnclaimed {
		if _, err := res.LookupHost(ctx, cname); err != nil && IsNotFound(err) {
			r.Vulnerable = true
			r.Confidence = ConfidenceHigh
			r.Evidence = "CNAME target " + cname + " does not resolve (NXDOMAIN): the " + fp.Service + " resource is unclaimed"
			r.Reason = "double gate satisfied: fingerprinted CNAME (" + cname + ") + DNS unclaimed signal (NXDOMAIN on target)"
			return r
		}
	}

	status, body, err := fet.Fetch(ctx, host)
	if err != nil {
		r.Reason = "CNAME matches " + fp.Service + " (" + cname + ") but the host is unreachable over HTTP; cannot confirm the unclaimed fingerprint (not flagged)"
		return r
	}

	if matched, ok := fp.matchBody(body, status); ok {
		r.Vulnerable = true
		r.Confidence = ConfidenceHigh
		r.Evidence = fp.Service + " unclaimed fingerprint: " + truncate(matched, maxFingerprintEvidence)
		r.Reason = "double gate satisfied: fingerprinted CNAME (" + cname + ") + unclaimed HTTP fingerprint"
		return r
	}

	r.Reason = "CNAME matches " + fp.Service + " (" + cname + ") but the page does NOT show the unclaimed fingerprint; the resource appears CLAIMED (not flagged)"
	return r
}

// CheckAll evaluates every host and returns one Result per host, in order. It is
// the breadth-first sweep entry point. Hosts are checked sequentially here;
// callers that want concurrency can shard the slice and call Check directly.
func (e *Engine) CheckAll(ctx context.Context, hosts []string) []Result {
	out := make([]Result, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, e.Check(ctx, h, nil, nil))
	}
	return out
}

// Vulnerable filters results to only the confirmed, double-gated takeovers.
func Vulnerable(results []Result) []Result {
	var out []Result
	for _, r := range results {
		if r.Vulnerable {
			out = append(out, r)
		}
	}
	return out
}

// matchCNAME returns the fingerprint whose CNAME suffixes the given (normalized)
// CNAME target falls under, and whether one matched.
func (e *Engine) matchCNAME(cname string) (Fingerprint, bool) {
	for _, fp := range e.db {
		if fp.matchCNAME(cname) {
			return fp, true
		}
	}
	return Fingerprint{}, false
}

// normalizeHost lowercases, trims whitespace, strips any scheme/path/port, and
// removes a trailing dot, yielding a bare hostname suitable for DNS lookups and
// suffix matching.
func normalizeHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// strip [ipv6] brackets / :port — we only need the host label here.
	s = strings.TrimPrefix(s, "[")
	if i := strings.Index(s, "]"); i >= 0 {
		s = s[:i]
	} else if i := strings.LastIndex(s, ":"); i >= 0 {
		// only strip a trailing :port (numeric-ish); leave bare hosts alone.
		if isPortSuffix(s[i+1:]) {
			s = s[:i]
		}
	}
	return strings.TrimSuffix(strings.TrimSpace(s), ".")
}

// isPortSuffix reports whether s is a non-empty all-digit port.
func isPortSuffix(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// truncate shortens s to at most n bytes, appending an ellipsis if cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
