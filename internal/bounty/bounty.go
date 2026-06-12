// Package bounty is the submission gate: it turns tyto's raw finding stream into
// a payability-tiered, submission-ready projection so the payable-for-an-
// automated-tool classes (subdomain takeover, exposed .git, exposed secrets,
// exposed config, known-CVE template hits) are foregrounded — never lost in a
// "Noise" bucket just because no live verifier re-proved them.
//
// THE PROBLEM THIS FIXES. tyto's report finalize path builds the actionable body
// ONLY from findings a live re-verifier could actively re-prove (StatusConfirmed).
// The high-value bounty classes — a dangling CNAME, a publicly readable /.git, a
// leaked AWS key in a JS bundle — have NO active verifier, so they come back
// "inconclusive" and get dumped into Noise. A successful overnight sweep then
// looks empty. bounty introduces a middle tier, CANDIDATE: high-value, near-
// certain findings that lack an active verifier but are still submission-grade.
// Both VALIDATED and CANDIDATE are actionable; only true NOISE (missing security
// headers, bare version banners, info-only) is held back, never submitted.
//
// PRECISION OVER RECALL. A false positive on a fresh bounty account gets you
// banned, so the CANDIDATE tier is deliberately narrow: a finding only earns it
// when its class is one of the payable classes AND it carries a non-info
// severity (or is an explicitly high-value class like takeover/.git/secret that
// the tool already gates with its own corroboration). The NEVER-submit classes
// (missing-security-header, bare version disclosure, generic info banners) can
// never leave the NOISE tier regardless of how they were produced.
//
// PURITY. Every function here is a pure transform over its inputs — no I/O, no
// clock, no network, no mutation of the input slice. The same inputs always
// produce the same tiers, ranking, dedup and writeups, so the gate is fully
// unit-testable and the audit log can replay it.
package bounty

import (
	"strings"

	"github.com/dukotah/tyto/internal/state"
)

// Tier is the payability classification of a finding (or correlated issue).
type Tier int

const (
	// TierNoise is low-value / never-submit: missing security headers, bare
	// version banners, generic info-only detections. Retained for the audit
	// trail, but NEVER placed in the submit body.
	TierNoise Tier = iota
	// TierCandidate is a high-value, near-certain finding that lacks an active
	// re-verifier (subdomain takeover, exposed .git, exposed secret/key, exposed
	// config, known-CVE template hit). It IS actionable and submission-ready,
	// clearly tagged as a candidate so a triager knows it was not live-re-proved.
	TierCandidate
	// TierValidated is a finding a verifier actively re-proved against the live
	// target right now. The strongest tier; submit-first.
	TierValidated
)

// String renders the tier for reports and tags.
func (t Tier) String() string {
	switch t {
	case TierValidated:
		return "validated"
	case TierCandidate:
		return "candidate"
	default:
		return "noise"
	}
}

// PayClass is the payability family a finding belongs to. It drives ranking
// (takeover/secret/.git outrank CVE, which outrank injection, which outrank the
// rest) and the never-submit decision.
type PayClass int

const (
	// ClassOther is anything not in a recognized payability family.
	ClassOther PayClass = iota
	// --- NEVER-SUBMIT classes (always NOISE) ---------------------------------
	ClassMissingHeader     // missing security headers
	ClassVersionDisclosure // bare version / banner disclosure, info-only
	ClassInfo              // generic informational detection
	// --- PAYABLE classes (CANDIDATE-eligible), highest value first -----------
	ClassSubdomainTakeover // dangling DNS / claimable host
	ClassExposedSecret     // leaked key / token / credential
	ClassExposedGit        // publicly readable .git source disclosure
	ClassExposedConfig     // exposed config / env / backup file
	ClassKnownCVE          // version-matched known CVE / template hit
	ClassInjection         // XSS / SQLi / SSTI / RCE / SSRF
)

// neverSubmit reports whether a class is categorically non-submittable. These
// can never leave the NOISE tier, regardless of severity or how they were
// produced — a missing-header or bare-version finding is informational, full
// stop, and submitting it on a fresh account gets you flagged as a noisy scanner.
func (c PayClass) neverSubmit() bool {
	switch c {
	case ClassMissingHeader, ClassVersionDisclosure, ClassInfo:
		return true
	default:
		return false
	}
}

// payable reports whether a class is one of the high-value families eligible
// for the CANDIDATE tier even without an active re-verifier.
func (c PayClass) payable() bool {
	switch c {
	case ClassSubdomainTakeover, ClassExposedSecret, ClassExposedGit,
		ClassExposedConfig, ClassKnownCVE, ClassInjection:
		return true
	default:
		return false
	}
}

// rank is the payability weight used to order actionable issues (higher first).
// Mirrors the mission priority: takeover/secret/.git > CVE > injection > rest.
func (c PayClass) rank() int {
	switch c {
	case ClassSubdomainTakeover:
		return 100
	case ClassExposedSecret:
		return 95
	case ClassExposedGit:
		return 90
	case ClassExposedConfig:
		return 80
	case ClassKnownCVE:
		return 60
	case ClassInjection:
		return 40
	default:
		return 10
	}
}

// label is a human-readable class name for writeups.
func (c PayClass) label() string {
	switch c {
	case ClassSubdomainTakeover:
		return "Subdomain takeover"
	case ClassExposedSecret:
		return "Exposed secret"
	case ClassExposedGit:
		return "Exposed .git source disclosure"
	case ClassExposedConfig:
		return "Exposed configuration / sensitive file"
	case ClassKnownCVE:
		return "Known CVE (version-matched)"
	case ClassInjection:
		return "Injection"
	case ClassMissingHeader:
		return "Missing security header"
	case ClassVersionDisclosure:
		return "Version disclosure"
	case ClassInfo:
		return "Informational"
	default:
		return "Other"
	}
}

// Classify maps a finding to its payability class using the producing tool and
// the (normalized) title. It is deliberately ordered most-specific first and is
// conservative: a finding only earns a payable class on a strong signal (the
// dedicated tool that produces it, or an unambiguous title phrase), so the
// CANDIDATE tier stays near-zero false positive.
func Classify(f state.Finding) PayClass {
	tool := strings.ToLower(strings.TrimSpace(f.Tool))
	title := normalize(f.Title)

	// NEVER-SUBMIT first: a missing-header / bare-version / info detection is
	// non-submittable even if some other signal would otherwise match.
	if isMissingHeader(title) {
		return ClassMissingHeader
	}
	if isVersionDisclosure(title) {
		return ClassVersionDisclosure
	}

	// NEGATION GUARD: a defensive / negative / "we checked and it's fine" title
	// must NEVER reach a payable (submittable) class — submitting "No XSS found"
	// or "SSRF filter correctly blocks internal IPs" as a candidate is the exact
	// false positive that bans a fresh bounty account. Demote to info/noise.
	if looksNegative(title) {
		return ClassInfo
	}

	// PAYABLE classes — keyed primarily off the dedicated producing tool (the
	// strongest, lowest-FP signal), then corroborated by title phrasing.
	switch tool {
	case "subtakeover":
		// The subtakeover tool only emits a takeover finding when it fingerprinted
		// a claimable provider response; trust its dedicated output.
		if isTakeoverTitle(title) {
			return ClassSubdomainTakeover
		}
	case "dotgit":
		if isGitTitle(title) {
			return ClassExposedGit
		}
	case "secretscan", "jsmine":
		if isSecretTitle(title) {
			return ClassExposedSecret
		}
	case "cvematch", "exploitdb":
		if isCVETitle(title) {
			return ClassKnownCVE
		}
	}

	// Tool-agnostic title signals (a template scanner or generic crawler can also
	// surface these). Order: most-payable class wins.
	switch {
	case isTakeoverTitle(title):
		return ClassSubdomainTakeover
	case isGitTitle(title):
		return ClassExposedGit
	case isSecretTitle(title):
		return ClassExposedSecret
	case isConfigTitle(title):
		return ClassExposedConfig
	case isCVETitle(title):
		return ClassKnownCVE
	case isInjectionTitle(title):
		return ClassInjection
	}

	// Info-severity leftovers with no payable signal are informational.
	if f.Severity == state.SeverityInfo {
		return ClassInfo
	}
	return ClassOther
}

// --- class title heuristics ------------------------------------------------
// Each is a narrow phrase match against the normalized (lower-cased, whitespace-
// collapsed) title. Narrow on purpose: precision over recall.

func isMissingHeader(t string) bool {
	return strings.Contains(t, "missing security header") ||
		strings.Contains(t, "security headers missing") ||
		strings.Contains(t, "missing http security header") ||
		(strings.Contains(t, "missing") && (strings.Contains(t, "content-security-policy") ||
			strings.Contains(t, "x-frame-options") || strings.Contains(t, "strict-transport-security") ||
			strings.Contains(t, "hsts header")))
}

func isVersionDisclosure(t string) bool {
	// Bare banner / version disclosure (info-only). NOT a CVE — those say
	// "CVE-..." or "affects <product> <version>" and are caught by isCVETitle.
	if strings.Contains(t, "cve-") || strings.Contains(t, "affects") {
		return false
	}
	return strings.Contains(t, "version disclosed") ||
		strings.Contains(t, "version disclosure") ||
		strings.Contains(t, "server version") ||
		strings.Contains(t, "banner:") ||
		strings.Contains(t, "banner disclosure") ||
		strings.HasSuffix(t, " banner")
}

func isTakeoverTitle(t string) bool {
	return strings.Contains(t, "takeover") ||
		strings.Contains(t, "dangling cname") ||
		strings.Contains(t, "dangling dns") ||
		strings.Contains(t, "claimable") ||
		strings.Contains(t, "unclaimed") ||
		strings.Contains(t, "can be claimed")
}

func isGitTitle(t string) bool {
	// ".git directory" / "/.git/" are specific; bare "git directory" is NOT (it
	// matches benign prose like "reviewed git directory layout") — dropped.
	return strings.Contains(t, ".git directory") ||
		strings.Contains(t, "exposed .git") ||
		strings.Contains(t, "/.git/") ||
		strings.Contains(t, "git repository exposed") ||
		strings.Contains(t, "source code disclosure")
}

func isSecretTitle(t string) bool {
	return strings.Contains(t, "exposed secret") ||
		strings.Contains(t, "secret in") ||
		strings.Contains(t, "leaked secret") ||
		strings.Contains(t, "api key") ||
		strings.Contains(t, "access key") ||
		strings.Contains(t, "private key") ||
		strings.Contains(t, "hardcoded credential") ||
		strings.Contains(t, "leaked credential") ||
		strings.Contains(t, "aws secret") ||
		strings.Contains(t, "bearer token") ||
		strings.Contains(t, "auth token")
}

func isConfigTitle(t string) bool {
	return strings.Contains(t, ".env file") ||
		strings.Contains(t, "exposed .env") ||
		strings.Contains(t, "exposed config") ||
		strings.Contains(t, "exposed configuration") ||
		strings.Contains(t, "config file exposed") ||
		strings.Contains(t, "environment file") ||
		strings.Contains(t, "backup file exposed") ||
		strings.Contains(t, "database dump") ||
		strings.Contains(t, "wp-config") ||
		strings.Contains(t, "exposed .ds_store") ||
		strings.Contains(t, "exposed credentials file")
}

func isCVETitle(t string) bool {
	// Bare "affects" dropped — it matched benign prose ("affects all users"). A
	// real cvematch title carries the "cve-" id, which is the strong signal.
	return strings.Contains(t, "cve-") ||
		strings.Contains(t, "exploit-db") ||
		strings.Contains(t, "known vulnerability") ||
		strings.Contains(t, "vulnerable version")
}

func isInjectionTitle(t string) bool {
	return strings.Contains(t, "sql injection") ||
		strings.Contains(t, "sqli") ||
		strings.Contains(t, "cross-site scripting") ||
		strings.Contains(t, "xss") ||
		strings.Contains(t, "remote command execution") ||
		strings.Contains(t, "command injection") ||
		strings.Contains(t, "server-side template injection") ||
		strings.Contains(t, "ssti") ||
		strings.Contains(t, "server-side request forgery") ||
		strings.Contains(t, "ssrf")
}

// negativePhrases are defensive / "checked and it's fine" / informational-result
// phrases. A title containing any of them describes the ABSENCE of a bug (or a
// working control), so it must never reach a payable submittable class. Chosen to
// be phrases that appear in benign/negative titles but not in a genuine finding's
// title. Erring toward a false negative here is correct: missing a real bug costs
// nothing; submitting a non-bug gets the account banned.
var negativePhrases = []string{
	"not vulnerable", "not exploitable", "not affected", "not present",
	"no vulnerabilit", "nothing exposed", "no issues", "no such vuln",
	"protection enabled", "protections enabled", "is enabled", "are enabled",
	"tested for", "correctly blocks", "correctly block", "correctly handle",
	"reserved by", "reserved for", "mitigated", "properly configured",
	"securely configured", "hardened", "reviewed", "appears safe", "is safe",
	"no xss", "no sqli", "no ssrf", "no rce", "false positive",
}

// looksNegative reports whether a normalized title describes the absence of a
// vulnerability or a working defense rather than a real, submittable finding.
func looksNegative(t string) bool {
	for _, neg := range negativePhrases {
		if strings.Contains(t, neg) {
			return true
		}
	}
	return false
}

// normalize case-folds and collapses whitespace (same discipline as triage so
// the two stay consistent).
func normalize(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}
