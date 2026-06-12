package validate

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/takeover"
)

// ---- subdomain takeover ---------------------------------------------------

// subTakeoverVerifier re-proves a subdomain-takeover finding through the shared,
// double-gated takeover engine: it confirms ONLY when the host's CNAME resolves
// under a fingerprinted provider AND an independent unclaimed signal holds (the
// verbatim unclaimed-page string, or a definitive NXDOMAIN on the CNAME target).
// A claimed page, or a host that no longer dangles, is refuted — so a stale or
// already-fixed takeover candidate never reaches the submit body.
type subTakeoverVerifier struct{ eng *takeover.Engine }

func newSubTakeoverVerifier() subTakeoverVerifier {
	return subTakeoverVerifier{eng: takeover.New(takeover.NewNetResolver(), takeover.NewHTTPFetcher())}
}

func (subTakeoverVerifier) class() Class { return ClassSubdomainTakeover }

func (subTakeoverVerifier) handles(f state.Finding) bool {
	return containsFold(f.Title, "subdomain takeover") || containsFold(f.Title, "subdomain-takeover") ||
		(containsFold(f.Title, "takeover") && containsFold(f.Title+" "+f.Description, "subdomain"))
}

func (v subTakeoverVerifier) verify(ctx context.Context, _ Fetcher, f state.Finding) Verdict {
	eng := v.eng
	if eng == nil {
		eng = takeover.New(takeover.NewNetResolver(), takeover.NewHTTPFetcher())
	}
	vd := Verdict{Finding: f, Class: ClassSubdomainTakeover}
	if strings.TrimSpace(f.Target) == "" {
		vd.Status = StatusInconclusive
		vd.Reason = "finding has no target host to re-resolve"
		return vd
	}
	r := eng.Check(ctx, f.Target, nil, nil)
	if r.Vulnerable {
		vd.Status = StatusConfirmed
		vd.Reason = r.Reason
		vd.Evidence = r.Service + ": " + r.Evidence
		return vd
	}
	vd.Status = StatusRefuted
	vd.Reason = r.Reason
	return vd
}

// ---- reflected XSS --------------------------------------------------------

// reflectedXSSVerifier re-proves a reflected-XSS finding by injecting a fresh,
// distinctive marker into each query parameter and confirming it comes back
// VERBATIM (unencoded). It subtracts a benign baseline: the marker must be
// absent from an un-injected fetch first, so a static page that echoes a fixed
// string is never confirmed.
type reflectedXSSVerifier struct{}

func (reflectedXSSVerifier) class() Class { return ClassReflectedXSS }

func (reflectedXSSVerifier) handles(f state.Finding) bool {
	if containsFold(f.Title, "reflected xss") || containsFold(f.Title, "reflected-xss") {
		return true
	}
	// Cross-site scripting titles that are clearly reflection-based.
	return (containsFold(f.Title, "cross-site scripting") || containsFold(f.Title, "xss")) &&
		containsFold(f.Description+" "+f.Title, "reflect")
}

// xssMarker is a benign, distinctive marker. It carries an HTML-significant
// payload so that a verbatim reflection proves the value is NOT being encoded.
const xssMarker = `tyto-xssvfy-9f3a"><svg/onload=alert(1)>`

func (v reflectedXSSVerifier) verify(ctx context.Context, fetch Fetcher, f state.Finding) Verdict {
	vd := Verdict{Finding: f, Class: ClassReflectedXSS}
	raw := targetURL(f)
	if raw == "" {
		vd.Status = StatusInconclusive
		vd.Reason = "finding has no target URL to re-fetch"
		return vd
	}
	base, err := url.Parse(raw)
	if err != nil {
		vd.Status = StatusInconclusive
		vd.Reason = "target is not a parseable URL: " + err.Error()
		return vd
	}
	params := paramNames(base)
	if len(params) == 0 {
		vd.Status = StatusInconclusive
		vd.Reason = "no query parameters on the target to inject the XSS marker into"
		return vd
	}

	// Benign baseline: fetch the un-injected URL. If the marker is somehow
	// already present (it never should be — it is unique), or the page is
	// unreachable, we cannot cleanly attribute reflection.
	baseResp, err := fetch.Fetch(ctx, base.String())
	if err != nil {
		vd.Status = StatusInconclusive
		vd.Reason = "baseline fetch failed (target unreachable): " + err.Error()
		return vd
	}
	if strings.Contains(baseResp.Body, xssMarker) {
		vd.Status = StatusRefuted
		vd.Reason = "unique XSS marker present in the un-injected baseline; reflection cannot be attributed to the parameter"
		return vd
	}

	for _, name := range params {
		u := withParam(base, name, xssMarker)
		resp, err := fetch.Fetch(ctx, u)
		if err != nil {
			continue // try the next parameter; a single failure is not a refute
		}
		// Baseline subtraction: confirm only when the marker appears VERBATIM in
		// the injected response (unencoded). An HTML-encoded echo (&lt;svg...)
		// would not contain the literal marker, so it is correctly NOT confirmed.
		if strings.Contains(resp.Body, xssMarker) {
			vd.Status = StatusConfirmed
			vd.Reason = "XSS marker reflected unencoded in parameter " + name + " (absent from baseline)"
			vd.Evidence = "param " + name + " reflected marker verbatim at " + u
			return vd
		}
	}

	vd.Status = StatusRefuted
	vd.Reason = "XSS marker was not reflected unencoded in any parameter on re-fetch (no active reflection)"
	return vd
}

// ---- error-based SQLi -----------------------------------------------------

// errorSQLiVerifier re-proves an error-based SQLi finding by injecting a single
// quote into each query parameter and confirming a DB error signature appears
// that was NOT present in the benign baseline response.
type errorSQLiVerifier struct{}

func (errorSQLiVerifier) class() Class { return ClassErrorSQLi }

func (errorSQLiVerifier) handles(f state.Finding) bool {
	t := strings.ToLower(f.Title)
	if !strings.Contains(t, "sql") {
		return false
	}
	// Specifically error-based; boolean/blind SQLi is a different re-proof.
	return strings.Contains(t, "error-based") || strings.Contains(t, "error based") ||
		(strings.Contains(t, "sql injection") && !strings.Contains(t, "boolean") && !strings.Contains(t, "blind"))
}

// sqlErrRe matches common DB error signatures (same family webinject uses).
var sqlErrRe = regexp.MustCompile(`(?i)(SQL syntax|mysql_fetch|valid MySQL result|mysqli?_|ORA-\d{5}|PostgreSQL.{0,40}ERROR|SQLite3?::|sqlite_error|Unclosed quotation mark|quoted string not properly terminated|Microsoft OLE DB|ODBC SQL Server|System\.Data\.SQLite|Warning: pg_|supplied argument is not a valid)`)

func (v errorSQLiVerifier) verify(ctx context.Context, fetch Fetcher, f state.Finding) Verdict {
	vd := Verdict{Finding: f, Class: ClassErrorSQLi}
	raw := targetURL(f)
	if raw == "" {
		vd.Status = StatusInconclusive
		vd.Reason = "finding has no target URL to re-fetch"
		return vd
	}
	base, err := url.Parse(raw)
	if err != nil {
		vd.Status = StatusInconclusive
		vd.Reason = "target is not a parseable URL: " + err.Error()
		return vd
	}
	params := paramNames(base)
	if len(params) == 0 {
		vd.Status = StatusInconclusive
		vd.Reason = "no query parameters on the target to inject the quote into"
		return vd
	}

	baseResp, err := fetch.Fetch(ctx, base.String())
	if err != nil {
		vd.Status = StatusInconclusive
		vd.Reason = "baseline fetch failed (target unreachable): " + err.Error()
		return vd
	}
	// Benign-baseline subtraction: if the page ALREADY shows a DB error without
	// any injection, the error is not attributable to our quote — refute to
	// avoid the classic false positive of an always-broken page.
	if m := sqlErrRe.FindString(baseResp.Body); m != "" {
		vd.Status = StatusRefuted
		vd.Reason = "a DB error signature is present in the un-injected baseline (always-erroring page); not attributable to injection"
		return vd
	}

	for _, name := range params {
		orig := base.Query().Get(name)
		u := withParam(base, name, orig+"'")
		resp, err := fetch.Fetch(ctx, u)
		if err != nil {
			continue
		}
		if m := sqlErrRe.FindString(resp.Body); m != "" {
			vd.Status = StatusConfirmed
			vd.Reason = "injecting a quote into parameter " + name + " surfaced a DB error absent from baseline"
			vd.Evidence = "db error signature on inject: " + m + " (" + u + ")"
			return vd
		}
	}

	vd.Status = StatusRefuted
	vd.Reason = "injecting a quote produced no DB error in any parameter on re-fetch (no error-based SQLi)"
	return vd
}

// ---- missing security header ----------------------------------------------

// missingHeaderVerifier re-proves a missing-security-header finding by
// re-fetching the target and confirming the named header is STILL absent. If
// the header is present on re-fetch, the finding flips to refuted (the gap was
// closed, or the original scan was wrong).
type missingHeaderVerifier struct{}

func (missingHeaderVerifier) class() Class { return ClassMissingHeader }

func (missingHeaderVerifier) handles(f state.Finding) bool {
	t := strings.ToLower(f.Title + " " + f.Description)
	if !strings.Contains(t, "header") {
		return false
	}
	return strings.Contains(t, "missing") || strings.Contains(t, "absent") || strings.Contains(t, "not set") || strings.Contains(t, "no ")
}

// knownHeaders maps a recognizable name fragment to the canonical HTTP header.
// The fragment is matched case-insensitively against the finding's title /
// description / evidence so we can recover which header the scanner flagged.
var knownHeaders = []struct {
	frag      string
	canonical string
}{
	{"content-security-policy", "Content-Security-Policy"},
	{"content security policy", "Content-Security-Policy"},
	{"csp", "Content-Security-Policy"},
	{"strict-transport-security", "Strict-Transport-Security"},
	{"hsts", "Strict-Transport-Security"},
	{"x-frame-options", "X-Frame-Options"},
	{"frame-ancestors", "Content-Security-Policy"},
	{"x-content-type-options", "X-Content-Type-Options"},
	{"nosniff", "X-Content-Type-Options"},
	{"referrer-policy", "Referrer-Policy"},
	{"permissions-policy", "Permissions-Policy"},
	{"x-xss-protection", "X-XSS-Protection"},
}

// headerForFinding extracts the canonical header name the finding is about.
func headerForFinding(f state.Finding) string {
	hay := strings.ToLower(f.Title + " " + f.Description + " " + f.Evidence)
	for _, kh := range knownHeaders {
		if strings.Contains(hay, kh.frag) {
			return kh.canonical
		}
	}
	return ""
}

func (v missingHeaderVerifier) verify(ctx context.Context, fetch Fetcher, f state.Finding) Verdict {
	vd := Verdict{Finding: f, Class: ClassMissingHeader}
	header := headerForFinding(f)
	if header == "" {
		vd.Status = StatusInconclusive
		vd.Reason = "could not determine which security header the finding refers to"
		return vd
	}
	raw := targetURL(f)
	if raw == "" {
		vd.Status = StatusInconclusive
		vd.Reason = "finding has no target URL to re-fetch"
		return vd
	}
	resp, err := fetch.Fetch(ctx, raw)
	if err != nil {
		vd.Status = StatusInconclusive
		vd.Reason = "re-fetch failed (target unreachable): " + err.Error()
		return vd
	}
	if resp.Header != nil && strings.TrimSpace(resp.Header.Get(header)) != "" {
		// The header is present on re-fetch -> the "missing header" claim is no
		// longer true. Refute.
		vd.Status = StatusRefuted
		vd.Reason = header + " is present on re-fetch; the header is not missing"
		vd.Evidence = header + ": " + resp.Header.Get(header)
		return vd
	}
	vd.Status = StatusConfirmed
	vd.Reason = header + " is still absent on re-fetch; the security header is genuinely missing"
	vd.Evidence = "re-fetched " + raw + "; no " + header + " response header present"
	return vd
}

// ---- exposed secret -------------------------------------------------------

// exposedSecretVerifier re-proves an exposed-secret finding by re-fetching the
// source and confirming a high-entropy / well-formed secret is STILL present
// and is NOT a redacted placeholder. A placeholder / redacted / example value
// is refuted to avoid the common false positive of flagging documentation.
type exposedSecretVerifier struct{}

func (exposedSecretVerifier) class() Class { return ClassExposedSecret }

func (exposedSecretVerifier) handles(f state.Finding) bool {
	t := strings.ToLower(f.Title)
	return strings.Contains(t, "secret") || strings.Contains(t, "api key") ||
		strings.Contains(t, "access key") || strings.Contains(t, "token") ||
		strings.Contains(t, "credential") || strings.Contains(t, "private key")
}

// secretRes are well-formed secret shapes. A confirmed secret must match one of
// these in the live re-fetch AND not be a placeholder.
var secretRes = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                                 // AWS access key id
	regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),                                           // Google API key
	regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`),                                    // Slack token
	regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`),                                       // GitHub token
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),                               // private key block
	regexp.MustCompile(`sk_live_[0-9A-Za-z]{16,}`),                                         // Stripe live secret
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`), // JWT
}

// placeholderRe matches values that are redacted / example / template
// placeholders rather than real leaked secrets.
var placeholderRe = regexp.MustCompile(`(?i)(\*{3,}|x{6,}|redact|REDACTED|placeholder|example|sample|dummy|your[_-]?(api[_-]?)?key|<[^>]*>|\bchangeme\b|\bxxxx+\b|0{8,}|insert[_-]?secret|TODO)`)

// looksRedacted reports whether a candidate secret string is a placeholder.
func looksRedacted(s string) bool {
	if placeholderRe.MatchString(s) {
		return true
	}
	// A value that is mostly repeated/identical characters is not a real secret.
	if len(s) >= 8 {
		uniq := map[rune]int{}
		for _, r := range s {
			uniq[r]++
		}
		if len(uniq) <= 2 {
			return true
		}
	}
	return false
}

func (v exposedSecretVerifier) verify(ctx context.Context, fetch Fetcher, f state.Finding) Verdict {
	vd := Verdict{Finding: f, Class: ClassExposedSecret}
	raw := secretSource(f)
	if raw == "" {
		vd.Status = StatusInconclusive
		vd.Reason = "finding has no source URL to re-fetch the secret from"
		return vd
	}
	resp, err := fetch.Fetch(ctx, raw)
	if err != nil {
		vd.Status = StatusInconclusive
		vd.Reason = "re-fetch of the secret source failed (unreachable): " + err.Error()
		return vd
	}
	var matches []string
	for _, re := range secretRes {
		for _, m := range re.FindAllString(resp.Body, -1) {
			if looksRedacted(m) {
				continue
			}
			matches = append(matches, m)
		}
	}
	matches = dedupeSorted(matches)
	if len(matches) == 0 {
		// Either the secret is gone, or every candidate present is a placeholder.
		if anyPlaceholderPresent(resp.Body) {
			vd.Status = StatusRefuted
			vd.Reason = "only redacted/placeholder secret material is present on re-fetch; not a real exposed secret"
			return vd
		}
		vd.Status = StatusRefuted
		vd.Reason = "no well-formed secret present in the source on re-fetch (no live exposure)"
		return vd
	}
	vd.Status = StatusConfirmed
	vd.Reason = "a well-formed, non-placeholder secret is still exposed in the source on re-fetch"
	vd.Evidence = "live secret(s) present: " + redactList(matches) + " (" + raw + ")"
	return vd
}

// secretSource prefers the finding's Source-bearing field. Findings encode the
// secret's location in Target (host/service) and the URL in Evidence/Repro for
// secret scanners; fall back to Target.
func secretSource(f state.Finding) string {
	// Evidence/Repro frequently carry the exact URL the secret was seen at.
	for _, cand := range []string{extractURL(f.Evidence), extractURL(f.Repro), extractURL(f.Description)} {
		if cand != "" {
			return cand
		}
	}
	return targetURL(f)
}

var urlRe = regexp.MustCompile(`https?://[^\s"'<>) ]+`)

func extractURL(s string) string { return urlRe.FindString(s) }

// anyPlaceholderPresent reports whether the body contains any secret-shaped
// token that is a placeholder (used to distinguish "redacted" from "absent").
func anyPlaceholderPresent(body string) bool {
	for _, re := range secretRes {
		for _, m := range re.FindAllString(body, -1) {
			if looksRedacted(m) {
				return true
			}
		}
	}
	// Also catch obvious key-assignment placeholders not matching a real shape.
	return regexp.MustCompile(`(?i)(api[_-]?key|secret|token)\s*[:=]\s*["']?` + placeholderRe.String()).MatchString(body)
}

// redactList renders matched secrets audit-safely (prefix + length), never the
// full value, so the Verdict.Evidence is safe to log/report.
func redactList(in []string) string {
	var parts []string
	for _, s := range in {
		head := s
		if len(head) > 4 {
			head = head[:4]
		}
		parts = append(parts, head+"…("+itoa(len(s))+" chars)")
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ---- URL parameter helpers ------------------------------------------------

// paramNames returns the sorted query parameter names of a URL.
func paramNames(u *url.URL) []string {
	q := u.Query()
	names := make([]string, 0, len(q))
	for n := range q {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// withParam returns u with one query parameter set to value, encoded.
func withParam(u *url.URL, name, value string) string {
	c := *u
	q := c.Query()
	q.Set(name, value)
	c.RawQuery = q.Encode()
	return c.String()
}
