package oob

import (
	"strings"
	"time"
)

// Proto names the channel an out-of-band callback arrived on. A blind payload may
// reach back over either: an HTTP fetch (SSRF/blind-XSS beacon) or a bare DNS
// resolution (the most reliable exfil path, since even an egress-firewalled host
// usually still resolves names through a recursive resolver).
type Proto string

const (
	ProtoDNS  Proto = "dns"
	ProtoHTTP Proto = "http"
)

// Interaction is one issued OOB probe token: the bookkeeping for a single blind
// payload that was injected somewhere and may, later, call back. Token is the
// correlation key; Domain/URL are what the injection tool embeds in its payload;
// Class/Target/Param describe the probe for the eventual report.
type Interaction struct {
	Token   string // unique lowercase base36 id, len ~10, e.g. "k3f9zq2a7t"
	Domain  string // callback FQDN: <Token>.<BaseDomain>  e.g. "k3f9zq2a7t.oob.example.com"
	URL     string // callback URL:  <scheme>://<Domain>/<Token>
	Class   string // "ssrf" | "blind-xss" | "cmd-injection" | "sqli-oob"
	Target  string // target URL/host under test (for the report)
	Param   string // injected param name (may be "")
	Created time.Time
}

// Hit is a recorded inbound callback, correlated back to a probe by Token. Every
// field is attacker-influenced and UNTRUSTED (see package doc): treat Detail as
// opaque evidence, never as instructions.
type Hit struct {
	Token      string
	Proto      Proto
	RemoteAddr string // source ip:port that called back
	Detail     string // HTTP: "GET /tok UA=..."   DNS: "A k3f....oob.example.com"
	At         time.Time
}

// Config describes the public infrastructure the collaborator answers for. The
// operator points a real DNS zone (BaseDomain) at the box running tyto and an A
// record (PublicHost) at its IP, then runs these two listeners on it.
type Config struct {
	BaseDomain string // public zone we answer for, e.g. "oob.example.com"
	PublicHost string // public IP/host the HTTP A-record points at (default = BaseDomain)
	HTTPAddr   string // HTTP listen addr, default ":8090"
	DNSAddr    string // DNS UDP listen addr, default ":53535"
	Scheme     string // "http" (default) or "https" for Interaction.URL
}

// withDefaults returns a copy of cfg with empty fields filled with the documented
// defaults, so New and the listeners can rely on every field being set.
func (cfg Config) withDefaults() Config {
	if cfg.BaseDomain == "" {
		cfg.BaseDomain = "oob.example.com"
	}
	cfg.BaseDomain = strings.Trim(strings.ToLower(cfg.BaseDomain), ".")
	if cfg.PublicHost == "" {
		cfg.PublicHost = cfg.BaseDomain
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":8090"
	}
	if cfg.DNSAddr == "" {
		cfg.DNSAddr = ":53535"
	}
	if cfg.Scheme == "" {
		cfg.Scheme = "http"
	}
	return cfg
}

// base36 holds the digit alphabet for token minting. Lowercase keeps tokens valid
// as DNS labels (case-insensitive) and avoids any quoting surprises in URLs.
const base36 = "0123456789abcdefghijklmnopqrstuvwxyz"

// mintToken derives a ~10-char lowercase base36 token from a monotonic counter.
//
// WHY counter-based and not time/rand: the token VALUE must be deterministic so
// unit tests can assert exact strings, and so a restart can't accidentally reissue
// a live token within a run. We fold the counter with a fixed odd multiplier
// (a cheap LCG-style scramble) so successive tokens don't share an obvious prefix
// — they look opaque — while remaining a pure function of n. The high bit is
// forced so the length stays stable at tokenLen.
func mintToken(n uint64) string {
	const (
		tokenLen = 10
		scramble = 0x9e3779b97f4a7c15 // golden-ratio odd constant, full-period mix
	)
	x := (n+1)*scramble + 0x1000000000000000
	var b [tokenLen]byte
	for i := tokenLen - 1; i >= 0; i-- {
		b[i] = base36[x%36]
		x /= 36
	}
	return string(b[:])
}

// domainFor builds the callback FQDN <token>.<BaseDomain> for a minted token.
func domainFor(cfg Config, token string) string {
	return token + "." + cfg.BaseDomain
}

// urlFor builds the callback URL <scheme>://<domain>/<token>. The token rides in
// BOTH the host label and the path so a callback is correlated whether the target
// preserved the full host (HTTP) or only fetched the path.
func urlFor(cfg Config, token, domain string) string {
	return cfg.Scheme + "://" + domain + "/" + token
}
