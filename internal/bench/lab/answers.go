package lab

import (
	"regexp"
	"strings"
)

// Version identifies the answer key. Bump it whenever a planted item or decoy is
// added, removed, or changes meaning: results from different versions are not
// comparable, and `tyto bench compare` says so.
const Version = 1

// Tiers group planted items by what it takes to find them.
const (
	TierSurface   = "surface"   // visible to a single passive or low-risk check
	TierInjection = "injection" // needs an active payload against the right parameter
	TierChain     = "chain"     // needs more than one step, or reading between the lines
)

// Planted is one real vulnerability in the lab.
type Planted struct {
	ID       string
	Tier     string
	Title    string
	Location string
	// A finding is credited to this item when its text matches Class (what kind of
	// issue) AND Where (which part of the app). Matching is on the lower-cased
	// concatenation of the finding's title, target, description, evidence and
	// repro, so it works for tool-generated and operator-written findings alike.
	Class *regexp.Regexp
	Where *regexp.Regexp
}

// Decoy is a correctly-implemented endpoint that resembles a planted one. A
// finding that matches a decoy is a false positive.
type Decoy struct {
	ID       string
	Title    string
	Location string
	Class    *regexp.Regexp
	Where    *regexp.Regexp
}

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

var anywhere = re(``)

// Shared class patterns, so a planted item and its decoy use the same notion of
// "this finding claims an X".
var (
	classXSS      = re(`xss|cross[- ]site scripting`)
	classSQLi     = re(`sql ?i\b|sqli|sql injection|sql syntax|error-based`)
	classRedirect = re(`open redirect|unvalidated redirect|redirect`)
	classGraphQL  = re(`introspection`)
	classAccess   = re(`idor|insecure direct object|access control|missing auth|without auth|unauthenticated|no auth|bola`)
	classSecret   = re(`secret|credential|password|api key|access key|exposed`)
)

var planted = []Planted{
	// --- surface ---
	{"sec-headers", TierSurface, "Missing security headers", "all responses",
		re(`missing security header|content-security-policy|x-frame-options|x-content-type-options|strict-transport|clickjack|\bhsts\b|\bcsp\b`), anywhere},
	{"cookie-flags", TierSurface, "Session cookie without Secure/HttpOnly/SameSite", "Set-Cookie: session",
		re(`cookie`), re(`secure|httponly|samesite`)},
	{"cors-reflect", TierSurface, "CORS reflects any origin with credentials", "all responses",
		re(`\bcors\b|access-control-allow-origin|cross-origin resource`), anywhere},
	{"http-methods", TierSurface, "Dangerous HTTP methods advertised", "OPTIONS",
		re(`method`), re(`\btrace\b|\bput\b|\bdelete\b`)},
	{"server-banner", TierSurface, "Outdated server version disclosed", "Server header",
		re(`version disclos|server version|banner|outdated|end[- ]of[- ]life|apache/2\.2|php/5\.3`), anywhere},
	{"env-file", TierSurface, "Environment file exposed", "/.env",
		re(`expos|disclos|leak|secret|credential|sensitive|accessible`), re(`/\.env\b`)},
	{"git-exposed", TierSurface, "Git repository metadata exposed", "/.git/",
		re(`expos|disclos|leak|accessible|repository`), re(`\.git\b`)},
	{"dir-listing", TierSurface, "Directory listing enabled", "/backup/",
		re(`directory listing|directory index|index of|autoindex`), re(`backup`)},
	{"backup-dump", TierSurface, "Database backup downloadable", "/backup/backup.sql",
		re(`backup|dump|database`), re(`backup\.sql|sql dump|database dump|password hash`)},
	{"js-secrets", TierSurface, "Cloud and payment secrets in a public JS bundle", "/static/app.js",
		re(`aws|access key|stripe|sk_live|hard-?coded secret|api key`), re(`app\.js|javascript|\bjs\b|bundle|akia|sk_live`)},
	{"html-comment-creds", TierSurface, "Admin credentials in an HTML comment", "/",
		re(`comment`), re(`credential|password|creds`)},
	{"graphql-introspection", TierSurface, "GraphQL introspection enabled", "/api/graphql",
		classGraphQL, re(`graphql`)},
	{"weak-jwt", TierSurface, "JWT signed with a guessable secret", "/static/app.js",
		re(`jwt|json web token`), re(`weak|crack|guess|brute|dictionary|hs256|recover`)},

	// --- injection ---
	{"xss-reflected", TierInjection, "Reflected cross-site scripting", "/search?q=", classXSS, re(`/search|\bq\b`)},
	{"sqli-error", TierInjection, "Error-based SQL injection", "/item?id=", classSQLi, re(`/item|\bid\b`)},
	{"open-redirect", TierInjection, "Open redirect", "/redirect?url=", classRedirect, re(`/redirect|\burl\b`)},
	{"ssti", TierInjection, "Server-side template injection", "/greet?name=",
		re(`ssti|template injection|template expression`), re(`/greet|\bname\b`)},
	{"cmd-injection", TierInjection, "OS command injection", "/tools/ping?host=",
		re(`command (injection|execution)|\brce\b|remote code execution|os command`), re(`/tools/ping|\bhost\b`)},

	// --- chain ---
	{"debug-endpoint", TierChain, "Debug endpoint leaking database credentials (listed only in robots.txt)", "/internal/debug",
		anywhere, re(`/internal/debug`)},
	{"idor-invoice", TierChain, "Invoices readable by id with no authentication (IDOR)", "/api/invoice?id=",
		classAccess, re(`invoice`)},
	{"admin-takeover", TierChain, "Leaked credentials log in as admin and expose the customer export", "/login → /admin/export",
		re(`admin`), re(`/admin/export|customer export|(logged in|log in|login|authenticat|session).{0,80}(valid|success|work|as admin|leaked|comment)|(valid|working|leaked).{0,40}(credential|password).{0,80}(login|admin)`)},
}

var decoys = []Decoy{
	{"safe-search", "Output-encoded search (not XSS)", "/safe/search?q=", classXSS, re(`/safe/search`)},
	{"safe-item", "Integer-parsed item id (not SQLi)", "/safe/item?id=", classSQLi, re(`/safe/item`)},
	{"safe-redirect", "Same-site-only redirect (not an open redirect)", "/safe/redirect?url=", classRedirect, re(`/safe/redirect`)},
	{"graphql-v2", "Introspection disabled", "/api/v2/graphql", classGraphQL, re(`/api/v2/graphql`)},
	{"env-example", "Placeholder template file (no secrets)", "/.env.example", classSecret, re(`\.env\.example`)},
	{"account-auth", "Correctly requires a session", "/account", classAccess, re(`/account`)},
}

// Answers returns the planted vulnerabilities.
func Answers() []Planted { return append([]Planted(nil), planted...) }

// Decoys returns the false-positive traps.
func Decoys() []Decoy { return append([]Decoy(nil), decoys...) }

// Classify decides what a finding's text refers to. Decoys are checked first: a
// claim about /safe/search is a false positive even though it also mentions
// "/search". It returns the decoy id (if any) or the ids of every planted item
// the text is evidence for.
func Classify(text string) (decoyID string, plantedIDs []string) {
	t := strings.ToLower(text)
	for _, d := range decoys {
		if d.Where.MatchString(t) && d.Class.MatchString(t) {
			return d.ID, nil
		}
	}
	for _, p := range planted {
		if p.Class.MatchString(t) && p.Where.MatchString(t) {
			plantedIDs = append(plantedIDs, p.ID)
		}
	}
	return "", plantedIDs
}

// OracleStep is one perfectly-aimed tool invocation.
type OracleStep struct {
	Tool   string
	Path   string // appended to the lab base URL
	Params map[string]string
}

// OraclePlan is the reference "tool ceiling" run: every relevant built-in tool
// pointed at exactly the right URL, in cycles (the login in cycle 1 establishes
// the session cycle 2 relies on). It answers "what can the tools find when aimed
// perfectly?" — anything it misses is a TOOL gap; anything it finds that a model
// run misses is a PLANNING gap. It deliberately probes the decoys too, so a tool
// that false-positives on a safe endpoint is caught here.
func OraclePlan() [][]OracleStep {
	inj := func(tool string, paths ...string) []OracleStep {
		var s []OracleStep
		for _, p := range paths {
			s = append(s, OracleStep{Tool: tool, Path: p})
		}
		return s
	}
	c1 := []OracleStep{
		{Tool: "httpprobe", Path: "/"},
		{Tool: "webcheck", Path: "/"},
		{Tool: "cookieaudit", Path: "/"},
		{Tool: "corscheck", Path: "/"},
		{Tool: "httpmethods", Path: "/"},
		{Tool: "webdiscover", Path: "/"},
		{Tool: "templatescan", Path: "/"},
		{Tool: "templatescan", Path: "/backup"},
		{Tool: "dotgit", Path: "/"},
		{Tool: "dirfuzz", Path: "/"},
		{Tool: "webcrawl", Path: "/"},
		{Tool: "jsmine", Path: "/"},
		{Tool: "secretscan", Path: "/"},
		{Tool: "secretscan", Path: "/static/app.js"},
		{Tool: "secretscan", Path: "/.env"},
		{Tool: "secretscan", Path: "/.env.example"},
		{Tool: "secretscan", Path: "/internal/debug"},
		{Tool: "jwtcheck", Path: "/static/app.js"},
		{Tool: "graphqlcheck", Path: "/"},       // probes /api/graphql among its candidates
		{Tool: "graphqlcheck", Path: "/api/v2"}, // the decoy: /api/v2/graphql
		{Tool: "login", Path: "/", Params: map[string]string{"username": AdminUser, "password": AdminPassword, "login_url": "/login"}},
	}
	c1 = append(c1, inj("webinject", "/search?q=hello", "/item?id=1", "/safe/search?q=hello", "/safe/item?id=1")...)
	c1 = append(c1, inj("redircheck", "/redirect?url=/home", "/safe/redirect?url=/home")...)
	c1 = append(c1, inj("ssti", "/greet?name=guest", "/safe/search?q=hello")...)
	c1 = append(c1, inj("sqliexploit", "/item?id=1", "/safe/item?id=1")...)
	c1 = append(c1, inj("cmdexec", "/tools/ping?host=127.0.0.1")...)
	c2 := inj("accesscontrol", "/api/invoice?id=1001", "/admin/export", "/account")
	return [][]OracleStep{c1, c2}
}
