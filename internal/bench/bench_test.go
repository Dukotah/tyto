package bench

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/bench/lab"
)

func TestAnswerKeyIsWellFormed(t *testing.T) {
	ids := map[string]bool{}
	tiers := map[string]int{}
	for _, p := range lab.Answers() {
		if ids[p.ID] {
			t.Errorf("duplicate planted id %q", p.ID)
		}
		ids[p.ID] = true
		tiers[p.Tier]++
		if p.Class == nil || p.Where == nil || p.Title == "" || p.Location == "" {
			t.Errorf("planted %q is incomplete", p.ID)
		}
	}
	for _, tier := range []string{lab.TierSurface, lab.TierInjection, lab.TierChain} {
		if tiers[tier] == 0 {
			t.Errorf("tier %q has no planted items", tier)
		}
	}
	for _, d := range lab.Decoys() {
		if ids[d.ID] {
			t.Errorf("decoy id %q collides with a planted id", d.ID)
		}
		ids[d.ID] = true
	}
}

// The scorer must credit findings however they are worded — a tool's terse
// title or an agent's prose — and must never credit a decoy.
func TestClassify(t *testing.T) {
	cases := []struct {
		text    string
		decoy   string
		planted string // one id that must be credited ("" = none)
	}{
		{"Reflected XSS in parameter q\nhttp://127.0.0.1:8080/search?q=hello", "", "xss-reflected"},
		{"The search page echoes the q parameter unescaped, allowing cross-site scripting. GET /search?q=<script>", "", "xss-reflected"},
		{"Reflected XSS in parameter q\nhttp://127.0.0.1:8080/safe/search?q=hello", "safe-search", ""},
		{"SQL injection (error-based) in parameter id\nhttp://h/item?id=1", "", "sqli-error"},
		{"SQL injection in id\nhttp://h/safe/item?id=1", "safe-item", ""},
		{"Open redirect via url\nhttp://h/redirect?url=/home", "", "open-redirect"},
		{"Open redirect via url\nhttp://h/safe/redirect?url=/home", "safe-redirect", ""},
		{"GraphQL introspection enabled at /api/graphql\nhttp://h/api/graphql", "", "graphql-introspection"},
		{"GraphQL introspection enabled\nhttp://h/api/v2/graphql", "graphql-v2", ""},
		{"Exposed .env File\nhttp://h/.env", "", "env-file"},
		{"Exposed secrets in environment file\nhttp://h/.env.example", "env-example", ""},
		{"Missing authentication: endpoint readable without a session\nhttp://h/account", "account-auth", ""},
		{"IDOR: changing id returns another customer's invoice\nhttp://h/api/invoice?id=1002", "", "idor-invoice"},
		{"Debug endpoint exposes database password\nhttp://h/internal/debug (found via robots.txt)", "", "debug-endpoint"},
		{"Admin credentials leaked in an HTML comment on the index page\nhttp://h/", "", "html-comment-creds"},
		{"Leaked admin credentials are valid\nLogged in as admin with the password from the page comment and downloaded /admin/export (customer emails and card digits).\nhttp://h/login", "", "admin-takeover"},
		// A bare "session established" with no sign of what was reached is NOT the chain.
		{"Authenticated session established for 127.0.0.1:8080\nthe login response set a session cookie\nhttp://h/", "", ""},
		{"Remote command execution via parameter host\nhttp://h/tools/ping?host=127.0.0.1", "", "cmd-injection"},
		{"Server-Side Template Injection in parameter name\nhttp://h/greet?name=guest", "", "ssti"},
		{"1 open TCP port(s) on 127.0.0.1", "", ""},
	}
	for _, c := range cases {
		decoy, ids := lab.Classify(c.text)
		if decoy != c.decoy {
			t.Errorf("%q: decoy = %q, want %q", c.text, decoy, c.decoy)
		}
		if c.planted == "" && c.decoy == "" && len(ids) != 0 && c.text != "" {
			// "admin-takeover" must not be credited for the bare-session case.
			for _, id := range ids {
				if id == "admin-takeover" {
					t.Errorf("%q: must not credit admin-takeover", c.text)
				}
			}
		}
		if c.planted != "" && !contains(ids, c.planted) {
			t.Errorf("%q: credited %v, want %q", c.text, ids, c.planted)
		}
	}
}

func TestScoreAndCompare(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entries := []audit.Entry{
		{Time: t0, Kind: "decision", Data: map[string]any{"allowed": false}},
		{Time: t0, Kind: "action", Data: map[string]any{"tool": "webinject"}},
		{Time: t0.Add(30 * time.Second), Kind: "action", Data: map[string]any{"tool": "webinject"}},
	}
	base := Score("before", []Finding{
		{Severity: "high", Title: "Reflected XSS in parameter q", Target: "http://h/search?q=1", Tool: "webinject", Validated: true},
		{Severity: "high", Title: "Reflected XSS in parameter q", Target: "http://h/safe/search?q=1", Tool: "webinject", Validated: true},
		{Severity: "info", Title: "GraphQL endpoint (introspection disabled)", Target: "http://h/api/v2/graphql", Tool: "graphqlcheck", Validated: true},
		{Severity: "low", Title: "Something odd", Target: "http://h/odd", Tool: "x"},
		{Severity: "info", Title: "Crawled 3 pages", Target: "http://h/", Tool: "webcrawl"},
	}, entries)

	if base.Found != 1 || base.Validated != 1 || base.DecoysHit != 1 || base.PrecisionPct != 50 {
		t.Fatalf("base score wrong: found=%d validated=%d decoys=%d precision=%v", base.Found, base.Validated, base.DecoysHit, base.PrecisionPct)
	}
	if len(base.FalsePositives) != 1 || base.FalsePositives[0].Decoy != "safe-search" {
		t.Fatalf("an info note about a decoy must not count, a severity claim must: %+v", base.FalsePositives)
	}
	if len(base.Unmatched) != 1 || !strings.Contains(base.Unmatched[0], "Something odd") {
		t.Fatalf("unmatched should hold only the non-info unknown finding: %v", base.Unmatched)
	}
	if base.Effort == nil || base.Effort.Executed != 2 || base.Effort.Denied != 1 || base.Effort.DurationSeconds != 30 || base.Effort.ActionsPerFound != 2 {
		t.Fatalf("effort wrong: %+v", base.Effort)
	}
	if base.Planted != len(lab.Answers()) {
		t.Fatalf("planted = %d, want %d", base.Planted, len(lab.Answers()))
	}

	cur := Score("after", []Finding{
		{Severity: "high", Title: "SQL injection in id", Target: "http://h/item?id=1", Tool: "webinject", Validated: true},
		// Operator-asserted (not validated) chain finding.
		{Severity: "high", Title: "IDOR on invoices", Target: "http://h/api/invoice?id=1002", Tool: "operator", Description: "no authentication; any id returns another customer's invoice"},
	}, nil)
	if cur.Found != 2 || cur.Validated != 1 || cur.DecoysHit != 0 || cur.Effort != nil {
		t.Fatalf("cur score wrong: %+v", cur)
	}

	md := RenderMarkdown(base)
	for _, want := range []string{"**1 of ", "## False positives", "## Unscored findings", "Actions executed | 2 (1 denied"} {
		if !strings.Contains(md, want) {
			t.Errorf("scorecard missing %q", want)
		}
	}
	cmp := Compare(base, cur)
	for _, want := range []string{"## Newly found", "Error-based SQL injection", "Invoices readable", "## Regressions", "Reflected cross-site scripting", "| False positives | 1 | 0 | -1 |"} {
		if !strings.Contains(cmp, want) {
			t.Errorf("comparison missing %q:\n%s", want, cmp)
		}
	}
}

// The lab itself must behave as the answer key says: planted flaws are live and
// decoys are safe. If this fails, the benchmark is measuring the wrong thing.
func TestLabBehavesAsDocumented(t *testing.T) {
	srv := httptest.NewServer(lab.Handler())
	defer srv.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string, hdr ...string) (int, string, http.Header) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return resp.StatusCode, b.String(), resp.Header
	}
	xss := url.QueryEscape("<script>alert(1)</script>")

	if _, body, _ := get("/search?q=" + xss); !strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("planted XSS is not reflecting")
	}
	if _, body, _ := get("/safe/search?q=" + xss); strings.Contains(body, "<script>") {
		t.Error("decoy search must encode its output")
	}
	if code, body, _ := get("/item?id=1'"); code != 500 || !strings.Contains(body, "SQL syntax") {
		t.Error("planted SQLi is not erroring")
	}
	if code, body, _ := get("/safe/item?id=1'"); code != 400 || strings.Contains(body, "SQL") {
		t.Error("decoy item must reject cleanly")
	}
	if _, _, h := get("/redirect?url=" + url.QueryEscape("https://evil.test/")); h.Get("Location") != "https://evil.test/" {
		t.Error("planted open redirect is not redirecting off-site")
	}
	for _, dest := range []string{"https://evil.test/", "//evil.test/", `/\evil.test`} {
		if code, _, h := get("/safe/redirect?url=" + url.QueryEscape(dest)); code != 400 || h.Get("Location") != "" {
			t.Errorf("decoy redirect must refuse %q", dest)
		}
	}
	if _, body, _ := get("/greet?name=" + url.QueryEscape("{{7*6}}")); !strings.Contains(body, "42") {
		t.Error("planted SSTI is not evaluating")
	}
	if _, body, _ := get("/greet?name=" + url.QueryEscape("7*6")); strings.Contains(body, "42") {
		t.Error("a bare expression must not be evaluated")
	}
	if _, body, _ := get("/tools/ping?host=" + url.QueryEscape("x;whoami")); !strings.Contains(body, "www-data") {
		t.Error("planted command injection is not responding")
	}
	if code, body, _ := get("/api/invoice?id=1002"); code != 200 || !strings.Contains(body, "Dana Whitfield") {
		t.Error("planted IDOR is not serving other customers' invoices")
	}
	if code, _, _ := get("/admin/export"); code != 403 {
		t.Error("admin export must be forbidden without the admin session")
	}
	if code, _, _ := get("/account"); code != 302 {
		t.Error("decoy account page must redirect anonymous users")
	}
	if _, _, h := get("/", "Origin", "https://evil.test"); h.Get("Access-Control-Allow-Origin") != "https://evil.test" {
		t.Error("planted CORS reflection missing")
	}

	// The chain: leaked creds -> login -> admin export.
	form := url.Values{"username": {lab.AdminUser}, "password": {lab.AdminPassword}}
	resp, err := client.PostForm(srv.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var session string
	for _, c := range resp.Cookies() {
		if c.Name == "sid" {
			session = c.Name + "=" + c.Value
		}
	}
	if resp.StatusCode != 302 || session == "" {
		t.Fatalf("leaked credentials must log in: status %d", resp.StatusCode)
	}
	if code, body, _ := get("/admin/export", "Cookie", session); code != 200 || !strings.Contains(body, "contoso") {
		t.Error("admin session must reach the customer export")
	}
	bad, err := client.PostForm(srv.URL+"/login", url.Values{"username": {"admin"}, "password": {"wrong"}})
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode != 401 {
		t.Errorf("wrong password must be rejected, got %d", bad.StatusCode)
	}
}
