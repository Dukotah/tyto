// Package lab is tyto's benchmark target: a deliberately vulnerable web
// application with a known answer key. It exists so "is tyto (or the model
// driving it) getting better?" can be answered by measurement instead of opinion.
//
// The app plants real, detectable vulnerabilities in three tiers — surface
// misconfigurations, injection flaws, and issues that need more than one step —
// alongside DECOYS: endpoints that look like the vulnerable ones but are
// correctly implemented. Reporting a decoy is a false positive, which is how the
// benchmark measures precision as well as recall.
//
// It is a plain http.Handler, so tests mount it on httptest and `tyto bench lab`
// serves it on loopback. Nothing here executes input: the "command injection"
// and "template injection" endpoints are simulations that behave like the real
// flaw to a scanner but never reach a shell or a template engine.
package lab

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Planted secrets are assembled at runtime so the source tree never contains a
// literal that looks like a live credential to a secret scanner.
var (
	awsKeyID     = "AKIA" + "T7LQ2ZXN4WJ6PB3D"
	awsSecret    = "q9Zx2Lm8Vt4Rk7Wp" + "1Nc5Hy3Jb6Gd0Fs+Ea/UoIT"
	stripeSecret = "sk_" + "live_" + "51Lb9cQeXw7Zr2Kt8Vn4Mp6Yh3Jd0Gs5Fa1Uo"
	dbPassword   = "S3cr3t" + "R00tP@ss"
	// AdminUser / AdminPassword are the credentials leaked in an HTML comment on
	// the index page; logging in with them is the first step of the chain tier.
	AdminUser     = "admin"
	AdminPassword = "Password" + "123!"
	adminSession  = "sid=adm-7f3c9a1e55b04d2c"
	jwtWeakSecret = "secret"
)

// weakJWT is an HS256 token signed with a dictionary secret, exposed in app.js.
func weakJWT() string {
	enc := base64.RawURLEncoding.EncodeToString
	head := enc([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := enc([]byte(`{"sub":"guest","admin":false,"iat":1700000000}`))
	mac := hmac.New(sha256.New, []byte(jwtWeakSecret))
	mac.Write([]byte(head + "." + body))
	return head + "." + body + "." + enc(mac.Sum(nil))
}

const indexHTML = `<!doctype html><html><head><title>Northwind Billing Portal</title>
<script src="/static/app.js"></script></head><body>
<h1>Northwind Billing Portal</h1>
<!-- TODO: remove before prod. admin creds %s:%s -->
<form action="/login" method="post">
  <input name="username"><input name="password" type="password">
  <button>Sign in</button></form>
<ul>
<li><a href="/search?q=hello">search</a></li>
<li><a href="/item?id=1">item</a></li>
<li><a href="/redirect?url=/home">home</a></li>
<li><a href="/greet?name=guest">greeting</a></li>
<li><a href="/tools/ping?host=127.0.0.1">network check</a></li>
<li><a href="/api/invoice?id=1001">my invoice</a></li>
<li><a href="/backup/">backups</a></li>
<li><a href="/account">my account</a></li>
<li><a href="/safe/search?q=hello">search (v2)</a></li>
<li><a href="/safe/item?id=1">item (v2)</a></li>
<li><a href="/safe/redirect?url=/home">home (v2)</a></li>
</ul>
</body></html>`

const robotsTxt = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /.git\nDisallow: /api\nDisallow: /internal/debug\n"

const backupListing = `<!doctype html><html><head><title>Index of /backup/</title></head>
<body><h1>Index of /backup/</h1><ul>
<li><a href="backup.sql">backup.sql</a></li>
<li><a href="users.csv">users.csv</a></li></ul></body></html>`

var invoices = map[int]string{
	1001: `{"invoice":1001,"customer":"Guest User","email":"guest@northwind.test","amount":"42.00","card_last4":"4242"}`,
	1002: `{"invoice":1002,"customer":"Dana Whitfield","email":"dana.whitfield@contoso.test","amount":"18750.00","card_last4":"9917"}`,
	1003: `{"invoice":1003,"customer":"Marcus Oyelaran","email":"m.oyelaran@fabrikam.test","amount":"3310.40","card_last4":"0338"}`,
}

// Handler returns the vulnerable application.
func Handler() http.Handler { return http.HandlerFunc(serve) }

func send(w http.ResponseWriter, r *http.Request, code int, ctype, body string) {
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Server", "Apache/2.2.14 (Unix) PHP/5.3.1") // PLANTED: outdated, verbose banner
	h.Add("Set-Cookie", "session=1a2b3c4d; Path=/")   // PLANTED: no HttpOnly / Secure / SameSite
	// PLANTED: any Origin is reflected and credentials are allowed.
	if o := r.Header.Get("Origin"); o != "" {
		h.Set("Access-Control-Allow-Origin", o)
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	// PLANTED: no CSP, X-Frame-Options, X-Content-Type-Options or HSTS anywhere.
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
}

func isAdmin(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Cookie"), adminSession)
}

func serve(w http.ResponseWriter, r *http.Request) {
	p, q := r.URL.Path, r.URL.Query()

	if r.Method == http.MethodOptions {
		// PLANTED: dangerous methods advertised.
		w.Header().Set("Allow", "GET, POST, PUT, DELETE, TRACE, OPTIONS")
		send(w, r, 200, "text/plain", "")
		return
	}
	if r.Method == http.MethodPost {
		if p == "/login" {
			_ = r.ParseForm()
			// CHAIN step 1: the credentials leaked in the index page comment work.
			if r.PostForm.Get("username") == AdminUser && r.PostForm.Get("password") == AdminPassword {
				w.Header().Add("Set-Cookie", adminSession+"; Path=/")
				w.Header().Set("Location", "/admin")
				send(w, r, 302, "text/html", "")
				return
			}
			send(w, r, 401, "text/html", "<h1>Invalid credentials</h1>")
			return
		}
		// GraphQL is spoken over POST; both endpoints answer it the way GET does.
		if p != "/api/graphql" && p != "/api/v2/graphql" {
			send(w, r, 405, "text/plain", "method not allowed")
			return
		}
	}

	switch p {
	case "/":
		send(w, r, 200, "text/html", fmt.Sprintf(indexHTML, AdminUser, AdminPassword))
	case "/static/app.js":
		// PLANTED: cloud + payment secrets and a weakly-signed JWT in a public bundle.
		send(w, r, 200, "application/javascript", "// Northwind portal bundle\nconst API_BASE = \"/api\";\n"+
			"const AWS_KEY = \""+awsKeyID+"\";\nconst stripe_secret = \""+stripeSecret+"\";\n"+
			"fetch(API_BASE + \"/user?token="+weakJWT()+"\");\nfetch(API_BASE + \"/graphql\");\n")
	case "/.env":
		// PLANTED: environment file served from the web root.
		send(w, r, 200, "text/plain", "DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASSWORD="+dbPassword+
			"\nAWS_ACCESS_KEY_ID="+awsKeyID+"\nAWS_SECRET_ACCESS_KEY="+awsSecret+"\nJWT_SIGNING_KEY="+jwtWeakSecret+"\n")
	case "/.env.example":
		// DECOY: a template file with placeholders, not secrets.
		send(w, r, 200, "text/plain", "DB_HOST=localhost\nDB_USER=changeme\nDB_PASSWORD=changeme\nAWS_ACCESS_KEY_ID=your-key-id-here\nAWS_SECRET_ACCESS_KEY=your-secret-here\n")
	case "/.git/config":
		// PLANTED: repository metadata exposed.
		send(w, r, 200, "text/plain", "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://git.northwind.test/billing/portal.git\n")
	case "/.git/HEAD":
		send(w, r, 200, "text/plain", "ref: refs/heads/main\n")
	case "/robots.txt":
		send(w, r, 200, "text/plain", robotsTxt)
	case "/backup", "/backup/":
		// PLANTED: directory listing.
		send(w, r, 200, "text/html", backupListing)
	case "/backup/backup.sql":
		// PLANTED: database dump with password hashes.
		send(w, r, 200, "text/plain", "-- MySQL dump 10.13\nCREATE TABLE users (id INT, name VARCHAR(64), pw CHAR(60));\nINSERT INTO users VALUES(1,'admin','$2b$10$abcdefghijklmnopqrstuv');\n")
	case "/backup/users.csv":
		send(w, r, 200, "text/csv", "id,name,email\n1,admin,admin@northwind.test\n")
	case "/login":
		send(w, r, 200, "text/html", `<h1>Sign in</h1><form method="post" action="/login"><input name="username"><input name="password" type="password"></form>`)
	case "/admin":
		if !isAdmin(r) {
			w.Header().Set("Location", "/login")
			send(w, r, 302, "text/html", "")
			return
		}
		send(w, r, 200, "text/html", `<h1>Admin console</h1><a href="/admin/export">export customers</a>`)
	case "/admin/export":
		// CHAIN step 2: only reachable with the admin session.
		if !isAdmin(r) {
			send(w, r, 403, "text/plain", "forbidden")
			return
		}
		send(w, r, 200, "text/csv", "customer,email,card_last4\nDana Whitfield,dana.whitfield@contoso.test,9917\nMarcus Oyelaran,m.oyelaran@fabrikam.test,0338\n")
	case "/account":
		// DECOY: correctly requires a session; anonymous users are sent to login.
		if !isAdmin(r) {
			w.Header().Set("Location", "/login")
			send(w, r, 302, "text/html", "")
			return
		}
		send(w, r, 200, "text/html", "<h1>Account</h1><p>admin</p>")
	case "/search":
		// PLANTED: reflected XSS — q echoed unsanitized.
		send(w, r, 200, "text/html", "<h1>Results for "+q.Get("q")+"</h1>")
	case "/safe/search":
		// DECOY: same feature, output-encoded.
		send(w, r, 200, "text/html", "<h1>Results for "+html.EscapeString(q.Get("q"))+"</h1>")
	case "/item":
		// PLANTED: error-based SQL injection on id.
		id := q.Get("id")
		if strings.ContainsAny(id, `'"`) {
			send(w, r, 500, "text/plain", "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"+html.EscapeString(id)+"' at line 1")
			return
		}
		send(w, r, 200, "text/html", "<h1>Item "+html.EscapeString(id)+"</h1><p>Widget</p>")
	case "/safe/item":
		// DECOY: id is parsed as an integer; anything else is a clean 400.
		n, err := strconv.Atoi(q.Get("id"))
		if err != nil {
			send(w, r, 400, "text/html", "<h1>Bad request</h1><p>id must be a number</p>")
			return
		}
		send(w, r, 200, "text/html", "<h1>Item "+strconv.Itoa(n)+"</h1><p>Widget</p>")
	case "/redirect":
		// PLANTED: open redirect.
		w.Header().Set("Location", q.Get("url"))
		send(w, r, 302, "text/html", "")
	case "/safe/redirect":
		// DECOY: only same-site relative paths are honored.
		dest := q.Get("url")
		if u, err := url.Parse(dest); err != nil || u.Host != "" || u.Scheme != "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") || strings.Contains(dest, `\`) {
			send(w, r, 400, "text/html", "<h1>Bad request</h1><p>invalid destination</p>")
			return
		}
		w.Header().Set("Location", dest)
		send(w, r, 302, "text/html", "")
	case "/greet":
		// PLANTED: server-side template injection (simulated evaluation).
		send(w, r, 200, "text/html", "<h1>Hello "+html.EscapeString(evalTemplate(q.Get("name")))+"</h1>")
	case "/tools/ping":
		// PLANTED: OS command injection (simulated shell — nothing is executed).
		send(w, r, 200, "text/plain", "PING "+q.Get("host")+"\n"+fakeShell(q.Get("host")))
	case "/api/graphql":
		// PLANTED: GraphQL introspection enabled.
		send(w, r, 200, "application/json", `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User","fields":[{"name":"passwordHash"}]},{"name":"Invoice"}]}}}`)
	case "/api/v2/graphql":
		// DECOY: introspection disabled.
		send(w, r, 400, "application/json", `{"errors":[{"message":"GraphQL introspection is not allowed"}]}`)
	case "/api/user":
		send(w, r, 200, "application/json", `{"user":"guest","admin":false}`)
	case "/api/invoice":
		// PLANTED: IDOR + missing authentication — any invoice by id, no session.
		id, _ := strconv.Atoi(q.Get("id"))
		if body, ok := invoices[id]; ok {
			send(w, r, 200, "application/json", body)
			return
		}
		send(w, r, 404, "application/json", `{"error":"not found"}`)
	case "/internal/debug":
		// PLANTED: debug endpoint, discoverable only via robots.txt.
		send(w, r, 200, "application/json", `{"debug":true,"db":{"host":"127.0.0.1","user":"root","password":"`+dbPassword+`"},"build":"2019.03.1"}`)
	default:
		send(w, r, 404, "text/html", "<h1>404 Not Found</h1>")
	}
}

var (
	tplMustache = regexp.MustCompile(`\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}`)
	tplDollar   = regexp.MustCompile(`[$#]\{\s*(\d+)\s*\*\s*(\d+)\s*\}`)
	tplERB      = regexp.MustCompile(`<%=\s*(\d+)\s*\*\s*(\d+)\s*%>`)
)

// evalTemplate imitates a template engine that evaluates arithmetic expressions
// in user input: {{a*b}}, ${a*b}, #{a*b} and <%= a*b %> are replaced by the
// product. Plain text (including a bare "a*b") is returned unchanged.
func evalTemplate(s string) string {
	for _, re := range []*regexp.Regexp{tplMustache, tplDollar, tplERB} {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			g := re.FindStringSubmatch(m)
			a, _ := strconv.Atoi(g[1])
			b, _ := strconv.Atoi(g[2])
			return strconv.Itoa(a * b)
		})
	}
	return s
}

var shellSep = regexp.MustCompile(`;|&&|\|\||\||\n|&`)

// fakeShell imitates what a shell would print if `ping <input>` were built by
// string concatenation: every command after the first separator "runs". Only a
// fixed handful of harmless commands produce output, and that output is canned —
// no process is ever started.
func fakeShell(input string) string {
	parts := shellSep.Split(input, -1)
	var out strings.Builder
	for _, raw := range parts[1:] {
		cmd := strings.TrimSpace(strings.Trim(strings.TrimSpace(raw), "`$()"))
		switch {
		case strings.HasPrefix(cmd, "echo "):
			out.WriteString(strings.Trim(strings.TrimSpace(strings.TrimPrefix(cmd, "echo ")), `"'`) + "\n")
		case cmd == "id":
			out.WriteString("uid=33(www-data) gid=33(www-data) groups=33(www-data)\n")
		case cmd == "whoami":
			out.WriteString("www-data\n")
		case cmd == "hostname":
			out.WriteString("northwind-web-01\n")
		case cmd == "uname -a" || cmd == "uname":
			out.WriteString("Linux northwind-web-01 4.4.0-21-generic #37-Ubuntu SMP x86_64 GNU/Linux\n")
		case cmd == "pwd":
			out.WriteString("/var/www/html\n")
		case cmd == "cat /etc/passwd":
			out.WriteString("root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
		}
	}
	return out.String()
}
