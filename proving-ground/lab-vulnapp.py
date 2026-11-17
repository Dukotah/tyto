#!/usr/bin/env python3
"""Deliberately vulnerable lab target for an authorized tyto demo run.
Binds 127.0.0.1:8080 only. Plants real, detectable issues across the OWASP map
so the tyto arsenal produces genuine findings. NOT for production, obviously."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import html

HOST, PORT = "127.0.0.1", 8080

INDEX = """<!doctype html><html><head><title>Northwind Billing Portal</title>
<script src="/static/app.js"></script></head><body>
<h1>Northwind Billing Portal</h1>
<!-- TODO: remove before prod. admin creds admin:Password123! -->
<form action="/admin" method="post">
  <input name="username"><input name="password" type="password">
  <button>Sign in</button></form>
<a href="/search?q=hello">search</a> | <a href="/item?id=1">item</a>
| <a href="/redirect?url=/home">home</a> | <a href="/backup/">backups</a>
</body></html>"""

APPJS = """// Northwind portal bundle
const API_BASE = "/api";
// FIXME hard-coded, rotate later
const API_KEY = "AKIAIOSFODNN7EXAMPLE";
const stripe_secret = "sk_live_51H8xReAbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
fetch(API_BASE + "/user?token=eyJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZX0.abc");
"""

ENV = """DB_HOST=127.0.0.1
DB_USER=root
DB_PASSWORD=S3cr3tR00tP@ss
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JWT_SIGNING_KEY=supersecretjwtkey
"""

GITCONFIG = """[core]
\trepositoryformatversion = 0
[remote "origin"]
\turl = https://github.com/northwind/billing-portal.git
"""

ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /.git\nDisallow: /api\n"

BACKUP_LISTING = """<!doctype html><html><head><title>Index of /backup/</title></head>
<body><h1>Index of /backup/</h1><ul>
<li><a href="backup.sql">backup.sql</a></li>
<li><a href="users.csv">users.csv</a></li></ul></body></html>"""

BACKUP_SQL = "INSERT INTO users VALUES(1,'admin','$2b$10$abcdefghijklmnopqrstuv');\n"


class H(BaseHTTPRequestHandler):
    server_version = "Apache/2.2.14"   # outdated/verbose banner
    sys_version = "(Unix) PHP/5.3.1"

    def _send(self, code, body=b"", ctype="text/html", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # weak cookie: no HttpOnly / Secure / SameSite
        self.send_header("Set-Cookie", "session=1a2b3c4d; Path=/")
        # overly permissive CORS with credentials
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        # NOTE: no X-Frame-Options, no CSP, no HSTS, no X-Content-Type-Options
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        # advertises dangerous methods
        self._send(200, "", extra={"Allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"})

    def do_POST(self):
        self._send(200, "<h1>Invalid credentials</h1>")

    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)

        if p == "/":
            return self._send(200, INDEX)
        if p == "/static/app.js":
            return self._send(200, APPJS, "application/javascript")
        if p == "/.env":
            return self._send(200, ENV, "text/plain")
        if p == "/.git/config":
            return self._send(200, GITCONFIG, "text/plain")
        if p == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain")
        if p == "/robots.txt":
            return self._send(200, ROBOTS, "text/plain")
        if p == "/backup/" or p == "/backup":
            return self._send(200, BACKUP_LISTING)
        if p == "/backup/backup.sql":
            return self._send(200, BACKUP_SQL, "text/plain")
        if p == "/admin":
            return self._send(200, "<h1>Admin Login</h1><form method=post>"
                                    "<input name=user><input name=pass></form>")
        if p == "/search":
            # reflected XSS: q echoed unsanitized
            term = q.get("q", [""])[0]
            return self._send(200, f"<h1>Results for {term}</h1>")
        if p == "/item":
            # error-based SQL injection on id
            idv = q.get("id", [""])[0]
            if "'" in idv or '"' in idv:
                return self._send(500,
                    "You have an error in your SQL syntax; check the manual that "
                    "corresponds to your MySQL server version near '" + html.escape(idv) + "'",
                    "text/plain")
            return self._send(200, f"<h1>Item {html.escape(idv)}</h1><p>Widget</p>")
        if p == "/redirect":
            # open redirect
            dest = q.get("url", ["/"])[0]
            return self._send(302, "", extra={"Location": dest})
        if p == "/api/graphql":
            return self._send(200, '{"data":{"__schema":{"types":[{"name":"User"}]}}}',
                              "application/json")
        if p == "/api/user":
            return self._send(200, '{"user":"guest","admin":false}', "application/json")
        # default 404
        return self._send(404, "<h1>404 Not Found</h1>")

    def log_message(self, *a):  # quiet
        pass


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
