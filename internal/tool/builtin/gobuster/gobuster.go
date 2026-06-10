// Package gobuster is a content/host-discovery adapter that shells out to the
// EXTERNAL gobuster binary. It is the bigger cousin of tyto's NATIVE dirfuzz and
// the ffuf adapter: it shares their content-discovery finding + endpoint-Asset
// conventions, but adds two enumeration modes those tools lack natively — DNS
// subdomain brute force ("dns") and virtual-host discovery ("vhost") — alongside
// classic directory brute force ("dir").
//
// Like every tyto shell-out adapter it is runtime-detected: tyto stays a pure-Go,
// offline-by-default binary, so when gobuster is not installed this adapter
// DEGRADES GRACEFULLY — it emits a single info finding and succeeds rather than
// failing. The live path is only taken when an operator has gobuster on PATH.
//
// It is scan-category and RiskLow (wordlist discovery is benign active contact),
// so the Scope Guard gates it before Execute is ever reached. gobuster is driven
// without a shell (args are a slice), so target/param values can't inject flags.
package gobuster

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool implements the external gobuster content/host-discovery adapter.
type Tool struct{}

// New returns a gobuster Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "gobuster" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk implements tool.Tool. Wordlist discovery is benign active contact
// relative to exploitation, so the ceiling is Low.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const (
	// maxFindings caps emitted findings so a huge wordlist (or a server/zone that
	// answers to everything) can't balloon the result.
	maxFindings = 150
	// defaultWordlist ships with Kali's dirb package.
	defaultWordlist = "/usr/share/wordlists/dirb/common.txt"
	// maxOutput bounds captured gobuster output.
	maxOutput = 2 << 20 // 2 MiB
)

// Execute resolves the mode + wordlist, detects gobuster, and — if present —
// runs the mode-appropriate gobuster invocation and parses its quiet output into
// findings + assets. With gobuster not installed it degrades gracefully to a
// single info finding and Success=true.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	mode := strings.ToLower(strings.TrimSpace(a.Params["mode"]))
	switch mode {
	case "dir", "dns", "vhost":
	default:
		mode = "dir"
	}

	wordlist := strings.TrimSpace(a.Params["wordlist"])
	if wordlist == "" {
		wordlist = defaultWordlist
	}

	bin := adapter.Detect("gobuster")
	if bin == "" {
		res.Findings = []state.Finding{adapter.Missing("gobuster", a.Target, "apt install gobuster")}
		res.Success = true
		res.Output = "gobuster not available; " + mode + " enumeration skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Honor cancellation before launching the external process. (adapter.Run also
	// binds ctx, so an in-flight run is killed on cancel too.)
	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	args := buildArgs(mode, a.Target, wordlist)

	out, runErr := adapter.Run(ctx, bin, args, maxOutput)

	findings, assets := parseGobuster(out, mode, a.Target)

	// Stamp IDs/target/tool/timestamp on parsed findings (parseGobuster stays
	// metadata-light so it is purely unit-testable on a captured string).
	for i := range findings {
		findings[i].ID = fmt.Sprintf("GB-%s-%d", a.ID, i)
		if findings[i].Target == "" {
			findings[i].Target = a.Target
		}
		findings[i].Tool = t.Name()
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = time.Now().UTC()
		}
	}
	for i := range assets {
		if assets[i].Attrs == nil {
			assets[i].Attrs = map[string]string{}
		}
		assets[i].Attrs["tool"] = t.Name()
	}
	res.Findings = append(res.Findings, findings...)
	res.Assets = append(res.Assets, assets...)

	summary := fmt.Sprintf("gobuster %s: %d hit(s)", mode, len(findings))
	if runErr != nil && len(findings) == 0 {
		// gobuster present but failed (bad target, missing wordlist, etc.) and gave
		// us nothing parseable. Not an error from tyto's perspective — report it.
		summary = fmt.Sprintf("gobuster %s run error with no parseable output: %v", mode, runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// buildArgs returns the gobuster argv for a mode (no shell; args are verbatim).
//   - dir:   gobuster dir -u <target> -w <wl> -q -k -z
//   - dns:   gobuster dns -d <domain> -w <wl> -q -z
//   - vhost: gobuster vhost -u <target> -w <wl> -q -z --append-domain
func buildArgs(mode, target, wordlist string) []string {
	switch mode {
	case "dns":
		return []string{"dns", "-d", domainOf(target), "-w", wordlist, "-q", "-z"}
	case "vhost":
		return []string{"vhost", "-u", target, "-w", wordlist, "-q", "-z", "--append-domain"}
	default: // dir
		return []string{"dir", "-u", target, "-w", wordlist, "-q", "-k", "-z"}
	}
}

// domainOf strips scheme and port from a target, yielding a bare hostname/domain
// suitable for gobuster's dns mode (-d). "https://example.com:8443/x" -> "example.com".
func domainOf(target string) string {
	s := strings.TrimSpace(target)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Drop any path/query/fragment.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Drop userinfo if present.
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// Drop port. Bracketed IPv6 ("[::1]:80") is left as-is apart from a trailing port.
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i >= 0 {
			s = s[1:i]
		}
	} else if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

// parseGobuster best-effort parses gobuster's quiet (-q) output into findings +
// assets for the given mode. It is target/tool-light (it stamps Target/asset
// values from the target so it is purely unit-testable on a captured string) and
// caps at maxFindings. Modes:
//
//   - dir:   lines like "/admin (Status: 200) [Size: 1234]" -> a "Discovered:
//     <path> (HTTP <status>)" finding (Validated, Low for sensitive
//     .git/.env/backup/config/admin else Info) + an endpoint Asset (full url) for
//     200/3xx responses.
//   - dns:   lines like "Found: api.example.com" -> a "Subdomain (DNS brute):
//     <host>" Info finding + a domain Asset.
//   - vhost: lines like "Found: dev.example.com (Status: 200) [Size: 512]" -> a
//     "Virtual host: <host>" Low finding + an endpoint/domain Asset.
func parseGobuster(out, mode, target string) ([]state.Finding, []state.Asset) {
	var findings []state.Finding
	var assets []state.Asset

	for _, raw := range strings.Split(out, "\n") {
		if len(findings) >= maxFindings {
			break
		}
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" {
			continue
		}

		switch mode {
		case "dns":
			host := afterFound(line)
			if host == "" {
				continue
			}
			findings = append(findings, state.Finding{
				Title:       "Subdomain (DNS brute): " + host,
				Severity:    state.SeverityInfo,
				Target:      host,
				Description: "gobuster dns brute force resolved a subdomain: " + host,
				Evidence:    line,
				Validated:   true,
			})
			assets = append(assets, state.Asset{
				ID:    host,
				Type:  "domain",
				Value: host,
			})

		case "vhost":
			host := afterFound(line)
			if host == "" {
				continue
			}
			// vhost lines carry the hostname first, then "(Status: ...) [Size: ...]".
			host = firstField(host)
			if host == "" {
				continue
			}
			findings = append(findings, state.Finding{
				Title:       "Virtual host: " + host,
				Severity:    state.SeverityLow,
				Target:      host,
				Description: "gobuster vhost discovery found a responding virtual host: " + host,
				Evidence:    line,
				Validated:   true,
			})
			assets = append(assets, state.Asset{
				ID:    host,
				Type:  "domain",
				Value: host,
				Attrs: map[string]string{"vhost": "true"},
			})

		default: // dir
			path, status, ok := parseDirLine(line)
			if !ok {
				continue
			}
			sev := state.SeverityInfo
			if isSensitive(path) {
				sev = state.SeverityLow
			}
			findings = append(findings, state.Finding{
				Title:       fmt.Sprintf("Discovered: %s (HTTP %d)", path, status),
				Severity:    sev,
				Target:      path,
				Description: fmt.Sprintf("gobuster dir brute force found an existing path (HTTP %d): %s", status, path),
				Evidence:    line,
				Validated:   true,
			})
			// Emit an endpoint asset for reachable content (200/3xx) so later tools
			// can test it; 401/403 etc. are reported but not handed on as endpoints.
			if status == 200 || (status >= 300 && status < 400) {
				url := joinURL(target, path)
				assets = append(assets, state.Asset{
					ID:    url,
					Type:  "endpoint",
					Value: url,
					Attrs: map[string]string{"status": fmt.Sprintf("%d", status)},
				})
			}
		}
	}
	return findings, assets
}

// afterFound returns the text following gobuster's "Found:" prefix (dns/vhost
// quiet output), trimmed. "" when the line is not a Found line.
func afterFound(line string) string {
	const pfx = "Found:"
	if !strings.HasPrefix(line, pfx) {
		return ""
	}
	return strings.TrimSpace(line[len(pfx):])
}

// firstField returns the first whitespace-delimited token of s.
func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// parseDirLine parses a gobuster dir quiet line, e.g.
// "/admin                (Status: 200) [Size: 1234]" -> ("/admin", 200, true).
// Returns ok=false for lines without a parseable "(Status: N)".
func parseDirLine(line string) (path string, status int, ok bool) {
	i := strings.Index(line, "(Status:")
	if i < 0 {
		return "", 0, false
	}
	path = strings.TrimSpace(line[:i])
	if path == "" {
		return "", 0, false
	}
	rest := line[i+len("(Status:"):]
	if j := strings.Index(rest, ")"); j >= 0 {
		rest = rest[:j]
	}
	status, err := parseInt(strings.TrimSpace(rest))
	if err != nil {
		return "", 0, false
	}
	return path, status, true
}

// parseInt parses a base-10 int without pulling in strconv error semantics we
// don't need; it fails on any non-digit so a malformed status is skipped.
func parseInt(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("non-digit %q", s)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

// joinURL combines a base target with a discovered path into a single url,
// avoiding a doubled slash. When target is empty the path is returned as-is.
func joinURL(target, path string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return path
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return strings.TrimRight(t, "/") + "/" + strings.TrimLeft(path, "/")
}

// isSensitive reports whether a discovered path looks like exposed sensitive
// content, mirroring the ffuf/dirfuzz severity bump.
func isSensitive(path string) bool {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, ".git"),
		strings.Contains(p, ".svn"),
		strings.Contains(p, ".env"),
		strings.Contains(p, "backup"),
		strings.Contains(p, "config"),
		strings.Contains(p, "admin"),
		strings.HasSuffix(p, ".sql"),
		strings.HasSuffix(p, ".bak"),
		strings.Contains(p, "actuator"),
		strings.Contains(p, "server-status"),
		strings.Contains(p, "credential"),
		strings.Contains(p, "secret"),
		strings.Contains(p, ".htpasswd"),
		strings.Contains(p, "id_rsa"):
		return true
	default:
		return false
	}
}
