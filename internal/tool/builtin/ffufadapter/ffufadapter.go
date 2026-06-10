// Package ffufadapter is a fast content/endpoint-discovery adapter that shells
// out to the EXTERNAL ffuf binary and parses its JSON output into endpoint
// assets + findings. It is the faster/bigger sibling of tyto's NATIVE dirfuzz
// tool (a pure-Go gobuster-lite): same finding + endpoint-Asset conventions, but
// driven by ffuf's high-throughput fuzzer over operator-supplied wordlists.
//
// Like every tyto shell-out adapter it is runtime-detected: tyto stays a pure-Go,
// offline-by-default binary, so when ffuf is not installed this adapter DEGRADES
// GRACEFULLY — it emits a single info finding and succeeds rather than failing.
// The live fuzz path is only taken when an operator has ffuf on PATH.
//
// It is scan-category and RiskLow (wordlist content discovery is benign active
// contact), so the Scope Guard gates it before Execute is ever reached. ffuf is
// driven without a shell (args are a slice), so target/param values can't inject
// arbitrary flags into a shell.
package ffufadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool implements an external ffuf content-discovery adapter.
type Tool struct{}

// New returns an ffufadapter Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "ffuf" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk implements tool.Tool. Wordlist content discovery is benign active
// contact relative to exploitation, so the ceiling is Low.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const (
	// maxFindings caps emitted findings so a huge wordlist (or a server that
	// answers to everything) can't balloon the result.
	maxFindings = 100
	// defaultWordlist ships with Kali's dirb package.
	defaultWordlist = "/usr/share/wordlists/dirb/common.txt"
	// defaultMatchCodes are the HTTP statuses ffuf treats as a hit.
	defaultMatchCodes = "200,204,301,302,307,401,403"
	// maxOutput bounds captured ffuf JSON output.
	maxOutput = 2 << 20 // 2 MiB
)

// Execute builds the FUZZ url, detects ffuf, and — if present — runs
// `ffuf -u <fuzzurl> -w <wordlist> -of json -o - -mc <codes> -s` and parses the
// JSON into endpoint assets and findings. With ffuf not installed it degrades
// gracefully to a single info finding and Success=true.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	fuzzURL := fuzzURLFor(a)
	wordlist := strings.TrimSpace(a.Params["wordlist"])
	if wordlist == "" {
		wordlist = defaultWordlist
	}

	bin := adapter.Detect("ffuf")
	if bin == "" {
		res.Findings = []state.Finding{adapter.Missing("ffuf", a.Target, "apt install ffuf")}
		res.Success = true
		res.Output = "ffuf not available; content fuzzing skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Honor cancellation before launching the external process. (adapter.Run also
	// binds ctx, so an in-flight fuzz is killed on cancel too.)
	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	matchCodes := strings.TrimSpace(a.Params["matchcodes"])
	if matchCodes == "" {
		matchCodes = defaultMatchCodes
	}
	// -of json -o - : JSON to stdout. -s : silent (no progress on stderr).
	args := []string{"-u", fuzzURL, "-w", wordlist, "-of", "json", "-o", "-", "-mc", matchCodes, "-s"}
	if ext := strings.TrimSpace(a.Params["extensions"]); ext != "" {
		args = append(args, "-e", ext)
	}

	out, runErr := adapter.Run(ctx, bin, args, maxOutput)

	findings, assets := parseFfuf(out)

	// Stamp IDs/target/tool on parsed findings (parseFfuf stays target/tool-agnostic
	// so it is purely unit-testable on a captured JSON string).
	for i := range findings {
		findings[i].ID = fmt.Sprintf("FF-%s-%d", a.ID, i)
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

	summary := fmt.Sprintf("ffuf: %d hit(s)", len(findings))
	if runErr != nil && len(findings) == 0 {
		// ffuf present but failed (bad url, missing wordlist, etc.) and gave us
		// nothing parseable. Not an error from tyto's perspective — report it.
		summary = fmt.Sprintf("ffuf run error with no parseable output: %v", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// fuzzURLFor builds the FUZZ url for an action. a.Params["url"] overrides the
// whole thing. Otherwise it takes a.Target and, if it doesn't already contain a
// FUZZ keyword, appends "/FUZZ" (after trimming a trailing slash).
func fuzzURLFor(a action.Action) string {
	if u := strings.TrimSpace(a.Params["url"]); u != "" {
		return u
	}
	target := strings.TrimSpace(a.Target)
	if strings.Contains(target, "FUZZ") {
		return target
	}
	return strings.TrimRight(target, "/") + "/FUZZ"
}

// ffufOutput mirrors the subset of `ffuf -of json` output this adapter consumes.
// Fields outside this struct are ignored by encoding/json, and every field is
// optional so malformed/partial documents parse without error.
type ffufOutput struct {
	Results []struct {
		URL    string            `json:"url"`
		Status int               `json:"status"`
		Length int               `json:"length"`
		Words  int               `json:"words"`
		Input  map[string]string `json:"input"`
	} `json:"results"`
}

// parseFfuf best-effort parses `ffuf -of json -o -` output into endpoint findings
// plus matching assets. For every result it emits a "Discovered" finding
// (Validated, Evidence carrying status+length, Severity Low for sensitive matches
// like .git/.env/backup/config/admin else Info) and — for reachable content
// (200/3xx) — an "endpoint" Asset. It tolerates missing fields and caps findings
// at ~100. It is target/tool-agnostic for unit-testing.
func parseFfuf(jsonOut string) ([]state.Finding, []state.Asset) {
	var out ffufOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonOut)), &out); err != nil {
		return nil, nil
	}

	var findings []state.Finding
	var assets []state.Asset

	for _, r := range out.Results {
		if len(findings) >= maxFindings {
			break
		}
		url := strings.TrimSpace(r.URL)
		if url == "" {
			continue
		}

		// The FUZZ value (e.g. "admin", ".git/config") lives under some key in
		// input; severity classification looks at it plus the url.
		fuzzVal := inputValue(r.Input)

		sev := state.SeverityInfo
		if isSensitive(fuzzVal, url) {
			sev = state.SeverityLow
		}

		findings = append(findings, state.Finding{
			Title:       fmt.Sprintf("Discovered: %s (HTTP %d)", url, r.Status),
			Severity:    sev,
			Target:      url,
			Description: fmt.Sprintf("ffuf content discovery found an existing endpoint (HTTP %d, %d bytes, %d words)", r.Status, r.Length, r.Words),
			Evidence:    fmt.Sprintf("%s -> %d (%d bytes)", url, r.Status, r.Length),
			Validated:   true,
		})

		// Emit an endpoint asset for reachable content (200/3xx) so later tools
		// can test it; 401/403 etc. are reported but not handed on as endpoints.
		if r.Status == 200 || (r.Status >= 300 && r.Status < 400) {
			assets = append(assets, state.Asset{
				ID:    url,
				Type:  "endpoint",
				Value: url,
				Attrs: map[string]string{"status": strconv.Itoa(r.Status)},
			})
		}
	}
	return findings, assets
}

// inputValue returns the FUZZ value from a result's input map. ffuf keys it under
// the wordlist keyword (commonly "FUZZ"); if absent, the first value is used.
func inputValue(input map[string]string) string {
	if v, ok := input["FUZZ"]; ok {
		return v
	}
	for _, v := range input {
		return v
	}
	return ""
}

// isSensitive reports whether a discovered path looks like exposed sensitive
// content, mirroring dirfuzz's severity bump. It checks both the FUZZ value and
// the full url (lower-cased).
func isSensitive(parts ...string) bool {
	p := strings.ToLower(strings.Join(parts, " "))
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
