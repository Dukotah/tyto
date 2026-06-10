// Package templates is a pure-Go, offline, Nuclei-style HTTP detection engine.
// It loads YAML detection templates and runs their HTTP requests and matchers
// against a target base URL. It is a lightweight, dependency-free alternative to
// embedding Nuclei: a single binary, no network template feed, no external
// process. Operators add their own templates; a curated starter pack is embedded
// via go:embed.
//
// A template is one YAML file describing an ID, human-readable info, and a list
// of requests. Each request fetches one or more paths (with {{BaseURL}}
// substituted for the target) and evaluates a set of matchers (status code,
// body/header words, regexes). Matching is intentionally conservative: an HTTP
// call that errors is skipped, not fatal, and the response body is capped so a
// hostile target cannot exhaust memory. The engine reports a Hit per matching
// URL — it never modifies the target (templates here are GET-only by design).
package templates

import (
	"context"
	"embed"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed embedded/*.yaml
var embedded embed.FS

// maxBodyBytes caps how much of a response body we read into memory before
// running matchers. A misbehaving or hostile target cannot make us allocate
// without bound. 512KB is ample for the textual signatures these templates use.
const maxBodyBytes = 512 * 1024

// validSeverities is the closed set of severities a template may declare.
var validSeverities = map[string]bool{
	"info":     true,
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

// Info is the human-readable metadata for a template.
type Info struct {
	Name        string `yaml:"name"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

// Template is one detection: an identifier, its info, and the requests to run.
type Template struct {
	ID       string    `yaml:"id"`
	Info     Info      `yaml:"info"`
	Requests []Request `yaml:"requests"`
}

// Request is a single HTTP probe: a method, one or more paths to fetch, and the
// matchers (combined via MatchersCondition) that decide whether it fired.
type Request struct {
	Method            string    `yaml:"method"`
	Path              []string  `yaml:"path"`
	MatchersCondition string    `yaml:"matchers-condition"`
	Matchers          []Matcher `yaml:"matchers"`
}

// Matcher is one condition evaluated against a response. Type is one of
// "status", "word", or "regex". Negative inverts the result.
type Matcher struct {
	Type      string   `yaml:"type"`
	Status    []int    `yaml:"status"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Part      string   `yaml:"part"`      // body|header|all (default body)
	Condition string   `yaml:"condition"` // and|or (default or)
	Negative  bool     `yaml:"negative"`
}

// Hit is a single confirmed match: which template fired, and at which URL.
type Hit struct {
	TemplateID  string
	Name        string
	Severity    string
	Description string
	URL         string
}

// Parse decodes a single YAML template.
func Parse(data []byte) (Template, error) {
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return Template{}, fmt.Errorf("parse template: %w", err)
	}
	return t, nil
}

// LoadEmbedded parses every template in the embedded starter pack. A malformed
// embedded template is returned as an error (it indicates a build-time mistake,
// not a runtime condition).
func LoadEmbedded() ([]Template, error) {
	entries, err := embedded.ReadDir("embedded")
	if err != nil {
		return nil, fmt.Errorf("read embedded dir: %w", err)
	}
	var tmpls []Template
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := "embedded/" + e.Name()
		data, err := embedded.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		t, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		tmpls = append(tmpls, t)
	}
	return tmpls, nil
}

// Run executes every request (and every path within it) against baseURL,
// evaluates the matchers, and returns one Hit per matching URL. A request whose
// HTTP call errors is skipped rather than aborting the template. Hits are
// deduplicated by URL within this template. The context is respected: it is
// attached to each request and a cancellation error is surfaced.
func (t Template) Run(ctx context.Context, client *http.Client, baseURL string) ([]Hit, error) {
	if client == nil {
		client = http.DefaultClient
	}
	base := strings.TrimRight(baseURL, "/")

	var hits []Hit
	seen := make(map[string]bool)

	for _, req := range t.Requests {
		method := req.Method
		if method == "" {
			method = http.MethodGet
		}
		for _, p := range req.Path {
			if err := ctx.Err(); err != nil {
				return hits, err
			}
			url := substitute(p, base)

			hreq, err := http.NewRequestWithContext(ctx, method, url, nil)
			if err != nil {
				// A bad URL/method is a per-path problem; skip it.
				continue
			}
			resp, err := client.Do(hreq)
			if err != nil {
				// Network/DNS/timeout: skip this path, keep going.
				if ctx.Err() != nil {
					return hits, ctx.Err()
				}
				continue
			}
			body := readCapped(resp.Body)
			resp.Body.Close()

			if evalRequest(req, resp, body) {
				if !seen[url] {
					seen[url] = true
					hits = append(hits, Hit{
						TemplateID:  t.ID,
						Name:        t.Info.Name,
						Severity:    t.Info.Severity,
						Description: t.Info.Description,
						URL:         url,
					})
				}
			}
		}
	}
	return hits, nil
}

// RunAll runs every template against baseURL and collects all hits. Per-template
// errors (including context cancellation mid-template) are skipped so one bad
// template cannot abort the whole scan; callers wanting strict cancellation
// should check ctx themselves.
func RunAll(ctx context.Context, client *http.Client, baseURL string, tmpls []Template) []Hit {
	var all []Hit
	for _, t := range tmpls {
		if ctx.Err() != nil {
			return all
		}
		hits, err := t.Run(ctx, client, baseURL)
		if err != nil {
			continue
		}
		all = append(all, hits...)
	}
	return all
}

// substitute replaces {{BaseURL}} with the (trailing-slash-stripped) base. Paths
// are expected to begin with the placeholder, but a literal-only path is passed
// through unchanged so operators can hardcode a full URL if they must.
func substitute(path, base string) string {
	return strings.ReplaceAll(path, "{{BaseURL}}", base)
}

// readCapped reads up to maxBodyBytes from r. Read errors yield whatever was
// read so far; matchers then evaluate against the partial body.
func readCapped(r io.Reader) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, maxBodyBytes))
	return b
}

// evalRequest combines a request's matchers per its matchers-condition.
func evalRequest(req Request, resp *http.Response, body []byte) bool {
	if len(req.Matchers) == 0 {
		return false
	}
	cond := strings.ToLower(req.MatchersCondition)
	and := cond != "or" // default is "and"

	for _, m := range req.Matchers {
		ok := evalMatcher(m, resp, body)
		if and && !ok {
			return false
		}
		if !and && ok {
			return true
		}
	}
	return and // all passed (and) / none passed (or)
}

// evalMatcher evaluates a single matcher, applying Negative last.
func evalMatcher(m Matcher, resp *http.Response, body []byte) bool {
	var ok bool
	switch strings.ToLower(m.Type) {
	case "status":
		for _, s := range m.Status {
			if resp.StatusCode == s {
				ok = true
				break
			}
		}
	case "word":
		hay := part(m.Part, resp, body)
		ok = matchTerms(m.Condition, m.Words, func(w string) bool {
			return strings.Contains(hay, w)
		})
	case "regex":
		hay := part(m.Part, resp, body)
		ok = matchTerms(m.Condition, m.Regex, func(p string) bool {
			re, err := regexp.Compile(p)
			if err != nil {
				return false
			}
			return re.MatchString(hay)
		})
	default:
		ok = false
	}
	if m.Negative {
		return !ok
	}
	return ok
}

// matchTerms applies test to each term and combines per condition (default or).
// An empty term list never matches.
func matchTerms(condition string, terms []string, test func(string) bool) bool {
	if len(terms) == 0 {
		return false
	}
	and := strings.ToLower(condition) == "and"
	for _, term := range terms {
		ok := test(term)
		if and && !ok {
			return false
		}
		if !and && ok {
			return true
		}
	}
	return and
}

// part returns the response text a word/regex matcher should search, per the
// matcher's Part field (default body).
func part(p string, resp *http.Response, body []byte) string {
	switch strings.ToLower(p) {
	case "header":
		return headerDump(resp)
	case "all":
		statusLine := fmt.Sprintf("%s %s", resp.Proto, resp.Status)
		return statusLine + "\n" + headerDump(resp) + "\n" + string(body)
	default: // "body" or unspecified
		return string(body)
	}
}

// headerDump renders all response headers as "Key: value" lines.
func headerDump(resp *http.Response) string {
	var sb strings.Builder
	for k, vs := range resp.Header {
		for _, v := range vs {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// ValidSeverity reports whether s is one of the allowed severity levels. Exposed
// so callers (and tests) can validate operator-supplied templates.
func ValidSeverity(s string) bool {
	return validSeverities[strings.ToLower(s)]
}
