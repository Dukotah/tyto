// Package dirfuzz performs wordlist-based content/endpoint discovery against an
// authorized HTTP service — a polite, bounded gobuster-lite. It is the broader
// sibling of webdiscover (which probes a small CURATED set of sensitive paths):
// dirfuzz walks a ~200-entry embedded wordlist (or an operator-supplied file)
// with a small concurrent worker pool and reports paths that exist.
//
// To avoid false positives on servers that answer 200/30x to everything, it
// first probes a definitely-nonexistent path to learn the "not found" baseline
// (status + body length) and treats responses matching that baseline as misses
// — soft-404 detection. math/rand is banned in this codebase, so the probe path
// is a fixed unlikely constant rather than a generated string.
package dirfuzz

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "embed"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

//go:embed wordlist.txt
var embeddedWordlist string

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{
		Timeout:       6 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (t *Tool) Name() string              { return "dirfuzz" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const (
	defaultConcurrency = 10
	maxConcurrency     = 20
	defaultMaxWords    = 1000
	maxFindings        = 50
	maxBodySample      = 64 << 10 // bytes of body read for soft-404 length comparison
	// soft404Probe is a path that should never exist; its response defines the
	// "not found" baseline. Hardcoded (math/rand is banned).
	soft404Probe = "tyto-dirfuzz-nonexistent-9q7zx3k1vbn02"
	// lengthTolerance: responses within this many bytes of the baseline length
	// (when status matches) are treated as soft-404s.
	lengthTolerance = 48
)

// result of probing one path.
type probeResult struct {
	path    string
	status  int
	length  int
	err     error
	missing bool // matched the soft-404 baseline
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	base := strings.TrimRight(normalizeURL(a.Target), "/")

	words, err := loadWords(a.Params["wordlist"])
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: cannot load wordlist: %v", base, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	if max := parseBound(a.Params["max"], defaultMaxWords, len(words)); max < len(words) {
		words = words[:max]
	}
	concurrency := parseBound(a.Params["concurrency"], defaultConcurrency, maxConcurrency)
	if concurrency < 1 {
		concurrency = 1
	}

	// Learn the not-found baseline by probing a path that should not exist. A
	// connection error here means the base is unreachable — bail with res.Err.
	baseStatus, baseLen, err := t.probe(ctx, base+"/"+soft404Probe, a.Cookie)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", base, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	results := t.fuzz(ctx, base, words, concurrency, baseStatus, baseLen, a.Cookie)

	// Stable ordering for deterministic findings/output.
	sort.Slice(results, func(i, j int) bool { return results[i].path < results[j].path })

	var hits int
	for _, r := range results {
		if r.err != nil || r.missing {
			continue
		}
		hits++
		if len(res.Findings) >= maxFindings {
			continue
		}
		sev := severityFor(r.path, r.status)
		res.Findings = append(res.Findings, state.Finding{
			ID:          fmt.Sprintf("DF-%s-%d", a.ID, hits),
			Title:       fmt.Sprintf("Discovered: /%s (HTTP %d)", r.path, r.status),
			Severity:    sev,
			Target:      base + "/" + r.path,
			Description: fmt.Sprintf("wordlist content discovery found an existing path (HTTP %d, %d bytes)", r.status, r.length),
			Evidence:    fmt.Sprintf("GET /%s -> %d (%d bytes)", r.path, r.status, r.length),
			Tool:        t.Name(),
			Validated:   true,
		})
		// Emit an endpoint asset for reachable content (200/3xx) so later tools
		// can test it; 403/401 etc. are reported but not handed on as endpoints.
		if r.status == 200 || (r.status >= 300 && r.status < 400) {
			ep := base + "/" + r.path
			res.Assets = append(res.Assets, state.Asset{
				ID:    ep,
				Type:  "endpoint",
				Value: ep,
				Attrs: map[string]string{"status": strconv.Itoa(r.status), "tool": t.Name()},
			})
		}
	}

	res.Success = true
	res.Output = fmt.Sprintf("%s: fuzzed %d paths, %d hits", base, len(results), hits)
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// fuzz probes every word with a bounded worker pool, classifying each response
// against the soft-404 baseline. It honors ctx cancellation.
func (t *Tool) fuzz(ctx context.Context, base string, words []string, concurrency, baseStatus, baseLen int, cookie string) []probeResult {
	jobs := make(chan string)
	out := make(chan probeResult)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				if ctx.Err() != nil {
					return
				}
				status, length, err := t.probe(ctx, base+"/"+word, cookie)
				out <- probeResult{
					path:    word,
					status:  status,
					length:  length,
					err:     err,
					missing: err == nil && isNotFound(status, length, baseStatus, baseLen),
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, w := range words {
			select {
			case <-ctx.Done():
				return
			case jobs <- w:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	var results []probeResult
	for r := range out {
		results = append(results, r)
	}
	return results
}

// probe issues a GET and returns the status code and (sampled) body length.
func (t *Tool) probe(ctx context.Context, url, cookie string) (status, length int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "tyto-dirfuzz")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodySample))
	return resp.StatusCode, int(n), nil
}

// isNotFound reports whether a response should be treated as "not found": an
// explicit 404, or a soft-404 that matches the learned baseline (same status
// and a similar body length).
func isNotFound(status, length, baseStatus, baseLen int) bool {
	if status == 404 {
		return true
	}
	if status == baseStatus {
		diff := length - baseLen
		if diff < 0 {
			diff = -diff
		}
		if diff <= lengthTolerance {
			return true
		}
	}
	return false
}

// severityFor bumps sensitive hits to Low; everything else is Info.
func severityFor(path string, status int) state.Severity {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, ".git"),
		strings.Contains(p, ".svn"),
		strings.Contains(p, ".env"),
		strings.Contains(p, "backup"),
		strings.Contains(p, "config"),
		strings.HasSuffix(p, ".sql"),
		strings.HasSuffix(p, ".bak"),
		strings.Contains(p, "actuator"),
		strings.Contains(p, "server-status"),
		strings.Contains(p, "credential"),
		strings.Contains(p, "secret"),
		strings.Contains(p, ".htpasswd"),
		strings.Contains(p, "id_rsa"):
		return state.SeverityLow
	default:
		return state.SeverityInfo
	}
}

// loadWords returns the wordlist: an external file when path is non-empty and
// readable, otherwise the embedded list. A supplied-but-unreadable path falls
// back to the embedded list rather than failing — so a planner that hands over a
// bogus path (e.g. a bare "common.txt") can't break content discovery. '#'
// comments and blank lines are skipped.
func loadWords(path string) ([]string, error) {
	src := embeddedWordlist
	if p := strings.TrimSpace(path); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			src = string(b)
		}
	}
	var words []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(src))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "/")
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		words = append(words, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("empty wordlist")
	}
	return words, nil
}

// parseBound parses an optional positive-int param, clamping to [1, hardMax]
// and falling back to def when unset/invalid.
func parseBound(s string, def, hardMax int) int {
	v := def
	if t := strings.TrimSpace(s); t != "" {
		if n, err := strconv.Atoi(t); err == nil && n > 0 {
			v = n
		}
	}
	if v > hardMax {
		v = hardMax
	}
	return v
}

func normalizeURL(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	if strings.HasSuffix(target, ":443") || strings.HasSuffix(target, ":8443") {
		return "https://" + target
	}
	return "http://" + target
}
