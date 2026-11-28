// Package httpprobe fingerprints an HTTP(S) service: one GET, recording status,
// Server header, and page title. It is a low-risk active probe — the Scope Guard
// has already authorized any action that reaches Execute. Response data is
// untrusted and only ever lands in Finding/Asset fields the quarantine boundary
// keeps out of the planner prompt.
package httpprobe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// Tool implements an HTTP service fingerprint.
type Tool struct{ http *http.Client }

// New returns an httpprobe Tool that does not follow redirects (we want to see
// the service's own first response).
func New() *Tool {
	return &Tool{http: &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (t *Tool) Name() string              { return "httpprobe" }
func (t *Tool) Category() action.Category { return action.CategoryRecon }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const maxBody = 64 << 10 // cap the body we read for title extraction

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Execute GETs the target and records what the service advertises.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	url := normalizeURL(a.Target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}
	req.Header.Set("User-Agent", "tyto-httpprobe")
	if a.Cookie != "" {
		req.Header.Set("Cookie", a.Cookie)
	}

	resp, err := t.http.Do(req)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", url, err)
		res.FinishedAt = time.Now().UTC()
		// A connection error is not a tool failure; report it and move on.
		return res, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	server := resp.Header.Get("Server")
	title := extractTitle(body)

	res.Assets = append(res.Assets, state.Asset{
		ID:    url,
		Type:  "url",
		Value: url,
		Attrs: map[string]string{"status": resp.Status, "server": server, "title": title},
	})
	// Also emit a `service` asset. The methodology catalog gates the entire web
	// battery (headers/TLS/CORS/secrets/content-discovery/CVE/nuclei/...) on a
	// service asset whose Attrs["service"] is http/https — a bare `url` asset
	// matches nothing. Emitting it here means a subdomain we just probed unlocks
	// deep testing on its own, without needing a port scan first.
	scheme := "http"
	if strings.HasPrefix(url, "https://") {
		scheme = "https"
	}
	res.Assets = append(res.Assets, state.Asset{
		ID:    "svc:" + url,
		Type:  "service",
		Value: url,
		Attrs: map[string]string{"service": scheme, "status": resp.Status, "server": server},
	})
	res.Findings = append(res.Findings, state.Finding{
		ID:          "HTTP-" + a.ID,
		Title:       fmt.Sprintf("HTTP service at %s (%d)", url, resp.StatusCode),
		Severity:    state.SeverityInfo,
		Target:      url,
		Description: fmt.Sprintf("status=%q server=%q title=%q", resp.Status, server, title),
		Evidence:    firstLine(string(body)),
		Tool:        t.Name(),
		Validated:   true, // we directly observed the live response
	})

	res.Success = true
	res.Output = fmt.Sprintf("%s -> %s server=%q", url, resp.Status, server)
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// normalizeURL ensures the target has a scheme; bare host:443/:8443 imply https.
func normalizeURL(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	if strings.HasSuffix(target, ":443") || strings.HasSuffix(target, ":8443") {
		return "https://" + target
	}
	return "http://" + target
}

func extractTitle(body []byte) string {
	if m := titleRe.FindSubmatch(body); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// WrapTransport implements tool.TransportWrapper: it lets the engine layer a
// RoundTripper (engagement traffic marker, evidence capture) under this tool's
// HTTP client without the tool knowing about it.
func (t *Tool) WrapTransport(wrap func(http.RoundTripper) http.RoundTripper) {
	t.http.Transport = wrap(t.http.Transport)
}
