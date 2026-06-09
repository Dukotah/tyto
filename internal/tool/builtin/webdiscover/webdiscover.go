// Package webdiscover probes an authorized HTTP service for a curated set of
// commonly-exposed sensitive paths (secrets files, VCS metadata, status
// endpoints, admin panels). It is a deterministic, offline content-discovery
// check — a focused, safe subset of what ffuf/nuclei-exposures do — and guards
// against false positives by first probing a path that should not exist: if the
// server answers 200 to garbage, content discovery is unreliable and is skipped.
package webdiscover

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{
		Timeout:       6 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (t *Tool) Name() string              { return "webdiscover" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

// probe is a sensitive path and the severity of finding it exposed.
type probe struct {
	path     string
	severity state.Severity
	what     string
}

var probes = []probe{
	{"/.env", state.SeverityHigh, "environment file (often contains secrets/credentials)"},
	{"/.git/config", state.SeverityHigh, "exposed Git repository metadata (source disclosure)"},
	{"/.aws/credentials", state.SeverityHigh, "exposed AWS credentials file"},
	{"/.svn/entries", state.SeverityMedium, "exposed Subversion metadata"},
	{"/server-status", state.SeverityMedium, "Apache server-status endpoint"},
	{"/actuator", state.SeverityMedium, "Spring Boot actuator endpoints"},
	{"/phpinfo.php", state.SeverityMedium, "phpinfo() output (environment disclosure)"},
	{"/.htaccess", state.SeverityMedium, "exposed Apache .htaccess"},
	{"/admin", state.SeverityLow, "administration panel reachable"},
	{"/robots.txt", state.SeverityInfo, "robots.txt (may reveal hidden paths)"},
}

const benignProbe = "/tyto-nonexistent-zzqx9173"

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	base := strings.TrimRight(normalizeURL(a.Target), "/")

	// False-positive guard: if the server answers < 400 to a path that should not
	// exist, every probe would "hit" — report that and stop.
	if code, err := t.status(ctx, base+benignProbe); err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", base, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	} else if code < 400 {
		res.Findings = append(res.Findings, state.Finding{
			ID: "WD-" + a.ID, Title: "Content discovery unreliable (catch-all responses)", Severity: state.SeverityInfo,
			Target: base, Description: fmt.Sprintf("server returned HTTP %d for a non-existent path; path probing skipped", code),
			Tool: t.Name(), Validated: true,
		})
		res.Success = true
		res.Output = fmt.Sprintf("%s: catch-all responses, discovery skipped", base)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	var hits int
	for _, p := range probes {
		select {
		case <-ctx.Done():
			res.Err = ctx.Err().Error()
			res.FinishedAt = time.Now().UTC()
			return res, ctx.Err()
		default:
		}
		code, err := t.status(ctx, base+p.path)
		if err != nil || code >= 400 {
			continue
		}
		hits++
		res.Findings = append(res.Findings, state.Finding{
			ID:          fmt.Sprintf("WD-%s-%d", a.ID, hits),
			Title:       "Exposed path: " + p.path,
			Severity:    p.severity,
			Target:      base + p.path,
			Description: fmt.Sprintf("%s (HTTP %d)", p.what, code),
			Evidence:    fmt.Sprintf("GET %s -> %d", p.path, code),
			Tool:        t.Name(),
			Validated:   true,
		})
	}

	res.Success = true
	res.Output = fmt.Sprintf("%s: %d exposed path(s) of %d probed", base, hits, len(probes))
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

func (t *Tool) status(ctx context.Context, url string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "tyto-webdiscover")
	resp, err := t.http.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
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
