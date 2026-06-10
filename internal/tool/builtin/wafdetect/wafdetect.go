// Package wafdetect fingerprints a WAF or CDN sitting in front of an authorized
// HTTP service. Knowing a WAF/CDN exists is INFORMATIONAL recon: it shapes how
// later, more intrusive testing should be approached (e.g. expect rate limiting,
// IP blocking, or payload normalization). The probe sends two GETs — one normal
// and one carrying an obviously-malicious query string — and matches well-known
// vendor signatures across response headers, status, and body. Findings are
// SeverityInfo and Validated, since each is directly observed. The Scope Guard
// has already authorized the target; untrusted response data only reaches
// quarantined Finding fields.
package wafdetect

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "wafdetect" }
func (t *Tool) Category() action.Category { return action.CategoryRecon }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const maxBody = 64 << 10

// maliciousPayload is an obviously-hostile value blending XSS, SQLi, and
// path-traversal payloads. A WAF/CDN commonly answers it with a block page,
// 403, 406, or 501 even when the normal request returns 200. It is sent
// URL-encoded so the request line stays well-formed (the WAF still inspects the
// decoded value).
const maliciousPayload = "<script>alert(1)</script>' OR 1=1-- -../../etc/passwd"

// maliciousQuery returns the encoded query string carrying maliciousPayload.
func maliciousQuery() string { return "?x=" + url.QueryEscape(maliciousPayload) }

// probe is the observable surface of one response that signatures match against.
type probe struct {
	status  int
	header  http.Header
	cookies []*http.Cookie
	body    string
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	target := normalizeURL(a.Target)

	normal, err := t.fetch(ctx, target)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", target, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	// The malicious probe is best-effort: if it errors (e.g. the WAF resets the
	// connection), we still report from the normal response.
	malicious, _ := t.fetch(ctx, target+maliciousQuery())

	var findings []state.Finding
	add := func(title, detail, evidence string) {
		findings = append(findings, state.Finding{
			ID: fmt.Sprintf("WAF-%s-%d", a.ID, len(findings)), Title: title, Severity: state.SeverityInfo,
			Target: target, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true,
		})
	}

	detected := detect(normal, malicious)
	for _, d := range detected {
		add(d.title, d.detail, d.evidence)
	}
	if len(findings) == 0 {
		add("No WAF/CDN fingerprinted",
			"no known WAF/CDN vendor signature matched and the malicious probe was not blocked",
			"no matching header, cookie, status, or body signal")
	}

	res.Findings = findings
	res.Success = true
	res.Output = fmt.Sprintf("%s: %d WAF/CDN signal(s)", target, len(detected))
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

func (t *Tool) fetch(ctx context.Context, url string) (*probe, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tyto-wafdetect")

	resp, err := t.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return &probe{
		status:  resp.StatusCode,
		header:  resp.Header,
		cookies: resp.Cookies(),
		body:    string(body),
	}, nil
}

// match is one identified WAF/CDN result.
type match struct {
	title    string
	detail   string
	evidence string
}

// detect runs every vendor signature over the normal probe (and the malicious
// probe for generic block-behavior), returning one match per distinct WAF/CDN.
func detect(normal, malicious *probe) []match {
	var out []match
	seen := map[string]bool{}
	emit := func(title, detail, evidence string) {
		if seen[title] {
			return
		}
		seen[title] = true
		out = append(out, match{title: title, detail: detail, evidence: evidence})
	}

	// Cloudflare.
	if ev := vendorHit(normal, []sig{
		{header: "Server", value: "cloudflare"},
		{header: "cf-ray"},
		{header: "cf-mitigated"},
		{cookie: "__cfduid"},
	}); ev != "" {
		emit("WAF/CDN detected: Cloudflare",
			"Cloudflare reverse proxy / WAF fronts this service", ev)
	}

	// AWS (CloudFront / ELB).
	if ev := vendorHit(normal, []sig{
		{header: "x-amz-cf-id"},
		{header: "Server", value: "awselb"},
		{cookie: "AWSALB"},
	}); ev != "" {
		emit("WAF/CDN detected: AWS (CloudFront/ELB)",
			"an AWS CloudFront distribution or Elastic Load Balancer fronts this service", ev)
	}

	// Akamai.
	if ev := vendorHit(normal, []sig{
		{header: "Server", value: "akamaighost"},
		{headerPrefix: "x-akamai-"},
	}); ev != "" {
		emit("WAF/CDN detected: Akamai",
			"Akamai edge / Kona WAF fronts this service", ev)
	}

	// Imperva / Incapsula.
	if ev := vendorHit(normal, []sig{
		{header: "x-iinfo"},
		{header: "Server", value: "incapsula"},
		{cookie: "incap_ses"},
	}); ev != "" {
		emit("WAF/CDN detected: Imperva Incapsula",
			"Imperva Incapsula WAF/CDN fronts this service", ev)
	}

	// Sucuri.
	if ev := vendorHit(normal, []sig{
		{header: "Server", value: "sucuri/cloudproxy"},
		{header: "x-sucuri-id"},
	}); ev != "" {
		emit("WAF/CDN detected: Sucuri",
			"Sucuri CloudProxy WAF fronts this service", ev)
	}

	// F5 BIG-IP.
	if ev := vendorHit(normal, []sig{
		{header: "Server", value: "bigip"},
		{cookie: "BIGipServer"},
	}); ev != "" {
		emit("WAF/CDN detected: F5 BIG-IP",
			"an F5 BIG-IP appliance (likely with ASM WAF) fronts this service", ev)
	}

	// ModSecurity / NAXSI explicit signature.
	if ev := vendorHit(normal, []sig{
		{header: "Server", value: "mod_security"},
		{header: "Server", value: "naxsi"},
	}); ev != "" {
		emit("WAF/CDN detected: ModSecurity",
			"a ModSecurity / NAXSI ruleset fronts this service", ev)
	}

	// Generic block behavior: the malicious probe is rejected (403/406/501)
	// while the normal request was allowed (2xx/3xx).
	if malicious != nil && normal.status < 400 && isBlockStatus(malicious.status) {
		emit("Generic WAF behavior (blocks malicious requests)",
			"the service returned a normal status to a benign request but blocked an obviously-malicious query, indicating an unidentified WAF",
			fmt.Sprintf("normal request -> %d, malicious request -> %d", normal.status, malicious.status))
	}

	return out
}

// sig is one signature alternative: a header name (optionally with a substring
// value), a header-name prefix, or a cookie name. An empty value means
// header-presence only.
type sig struct {
	header       string
	value        string
	headerPrefix string
	cookie       string
}

// vendorHit returns the first matching signal's evidence string, or "".
func vendorHit(p *probe, sigs []sig) string {
	if p == nil {
		return ""
	}
	for _, s := range sigs {
		switch {
		case s.cookie != "":
			for _, c := range p.cookies {
				if strings.EqualFold(c.Name, s.cookie) {
					return "Set-Cookie: " + c.Name
				}
			}
		case s.headerPrefix != "":
			for name := range p.header {
				if strings.HasPrefix(strings.ToLower(name), strings.ToLower(s.headerPrefix)) {
					return name + ": " + p.header.Get(name)
				}
			}
		case s.header != "":
			v := p.header.Get(s.header)
			if v == "" {
				continue
			}
			if s.value == "" {
				return s.header + ": " + v
			}
			if strings.Contains(strings.ToLower(v), strings.ToLower(s.value)) {
				return s.header + ": " + v
			}
		}
	}
	return ""
}

func isBlockStatus(code int) bool {
	return code == http.StatusForbidden || // 403
		code == http.StatusNotAcceptable || // 406
		code == http.StatusNotImplemented // 501
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
