// Package httpmethods probes an authorized HTTP service for dangerous request
// methods. It asks the server which verbs it advertises (OPTIONS -> Allow/Public)
// and independently checks whether TRACE is live and reflects request data
// (Cross-Site Tracing). Both checks are directly observed from the server's own
// responses, so every finding is marked Validated. The Scope Guard has already
// authorized the target; untrusted response data only reaches quarantined
// Finding fields.
package httpmethods

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "httpmethods" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const maxBody = 64 << 10

// traceProbe is a distinctive header we set on the TRACE request; if it is
// echoed back in the response body, the method reflects request data (XST).
const (
	traceHeader = "X-Tyto-Trace"
	traceValue  = "probe123"
)

// dangerous maps each dangerous HTTP method to the severity and title of a
// finding when the server advertises it in Allow.
type dangerousMethod struct {
	severity state.Severity
	title    string
}

var dangerousMethods = map[string]dangerousMethod{
	"PUT":     {state.SeverityMedium, "Dangerous HTTP method allowed: PUT"},
	"DELETE":  {state.SeverityMedium, "Dangerous HTTP method allowed: DELETE"},
	"TRACE":   {state.SeverityMedium, "HTTP TRACE enabled (Cross-Site Tracing)"},
	"CONNECT": {state.SeverityLow, "Dangerous HTTP method allowed: CONNECT"},
	"PATCH":   {state.SeverityLow, "Dangerous HTTP method allowed: PATCH"},
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	url := normalizeURL(a.Target)

	var findings []state.Finding
	seenTitles := map[string]bool{}
	add := func(sev state.Severity, title, detail, evidence string) {
		if seenTitles[title] {
			return
		}
		seenTitles[title] = true
		findings = append(findings, state.Finding{
			ID: fmt.Sprintf("HM-%s-%d", a.ID, len(findings)), Title: title, Severity: sev,
			Target: url, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true,
		})
	}

	// 1) OPTIONS: read the advertised method list (Allow, with Public as a
	// fallback used by some servers/proxies).
	optReq, err := http.NewRequestWithContext(ctx, http.MethodOptions, url, nil)
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}
	optReq.Header.Set("User-Agent", "tyto-httpmethods")

	optResp, err := t.http.Do(optReq)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", url, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	allow := optResp.Header.Get("Allow")
	if allow == "" {
		allow = optResp.Header.Get("Public")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(optResp.Body, maxBody))
	optResp.Body.Close()

	for _, m := range parseMethods(allow) {
		if d, ok := dangerousMethods[m]; ok {
			add(d.severity, d.title, "the server advertises this method in its Allow header; it can enable resource modification, deletion, or cross-site tracing", "Allow: "+allow)
		}
	}

	// 2) TRACE: independently confirm the method is live and reflects the
	// request. A 200 whose body echoes our probe header is a direct XST signal.
	traceReq, err := http.NewRequestWithContext(ctx, http.MethodTrace, url, nil)
	if err == nil {
		traceReq.Header.Set("User-Agent", "tyto-httpmethods")
		traceReq.Header.Set(traceHeader, traceValue)
		if traceResp, terr := t.http.Do(traceReq); terr == nil {
			body, _ := io.ReadAll(io.LimitReader(traceResp.Body, maxBody))
			traceResp.Body.Close()
			if traceResp.StatusCode == http.StatusOK && strings.Contains(string(body), traceValue) {
				add(state.SeverityMedium, "HTTP TRACE method reflects request (XST)",
					"a TRACE request returned 200 and echoed a request header back in the body, confirming Cross-Site Tracing",
					reflectedLine(string(body), traceValue))
			}
		}
	}

	res.Findings = findings
	res.Success = true
	res.Output = fmt.Sprintf("%s: %d dangerous-method issue(s)", url, len(findings))
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// parseMethods splits an Allow/Public header value into uppercased method tokens.
func parseMethods(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if m := strings.ToUpper(strings.TrimSpace(p)); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// reflectedLine returns the first body line containing the probe value, so the
// evidence is the reflected line rather than the whole echoed request.
func reflectedLine(body, needle string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, needle) {
			return strings.TrimRight(line, "\r")
		}
	}
	return needle + " reflected in TRACE response"
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
