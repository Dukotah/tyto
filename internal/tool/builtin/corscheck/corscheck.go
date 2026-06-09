// Package corscheck detects Cross-Origin Resource Sharing (CORS)
// misconfiguration with a single SAFE GET. It sends an attacker-controlled
// Origin header and inspects whether the response reflects it (or wildcards it)
// in Access-Control-Allow-Origin, and whether credentials are allowed. Every
// finding is directly observed from one response, so all are marked Validated.
// The Scope Guard has already authorized the target; untrusted response data
// only reaches quarantined Finding fields.
package corscheck

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// evilOrigin is the attacker-controlled Origin we ask the server to honor. If
// it is reflected back in Access-Control-Allow-Origin, the server trusts any
// origin.
const evilOrigin = "https://tyto-evil.example"

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "corscheck" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	url := normalizeURL(a.Target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}
	req.Header.Set("User-Agent", "tyto-corscheck")
	req.Header.Set("Origin", evilOrigin)

	resp, err := t.http.Do(req)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", url, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	defer resp.Body.Close()

	acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	acac := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))
	credentials := strings.EqualFold(acac, "true")
	evidence := fmt.Sprintf("Access-Control-Allow-Origin: %q, Access-Control-Allow-Credentials: %q", acao, acac)

	var findings []state.Finding
	add := func(sev state.Severity, title, detail string) {
		findings = append(findings, state.Finding{
			ID: fmt.Sprintf("CORS-%s-%d", a.ID, len(findings)), Title: title, Severity: sev,
			Target: url, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true,
		})
	}

	switch {
	case acao == evilOrigin && credentials:
		add(state.SeverityHigh, "CORS: arbitrary origin reflected with credentials",
			"the server reflects any Origin into Access-Control-Allow-Origin and allows credentials, permitting cross-origin credentialed reads of authenticated responses")
	case acao == evilOrigin:
		add(state.SeverityMedium, "CORS: arbitrary origin reflected",
			"the server reflects any Origin into Access-Control-Allow-Origin, so any site can read non-credentialed cross-origin responses")
	case acao == "*" && credentials:
		add(state.SeverityHigh, "CORS: wildcard origin with credentials",
			"the server returns a wildcard Access-Control-Allow-Origin together with Access-Control-Allow-Credentials: true; browsers block this exact combination, but it is a real misconfiguration signal indicating an overly permissive CORS policy")
	case acao == "*":
		add(state.SeverityLow, "CORS: wildcard Access-Control-Allow-Origin",
			"the server returns a wildcard Access-Control-Allow-Origin, exposing non-credentialed responses to any origin")
	}

	res.Findings = findings
	res.Success = true
	res.Output = fmt.Sprintf("%s: %d CORS issue(s)", url, len(findings))
	res.FinishedAt = time.Now().UTC()
	return res, nil
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
