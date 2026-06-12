// Package accesscontrol is a read-only broken-access-control / IDOR tester. It
// runs two GET-only differential checks against an authorized endpoint:
//
//  1. Missing-authentication (BAC): fetch the URL WITH the engagement's session
//     cookie (authenticated baseline) and WITHOUT any cookie (anonymous). If the
//     authenticated response is a real resource and the anonymous response is
//     substantially equivalent (same status, high body similarity), the endpoint
//     does not enforce auth — anyone can read it. We refute when the anonymous
//     request is denied (401/403), redirected to a login, or returns a clearly
//     different / empty body.
//
//  2. IDOR (object-id tampering): if a query parameter looks like a sequential
//     object identifier (numeric, or a conventional id-style name), replay the
//     authenticated request with that id MUTATED to a few nearby values. If a
//     mutated id returns a 200 carrying a DIFFERENT but plausibly-valid object
//     (materially different body from baseline, NOT an error / not-found /
//     forbidden page), we flag a possible IDOR — you read another object's record
//     by changing the id.
//
// Everything is GET / read-only: no state-changing requests, a bounded number of
// mutated ids, a bounded client timeout, and redirects into OTHER hosts are not
// followed. Discipline is refute-by-default: a finding is emitted only on a
// concrete differential signature (baseline subtraction), never on a guess. The
// diffing, mutation, and error-signature logic live in PURE functions
// (responses.go) so they are unit-tested with no network.
package accesscontrol

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// maxBody caps how much of each response we read for comparison.
const maxBody = 256 << 10

// maxMutations bounds how many mutated ids we try per parameter (safety cap).
const maxMutations = 4

// Tool performs the access-control checks. It holds only the shared HTTP client;
// the per-action session cookie is threaded as a local through Execute (NEVER
// stored on the struct), because the engine fans out Execute concurrently on the
// single registered instance — a shared cookie field would race and could leak
// one action's session to another target.
type Tool struct {
	http *http.Client
}

// New builds a Tool with a bounded-timeout client that does NOT blindly follow
// redirects: we inspect the first-hop response (a redirect to a login is a
// refute signal for BAC, and following it could cross into another host).
func New() *Tool {
	return &Tool{http: &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (t *Tool) Name() string { return "accesscontrol" }

// Category is Scan: this is differential enumeration of an endpoint's
// authorization behavior, not an exploitation primitive. The guard enforces
// THIS category, not the planner's advisory one.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk is Medium: the checks are read-only GETs, but an IDOR probe may read
// another user's data, so the guard should gate it above benign contact.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

// response is the minimal view of an HTTP response the pure checks operate on.
type response struct {
	status int
	body   string
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	cookie := a.Cookie // local — never stored on the shared Tool (concurrent Execute)

	base, err := url.Parse(normalizeURL(a.Target))
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}

	var notes []string
	var hits int
	add := func(sev state.Severity, title, detail, evidence, repro, impact, target, cvss string) {
		hits++
		res.Findings = append(res.Findings, state.Finding{
			ID: fmt.Sprintf("AC-%s-%d", a.ID, hits), Title: title, Severity: sev,
			Target: target, Description: detail, Evidence: evidence, Repro: repro, Impact: impact,
			Tool: t.Name(), Validated: true, CVSS: cvss,
		})
	}

	// --- Baseline (authenticated, or unauthenticated if no cookie) ---
	baseResp, err := t.fetch(ctx, base.String(), cookie)
	if err != nil {
		res.Err = err.Error()
		res.Output = base.String() + ": " + err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// --- Check 1: missing authentication / BAC ---
	if cookie == "" {
		notes = append(notes, "no session cookie supplied: auth-vs-anonymous check skipped (cannot compare authenticated vs anonymous); IDOR check ran unauthenticated (reduced coverage)")
	} else {
		anonResp, aerr := t.fetch(ctx, base.String(), "")
		if aerr != nil {
			notes = append(notes, "anonymous fetch failed ("+aerr.Error()+"); auth-vs-anonymous check inconclusive")
		} else if v := evaluateBAC(baseResp, anonResp); v.flag {
			add(state.SeverityHigh,
				"Resource accessible without authentication",
				"the endpoint returns the same protected resource to an anonymous (no-cookie) request as to the authenticated session; access control is not enforced. "+v.reason,
				v.evidence,
				"GET "+base.String()+" with no Cookie header returns HTTP "+itoa(anonResp.status)+" with a body equivalent to the authenticated response",
				"any unauthenticated party can read this resource",
				base.String(),
				"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
		} else {
			notes = append(notes, "auth-vs-anonymous: "+v.reason)
		}
	}

	// --- Check 2: IDOR (object-id tampering) ---
	q := base.Query()
	names := make([]string, 0, len(q))
	for n := range q {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic order

	idCandidates := 0
	for _, name := range names {
		orig := q.Get(name)
		muts := mutateID(name, orig, maxMutations)
		if len(muts) == 0 {
			continue
		}
		idCandidates++

		for _, mv := range muts {
			if ctx.Err() != nil {
				res.Err = ctx.Err().Error()
				res.FinishedAt = time.Now().UTC()
				return res, ctx.Err()
			}
			mu := withParam(base, name, mv)
			mresp, merr := t.fetch(ctx, mu, cookie)
			if merr != nil {
				continue
			}
			if v := evaluateIDOR(baseResp, mresp); v.flag {
				add(state.SeverityHigh,
					"Possible IDOR via parameter "+name,
					"changing the object identifier in parameter "+name+" returned a 200 response carrying a different, plausibly-valid record — the endpoint does not verify the object belongs to the session. "+v.reason,
					"param "+name+": original="+redact(orig)+" mutated="+redact(mv)+"; "+v.evidence,
					"GET "+mu+" (authenticated) returns HTTP 200 with a record distinct from the baseline object",
					"an attacker can read other users' / other objects' records by enumerating the identifier",
					mu,
					"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")
				break // one confirmed IDOR per parameter is enough
			}
		}
	}

	if idCandidates == 0 {
		notes = append(notes, "no sequential/object-id-style query parameters found to test for IDOR")
	}

	res.Success = true
	out := fmt.Sprintf("%s: %d finding(s)", base.String(), hits)
	if len(notes) > 0 {
		out += " | " + strings.Join(notes, "; ")
	}
	res.Output = out
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// fetch performs a bounded GET and returns the status + (capped) body. cookie ==
// "" sends no Cookie header (anonymous).
func (t *Tool) fetch(ctx context.Context, rawURL, cookie string) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("User-Agent", "tyto-accesscontrol")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return response{status: resp.StatusCode, body: string(body)}, nil
}

// withParam returns base's URL string with one query parameter overridden.
func withParam(base *url.URL, name, value string) string {
	u := *base
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
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

func itoa(n int) string { return fmt.Sprintf("%d", n) }
