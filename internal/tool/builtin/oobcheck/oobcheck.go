// Package oobcheck is the injection driver for tyto's out-of-band collaborator.
// It catches the BLIND vulnerability classes the in-band tools (webinject, ssti,
// sqliexploit) can't see — blind SSRF, blind/OOB OS command injection, out-of-band
// SQL injection, and stored/blind XSS — by planting payloads that, if they fire,
// make the target reach back to the collaborator listener (internal/oob). A
// recorded callback is unforgeable proof, so every confirmed finding is Critical
// and Validated.
//
// Flow: for each candidate parameter (and a few request headers) it registers a
// per-(point,class) probe with the collaborator, embeds that probe's unique
// callback Domain/URL in the class's payloads, sends the injected requests, waits
// a grace period for asynchronous callbacks, then Confirms only the tokens THIS
// execution issued (never the process-wide set) into findings.
//
// It is CategoryScan / RiskMedium: the payloads are benign beacons (an nslookup, a
// fetch of a host we control), detection not exploitation, so the Scope Guard
// gates it like the other active web tests. Reachability caveat: the target must
// be able to route to the collaborator's public DNS/HTTP listener (see internal/oob).
package oobcheck

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/oob"
	"github.com/dukotah/tyto/internal/state"
)

// Tool plants OOB probes and correlates the callbacks. collab is nil in the
// registered instance and lazily resolved to the process-wide oob.Default() at
// Execute time, so merely listing tools never starts a listener.
type Tool struct {
	http   *http.Client
	collab *oob.Collaborator
	wait   time.Duration
}

// New returns the registry instance. The collaborator and listener are resolved
// lazily on first Execute (via oob.Default) so `tyto tools` binds no ports.
func New() *Tool {
	return &Tool{
		http: &http.Client{
			Timeout: 6 * time.Second,
			// Don't chase redirects: a 30x to the callback host would beacon from
			// OUR client, not the target, and forge a false positive.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		wait: defaultWait,
	}
}

// newWith builds a Tool bound to an explicit collaborator and grace wait — used by
// tests to avoid the process-wide singleton and its real listener ports.
func newWith(c *oob.Collaborator, wait time.Duration) *Tool {
	t := New()
	t.collab = c
	t.wait = wait
	return t
}

func (t *Tool) Name() string              { return "oobcheck" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskMedium }

const (
	defaultWait = 5 * time.Second  // grace for asynchronous callbacks after sending
	maxWait     = 30 * time.Second // ceiling so a planner-supplied wait can't stall a cycle
	maxParams   = 8                // cap distinct parameters probed (bounds request volume)
)

// classes are the blind vuln classes probed, each with how many of the generator's
// payloads to actually send (the generators are ordered most-reliable-first).
var classes = []struct {
	name     string
	payloads func(oob.Interaction) []string
	send     int
}{
	{"ssrf", func(in oob.Interaction) []string { return in.SSRFTargets() }, 2},
	{"cmd-injection", func(in oob.Interaction) []string { return in.CmdInjection() }, 3},
	{"sqli-oob", func(in oob.Interaction) []string { return in.SQLiOOB() }, 1},
	{"blind-xss", func(in oob.Interaction) []string { return in.BlindXSS() }, 1},
}

// ssrfParams are common parameter names whose value is a URL/host the server
// fetches — the classic blind-SSRF surface. We probe these even when the target
// URL carries no query string, since the planner often hands us a bare endpoint.
var ssrfParams = []string{
	"url", "uri", "u", "link", "next", "redirect", "redirect_url", "return",
	"returnurl", "dest", "destination", "continue", "image", "imageurl", "img",
	"src", "source", "file", "path", "callback", "webhook", "feed", "host",
	"domain", "target", "to", "out", "view", "page", "load", "fetch", "proxy",
}

// ssrfHeaders are request headers a server-side fetch / logging pipeline commonly
// trusts as a routing hint, a secondary SSRF surface independent of any parameter.
var ssrfHeaders = []string{"X-Forwarded-For", "X-Forwarded-Host", "Referer", "True-Client-IP"}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	collab := t.collab
	if collab == nil {
		collab = oob.Default().Collaborator
	}

	base, err := url.Parse(normalizeURL(a.Target))
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}

	wait := t.wait
	if w := a.Params["wait"]; w != "" {
		if d, perr := time.ParseDuration(w); perr == nil && d >= 0 {
			wait = d
		}
	}
	if wait > maxWait {
		wait = maxWait
	}

	// tokens correlates each issued probe back to where it was planted, so the
	// confirmation pass only ever reads THIS execution's results.
	type probe struct {
		token string
		where string // human label: "param=url (ssrf)" / "header=Referer (ssrf)"
	}
	var probes []probe
	sent := 0

	// Parameter probes: every existing query param plus the common SSRF names.
	for _, name := range candidateParams(base) {
		for _, cl := range classes {
			it := collab.Register(cl.name, base.String(), name)
			pls := cl.payloads(*it)
			if len(pls) > cl.send {
				pls = pls[:cl.send]
			}
			for _, p := range pls {
				if t.injectParam(ctx, base, name, p, a.Cookie) {
					sent++
				}
			}
			probes = append(probes, probe{it.Token, fmt.Sprintf("param=%s (%s)", name, cl.name)})
		}
	}

	// Header probes: SSRF only (a URL-bearing header that a fetch/log pipeline honors).
	for _, h := range ssrfHeaders {
		it := collab.Register("ssrf", base.String(), "header:"+h)
		for _, p := range it.SSRFTargets()[:2] {
			if t.injectHeader(ctx, base, h, p, a.Cookie) {
				sent++
			}
		}
		probes = append(probes, probe{it.Token, fmt.Sprintf("header=%s (ssrf)", h)})
	}

	// Wait for asynchronous callbacks, then confirm only our own tokens.
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}

	confirmed := 0
	for _, pr := range probes {
		if f, ok := collab.Confirm(pr.token); ok {
			res.Findings = append(res.Findings, f)
			confirmed++
		}
	}

	res.Success = true
	res.Findings = append(res.Findings, state.Finding{
		ID:        "OOBCHECK-" + a.ID,
		Title:     fmt.Sprintf("OOB probing: %d probe(s) planted across %d injection point(s), %d confirmed callback(s)", len(probes), len(probes), confirmed),
		Severity:  state.SeverityInfo,
		Target:    base.String(),
		Tool:      t.Name(),
		Validated: true,
		FoundAt:   time.Now().UTC(),
	})
	if confirmed == 0 {
		// Be honest about why a zero result may be a false negative rather than proof
		// of safety: OOB needs the collaborator's listener reachable by the target.
		res.Output = fmt.Sprintf("%s: planted %d OOB probe(s) (%d requests), no callbacks within %s — confirm the collaborator's DNS/HTTP listener is reachable from the target", base.String(), len(probes), sent, wait)
	} else {
		res.Output = fmt.Sprintf("%s: %d OOB callback(s) CONFIRMED from %d probe(s) — blind vulnerability proven", base.String(), confirmed, len(probes))
	}
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// candidateParams returns the parameter names to probe: every name already on the
// target URL first (most likely to be processed), then common SSRF names, deduped
// and capped at maxParams to bound request volume.
func candidateParams(base *url.URL) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n == "" || seen[strings.ToLower(n)] || len(out) >= maxParams {
			return
		}
		seen[strings.ToLower(n)] = true
		out = append(out, n)
	}
	for n := range base.Query() {
		add(n)
	}
	for _, n := range ssrfParams {
		add(n)
	}
	return out
}

// injectParam sends a request with one parameter set to the payload, preserving
// the target's other query values. Returns whether the request was dispatched.
func (t *Tool) injectParam(ctx context.Context, base *url.URL, name, payload, cookie string) bool {
	u := *base
	q := u.Query()
	q.Set(name, payload)
	u.RawQuery = q.Encode()
	return t.send(ctx, u.String(), nil, cookie)
}

// injectHeader sends a request with the payload in one header (other things equal).
func (t *Tool) injectHeader(ctx context.Context, base *url.URL, header, payload, cookie string) bool {
	return t.send(ctx, base.String(), map[string]string{header: payload}, cookie)
}

// send issues a single GET, attaching any extra headers and the session cookie.
// A transport error is non-fatal (the callback, if any, still arrives out-of-band),
// so it only reports whether the request was dispatched.
func (t *Tool) send(ctx context.Context, u string, headers map[string]string, cookie string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "tyto-oobcheck")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return true // dispatched; the response/error doesn't matter for OOB
	}
	resp.Body.Close()
	return true
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

// WrapTransport implements tool.TransportWrapper: it lets the engine layer a
// RoundTripper (engagement traffic marker, evidence capture) under this tool's
// HTTP client without the tool knowing about it.
func (t *Tool) WrapTransport(wrap func(http.RoundTripper) http.RoundTripper) {
	t.http.Transport = wrap(t.http.Transport)
}
