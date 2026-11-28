// Package jwtcheck finds and analyzes JSON Web Tokens exposed by an authorized
// HTTP target. It performs a single SAFE GET, collects candidate JWTs from the
// response body, Set-Cookie values, and any response header, then decodes each
// token (header + payload) and flags common weaknesses: the unsigned "none"
// algorithm, HMAC signatures recoverable from a small weak-secret wordlist,
// expired tokens, and exposed sensitive claim keys. Every finding is directly
// observed from the one GET, so all are marked Validated. Untrusted token data
// only reaches quarantined Finding fields, and recovered secrets never appear in
// the always-emitted observation finding.
package jwtcheck

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "jwtcheck" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const maxBody = 64 << 10

// jwtRe matches a JWT: header.payload.signature, all base64url. The signature
// segment may be empty (alg:none produces an empty third segment).
var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

// weakSecrets is a small built-in wordlist of HMAC secrets to test against
// HS256/HS384/HS512 tokens. A match is direct proof the token is forgeable.
var weakSecrets = []string{
	"secret", "password", "123456", "jwt", "key",
	"changeme", "admin", "secretkey", "your-256-bit-secret", "test",
}

// sensitiveClaims are payload keys whose presence is worth flagging; we report
// only the key names, never the values, since values may themselves be secrets.
var sensitiveClaims = []string{"role", "admin", "is_admin", "scope", "email", "user"}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	url := normalizeURL(a.Target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Err = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, err
	}
	req.Header.Set("User-Agent", "tyto-jwtcheck")

	resp, err := t.http.Do(req)
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no HTTP response (%v)", url, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	var findings []state.Finding
	add := func(sev state.Severity, title, detail, evidence string) {
		findings = append(findings, state.Finding{
			ID: fmt.Sprintf("JWT-%s-%d", a.ID, len(findings)), Title: title, Severity: sev,
			Target: url, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true,
		})
	}

	tokens := collectTokens(string(body), resp.Header)
	issues := 0

	for _, tok := range tokens {
		hdr, claims, ok := decode(tok)
		if !ok {
			continue // not a structurally valid JWT despite matching the shape
		}

		alg, _ := hdr["alg"].(string)
		if alg == "" {
			alg = "unknown"
		}

		// Always emit an observation finding. Evidence is the decoded header plus
		// the claim KEYS only — never values, never any recovered secret.
		add(state.SeverityInfo, fmt.Sprintf("JWT observed (alg=%s)", alg),
			"a JSON Web Token was exposed by the target",
			fmt.Sprintf("header=%s claims=%s", compactJSON(hdr), claimKeys(claims)))

		// alg "none" — unsigned, signature verification is bypassable.
		if strings.EqualFold(alg, "none") {
			add(state.SeverityCritical, "JWT accepts 'none' algorithm (unsigned)",
				"the token declares alg=none, so signature verification can be bypassed and claims forged",
				fmt.Sprintf("header=%s", compactJSON(hdr)))
			issues++
		}

		// HMAC weak secret — try to recover the signing key from the wordlist.
		if secret, found := crackHMAC(tok, alg); found {
			add(state.SeverityCritical, fmt.Sprintf("JWT signed with weak secret '%s'", secret),
				"the HMAC signing key was recovered from a small wordlist, so tokens can be forged",
				fmt.Sprintf("secret=%q verifies the %s signature", secret, alg))
			issues++
		}

		// Expired token.
		if exp, ok := numClaim(claims, "exp"); ok && int64(exp) < time.Now().Unix() {
			add(state.SeverityInfo, "Expired JWT observed",
				"the token's exp claim is in the past",
				fmt.Sprintf("exp=%d", int64(exp)))
		}

		// Sensitive claim keys present.
		if keys := presentSensitive(claims); len(keys) > 0 {
			add(state.SeverityLow, "JWT exposes claims: "+strings.Join(keys, ", "),
				"the token payload carries identity/authorization claims that were exposed to the client",
				"claim keys: "+strings.Join(keys, ", "))
			issues++
		}
	}

	if len(tokens) == 0 {
		add(state.SeverityInfo, "No JWT found", "no JSON Web Token was observed in the response", url)
	}

	res.Findings = findings
	res.Success = true
	if len(tokens) == 0 {
		res.Output = fmt.Sprintf("%s: found 0 JWT(s), 0 issue(s)", url)
	} else {
		res.Output = fmt.Sprintf("%s: found %d JWT(s), %d issue(s)", url, len(tokens), issues)
	}
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// collectTokens gathers deduped JWTs from the response body, Set-Cookie values,
// and every other response header value.
func collectTokens(body string, header http.Header) []string {
	seen := map[string]bool{}
	var out []string
	scan := func(s string) {
		for _, m := range jwtRe.FindAllString(s, -1) {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	scan(body)
	for _, vals := range header {
		for _, v := range vals {
			scan(v)
		}
	}
	return out
}

// decode splits and base64url-decodes the header and payload JSON segments.
func decode(tok string) (hdr, claims map[string]any, ok bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, false
	}
	hdr, ok = decodeSegment(parts[0])
	if !ok {
		return nil, nil, false
	}
	claims, ok = decodeSegment(parts[1])
	if !ok {
		return nil, nil, false
	}
	return hdr, claims, true
}

func decodeSegment(seg string) (map[string]any, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	return m, true
}

// crackHMAC tries each weak secret against the token's HMAC signature for the
// matching HS algorithm. Returns the recovered secret on a match.
func crackHMAC(tok, alg string) (string, bool) {
	var newHash func() hash.Hash
	switch strings.ToUpper(alg) {
	case "HS256":
		newHash = sha256.New
	case "HS384":
		newHash = sha512.New384
	case "HS512":
		newHash = sha512.New
	default:
		return "", false
	}

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", false
	}
	signingInput := parts[0] + "." + parts[1]
	want, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(want) == 0 {
		return "", false
	}

	for _, secret := range weakSecrets {
		mac := hmac.New(newHash, []byte(secret))
		mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), want) {
			return secret, true
		}
	}
	return "", false
}

// claimKeys returns the sorted payload key names (values omitted on purpose).
func claimKeys(claims map[string]any) string {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// presentSensitive returns the sensitive claim keys present in the payload.
func presentSensitive(claims map[string]any) []string {
	var out []string
	for _, k := range sensitiveClaims {
		if _, ok := claims[k]; ok {
			out = append(out, k)
		}
	}
	return out
}

// numClaim extracts a numeric claim (JSON numbers decode to float64).
func numClaim(claims map[string]any, key string) (float64, bool) {
	switch v := claims[key].(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

// compactJSON renders a decoded segment back to compact JSON for evidence.
func compactJSON(m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
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
