package jwtcheck

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// b64 base64url-encodes raw bytes without padding (JWT segment encoding).
func b64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// noneToken builds an unsigned JWT (alg=none) with an empty signature segment.
func noneToken() string {
	h := b64(`{"alg":"none","typ":"JWT"}`)
	p := b64(`{"sub":"1234","name":"alice"}`)
	return h + "." + p + "."
}

// hs256Token builds an HS256 JWT signed with the given secret.
func hs256Token(secret string) string {
	h := b64(`{"alg":"HS256","typ":"JWT"}`)
	p := b64(`{"sub":"1234","role":"admin"}`)
	signingInput := h + "." + p
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig
}

func run(t *testing.T, h http.HandlerFunc) action.Result {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	tool := New()
	res, err := tool.Execute(context.Background(), action.Action{ID: "t1", Target: srv.URL})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success, got Output=%q Err=%q", res.Output, res.Err)
	}
	return res
}

func hasFinding(res action.Result, sev state.Severity, titleContains string) bool {
	for _, f := range res.Findings {
		if f.Severity == sev && strings.Contains(f.Title, titleContains) {
			if !f.Validated {
				return false
			}
			return true
		}
	}
	return false
}

func TestNoneAlgorithmInBody(t *testing.T) {
	tok := noneToken()
	res := run(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("token=" + tok))
	})
	if !hasFinding(res, state.SeverityCritical, "none' algorithm") {
		t.Fatalf("expected Critical none-algorithm finding; got %+v", res.Findings)
	}
}

func TestWeakSecretInSetCookie(t *testing.T) {
	tok := hs256Token("secret")
	res := run(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session="+tok+"; Path=/")
		w.Write([]byte("ok"))
	})
	if !hasFinding(res, state.SeverityCritical, "weak secret 'secret'") {
		t.Fatalf("expected Critical weak-secret finding; got %+v", res.Findings)
	}
}

func TestNoJWT(t *testing.T) {
	res := run(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nothing to see here"))
	})
	if !hasFinding(res, state.SeverityInfo, "No JWT found") {
		t.Fatalf("expected 'No JWT found' info finding; got %+v", res.Findings)
	}
}
