package oob

import (
	"strings"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/state"
)

// TestConfirmBuildsCriticalValidatedFinding registers a probe, records a
// synthetic callback for its token, and asserts Confirm returns a Critical,
// Validated finding whose Evidence mentions the source address.
func TestConfirmBuildsCriticalValidatedFinding(t *testing.T) {
	c := New(Config{BaseDomain: "oob.example.com"})
	it := c.Register("ssrf", "https://victim.example/fetch?u=", "u")

	src := "198.51.100.7:44321"
	c.Record(Hit{
		Token:      it.Token,
		Proto:      ProtoHTTP,
		RemoteAddr: src,
		Detail:     "GET /" + it.Token + " UA=curl/8",
		At:         time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC),
	})

	f, ok := c.Confirm(it.Token)
	if !ok {
		t.Fatalf("Confirm returned false for a token with a recorded hit")
	}
	if f.Severity != state.SeverityCritical {
		t.Fatalf("Severity = %v, want Critical", f.Severity)
	}
	if !f.Validated {
		t.Fatalf("Validated = false, want true (OOB callback is direct proof)")
	}
	if f.Tool != "oobcheck" {
		t.Fatalf("Tool = %q, want %q", f.Tool, "oobcheck")
	}
	if !strings.Contains(f.Evidence, src) {
		t.Fatalf("Evidence = %q, want it to mention source addr %q", f.Evidence, src)
	}
	if f.CVSS == "" || !strings.HasPrefix(f.CVSS, "CVSS:3.1/") {
		t.Fatalf("CVSS = %q, want a CVSS v3.1 vector", f.CVSS)
	}
	if !strings.Contains(strings.ToLower(f.Title), "ssrf") {
		t.Fatalf("Title = %q, want ssrf wording", f.Title)
	}
	if !strings.Contains(f.Repro, it.Domain) {
		t.Fatalf("Repro = %q, want callback domain %q", f.Repro, it.Domain)
	}
}

// TestConfirmUnhitTokenReturnsFalse asserts a registered-but-uncalled token (and
// an unknown token) yields no finding.
func TestConfirmUnhitTokenReturnsFalse(t *testing.T) {
	c := New(Config{BaseDomain: "oob.example.com"})
	it := c.Register("blind-xss", "https://victim.example/profile", "bio")

	if f, ok := c.Confirm(it.Token); ok {
		t.Fatalf("Confirm returned a finding for an un-hit token: %+v", f)
	}
	if _, ok := c.Confirm("nonexistenttoken"); ok {
		t.Fatalf("Confirm returned true for an unknown token")
	}
}

// TestConfirmAllCountMatchesHitTokens registers three probes, hits two of them
// (one twice), and asserts ConfirmAll yields exactly one finding per hit token,
// stable-ordered by token.
func TestConfirmAllCountMatchesHitTokens(t *testing.T) {
	c := New(Config{BaseDomain: "oob.example.com"})
	a := c.Register("ssrf", "https://a.example", "")
	b := c.Register("cmd-injection", "https://b.example", "host")
	_ = c.Register("sqli-oob", "https://c.example", "id") // never hit

	c.Record(Hit{Token: a.Token, Proto: ProtoDNS, RemoteAddr: "203.0.113.1:53", Detail: "A " + a.Domain})
	c.Record(Hit{Token: b.Token, Proto: ProtoHTTP, RemoteAddr: "203.0.113.2:9000", Detail: "GET /" + b.Token})
	c.Record(Hit{Token: b.Token, Proto: ProtoDNS, RemoteAddr: "203.0.113.3:53", Detail: "A " + b.Domain})

	findings := c.ConfirmAll()
	if len(findings) != 2 {
		t.Fatalf("ConfirmAll returned %d findings, want 2 (one per hit token)", len(findings))
	}

	// Stable order by token.
	for i := 1; i < len(findings); i++ {
		if findings[i-1].ID >= findings[i].ID {
			t.Fatalf("ConfirmAll not stable-ordered by token: %q then %q", findings[i-1].ID, findings[i].ID)
		}
	}
	for _, f := range findings {
		if f.Severity != state.SeverityCritical || !f.Validated {
			t.Fatalf("ConfirmAll finding not Critical/Validated: %+v", f)
		}
	}
}
