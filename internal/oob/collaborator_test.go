package oob

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		BaseDomain: "oob.example.com",
		HTTPAddr:   "127.0.0.1:0",
		DNSAddr:    "127.0.0.1:0",
	}
}

func TestRegisterUniqueAndWellFormed(t *testing.T) {
	c := New(testConfig())
	const n = 64
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		it := c.Register("ssrf", "http://target.test/q", "url")
		if it.Token == "" {
			t.Fatalf("empty token at %d", i)
		}
		if len(it.Token) != 10 {
			t.Fatalf("token %q len = %d, want 10", it.Token, len(it.Token))
		}
		if strings.ToLower(it.Token) != it.Token {
			t.Fatalf("token %q is not lowercase", it.Token)
		}
		for _, r := range it.Token {
			if !strings.ContainsRune(base36, r) {
				t.Fatalf("token %q has non-base36 rune %q", it.Token, r)
			}
		}
		if seen[it.Token] {
			t.Fatalf("duplicate token %q at %d", it.Token, i)
		}
		seen[it.Token] = true

		wantDomain := it.Token + ".oob.example.com"
		if it.Domain != wantDomain {
			t.Fatalf("Domain = %q, want %q", it.Domain, wantDomain)
		}
		wantURL := "http://" + wantDomain + "/" + it.Token
		if it.URL != wantURL {
			t.Fatalf("URL = %q, want %q", it.URL, wantURL)
		}
		if it.Class != "ssrf" || it.Target != "http://target.test/q" || it.Param != "url" {
			t.Fatalf("probe fields not preserved: %+v", it)
		}
	}
}

func TestMintTokenDeterministic(t *testing.T) {
	// The token VALUE is a pure function of the counter, so two fresh
	// collaborators must mint the same first token (no wall-clock/rand seeding).
	a := New(testConfig()).Register("ssrf", "t", "")
	b := New(testConfig()).Register("ssrf", "t", "")
	if a.Token != b.Token {
		t.Fatalf("non-deterministic mint: %q vs %q", a.Token, b.Token)
	}
	if mintToken(0) != a.Token {
		t.Fatalf("mintToken(0) = %q, want %q", mintToken(0), a.Token)
	}
}

func TestMatchToken(t *testing.T) {
	c := New(testConfig())
	it := c.Register("blind-xss", "http://target.test/", "name")
	tok := it.Token

	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"host subdomain", tok + ".oob.example.com", tok, true},
		{"host subdomain upper", strings.ToUpper(tok) + ".OOB.EXAMPLE.COM", tok, true},
		{"path segment", "/x/" + tok, tok, true},
		{"path with query host", "host/api/" + tok + "/cb", tok, true},
		{"unknown token", "deadbeef00.oob.example.com", "", false},
		{"empty", "", "", false},
		{"no token", "/just/some/path", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := c.MatchToken(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("MatchToken(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestRecordPollHitsRoundTrip(t *testing.T) {
	c := New(testConfig())
	it := c.Register("cmd-injection", "http://target.test/", "host")
	other := c.Register("sqli-oob", "http://target.test/", "id")

	now := time.Now().UTC()
	c.Record(Hit{Token: it.Token, Proto: ProtoDNS, RemoteAddr: "10.0.0.9:5", Detail: "A " + it.Domain, At: now})
	c.Record(Hit{Token: it.Token, Proto: ProtoHTTP, RemoteAddr: "10.0.0.9:6", Detail: "GET /" + it.Token, At: now})
	// A hit for an unregistered token must be dropped.
	c.Record(Hit{Token: "zzzzzzzzzz", Proto: ProtoDNS, Detail: "spoof", At: now})

	got := c.Poll(it.Token)
	if len(got) != 2 {
		t.Fatalf("Poll(it) len = %d, want 2", len(got))
	}
	if got[0].Proto != ProtoDNS || got[1].Proto != ProtoHTTP {
		t.Fatalf("hit order/proto wrong: %+v", got)
	}
	if c.Poll(other.Token) != nil {
		t.Fatalf("Poll(other) should be nil")
	}
	if c.Poll("zzzzzzzzzz") != nil {
		t.Fatalf("spoofed hit should not have been recorded")
	}
	if all := c.Hits(); len(all) != 2 {
		t.Fatalf("Hits() len = %d, want 2", len(all))
	}

	// Poll returns a copy; mutating it must not corrupt internal state.
	got[0].Detail = "tampered"
	if c.Poll(it.Token)[0].Detail == "tampered" {
		t.Fatalf("Poll did not return a defensive copy")
	}
}

func TestLookupAndInteractions(t *testing.T) {
	c := New(testConfig())
	it := c.Register("ssrf", "http://target.test/", "u")
	if got, ok := c.Lookup(it.Token); !ok || got.Token != it.Token {
		t.Fatalf("Lookup(%q) = (%+v,%v)", it.Token, got, ok)
	}
	if _, ok := c.Lookup("nope0000aa"); ok {
		t.Fatalf("Lookup of unknown token returned ok")
	}
	if its := c.Interactions(); len(its) != 1 || its[0].Token != it.Token {
		t.Fatalf("Interactions() = %+v", its)
	}
}

// TestServeHTTPRecordsHit drives the inline HTTP handler directly (no real port
// bind) and asserts a token in the path is recorded as a ProtoHTTP hit.
func TestServeHTTPRecordsHit(t *testing.T) {
	c := New(testConfig())
	it := c.Register("ssrf", "http://target.test/", "url")

	req := httptest.NewRequest(http.MethodGet, "/"+it.Token, nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rec := httptest.NewRecorder()
	c.handleHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	hits := c.Poll(it.Token)
	if len(hits) != 1 {
		t.Fatalf("Poll len = %d, want 1", len(hits))
	}
	h := hits[0]
	if h.Proto != ProtoHTTP {
		t.Fatalf("Proto = %q, want http", h.Proto)
	}
	if !strings.Contains(h.Detail, "GET /"+it.Token) || !strings.Contains(h.Detail, "UA=curl/8.0") {
		t.Fatalf("Detail = %q", h.Detail)
	}
}

// TestServeHTTPHostSubdomain covers the Host-label correlation path.
func TestServeHTTPHostSubdomain(t *testing.T) {
	c := New(testConfig())
	it := c.Register("blind-xss", "http://target.test/", "")

	req := httptest.NewRequest(http.MethodGet, "/beacon", nil)
	req.Host = it.Token + ".oob.example.com"
	rec := httptest.NewRecorder()
	c.handleHTTP(rec, req)

	if len(c.Poll(it.Token)) != 1 {
		t.Fatalf("host-subdomain hit not recorded")
	}
}

// TestServeHTTPUnknownTokenIgnored: a request carrying no known token records
// nothing but still answers 200.
func TestServeHTTPUnknownTokenIgnored(t *testing.T) {
	c := New(testConfig())
	req := httptest.NewRequest(http.MethodGet, "/nothinghere", nil)
	rec := httptest.NewRecorder()
	c.handleHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(c.Hits()) != 0 {
		t.Fatalf("unknown-token request should record no hit")
	}
}
