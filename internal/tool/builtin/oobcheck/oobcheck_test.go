package oobcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/oob"
	"github.com/dukotah/tyto/internal/state"
)

// ssrfSink simulates a server-side fetcher: any request whose `url` parameter
// carries a token issued by collab is treated as a fetch of that callback host,
// so the sink records the out-of-band Hit — exactly what a real blind-SSRF target
// would cause. Other parameters are ignored (a non-vulnerable surface), which lets
// the test prove the tool attributes the hit to the right injection point.
func ssrfSink(collab *oob.Collaborator, vulnParam string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(vulnParam)
		for _, it := range collab.Interactions() {
			if v != "" && strings.Contains(v, it.Token) {
				collab.Record(oob.Hit{
					Token:      it.Token,
					Proto:      oob.ProtoHTTP,
					RemoteAddr: "203.0.113.7:443",
					Detail:     "GET / (simulated server-side fetch)",
					At:         time.Now().UTC(),
				})
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
}

// newCollab builds a non-listening collaborator: the test injects callbacks via
// Record directly, so no real DNS/HTTP listener (or port) is needed.
func newCollab() *oob.Collaborator {
	return oob.New(oob.Config{BaseDomain: "oob.test"})
}

func criticalSSRF(fs []state.Finding) *state.Finding {
	for i := range fs {
		f := &fs[i]
		if f.Severity == state.SeverityCritical && strings.Contains(strings.ToLower(f.Title), "ssrf") {
			return f
		}
	}
	return nil
}

func TestOOBCheckConfirmsBlindSSRF(t *testing.T) {
	collab := newCollab()
	srv := ssrfSink(collab, "url")
	defer srv.Close()

	res, err := newWith(collab, 50*time.Millisecond).
		Execute(context.Background(), action.Action{ID: "o1", Target: srv.URL})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success {
		t.Fatalf("Success=false (out=%q err=%q)", res.Output, res.Err)
	}

	f := criticalSSRF(res.Findings)
	if f == nil {
		t.Fatalf("expected a confirmed critical SSRF finding; got %+v", res.Findings)
	}
	if !f.Validated {
		t.Fatal("an OOB-confirmed finding must be Validated")
	}
	if f.Tool != "oobcheck" {
		t.Fatalf("finding Tool = %q, want oobcheck", f.Tool)
	}
	if !strings.Contains(f.Repro, "url") {
		t.Fatalf("repro should name the injected `url` parameter: %q", f.Repro)
	}
	if f.Evidence == "" {
		t.Fatal("confirmed finding must carry callback evidence")
	}
}

// A target with no OOB-reachable sink must yield zero confirmed callbacks — no
// false positives — and an honest summary that a null result isn't proof of safety.
func TestOOBCheckNoSinkNoFindings(t *testing.T) {
	collab := newCollab()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // ignores everything; never calls back
	}))
	defer srv.Close()

	res, err := newWith(collab, 50*time.Millisecond).
		Execute(context.Background(), action.Action{ID: "o2", Target: srv.URL})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if criticalSSRF(res.Findings) != nil {
		t.Fatalf("no sink should mean no critical finding; got %+v", res.Findings)
	}
	// Exactly the one informational summary finding, and it must be honest about reachability.
	if len(res.Findings) != 1 || res.Findings[0].Severity != state.SeverityInfo {
		t.Fatalf("expected only the info summary finding; got %+v", res.Findings)
	}
	if !strings.Contains(res.Output, "no callbacks") {
		t.Fatalf("summary should flag the null result honestly: %q", res.Output)
	}
}

// The tool must scope confirmation to its OWN probes: a stray hit on a token this
// execution never issued must not surface as a finding.
func TestOOBCheckIgnoresForeignToken(t *testing.T) {
	collab := newCollab()
	// A probe issued by some OTHER run, already called back, sitting in the shared store.
	foreign := collab.Register("ssrf", "http://other.example", "x")
	collab.Record(oob.Hit{Token: foreign.Token, Proto: oob.ProtoHTTP, RemoteAddr: "198.51.100.1:80", Detail: "foreign"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := newWith(collab, 20*time.Millisecond).
		Execute(context.Background(), action.Action{ID: "o3", Target: srv.URL})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.ID, foreign.Token) {
			t.Fatalf("foreign token leaked into this action's findings: %+v", f)
		}
	}
}
