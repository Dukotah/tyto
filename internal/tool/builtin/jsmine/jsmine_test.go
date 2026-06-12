package jsmine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// appServer serves an index page that loads a same-host bundle; the bundle holds
// API routes, a query-param'd URL, and an exposed key — exactly what a SPA ships.
func appServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><head><script src="/static/app.js"></script></head><body>hi</body></html>`))
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`
			const API = "/api/v1/users";
			fetch("/api/orders?id=1&status=open");
			const key = "AKIAIOSFODNN7EXAMPLE";
			const css = "/styles/main.css";   // should be filtered (static)
		`))
	})
	return httptest.NewServer(mux)
}

func has(assets []state.Asset, substr string) bool {
	for _, a := range assets {
		if strings.Contains(a.Value, substr) {
			return true
		}
	}
	return false
}

func TestJSMineExtractsEndpointsParamsSecrets(t *testing.T) {
	srv := appServer(t)
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "j1", Target: srv.URL})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success {
		t.Fatalf("Success=false (out=%q err=%q)", res.Output, res.Err)
	}

	// The param-bearing URL must surface as a testable endpoint (params preserved).
	if !has(res.Assets, "/api/orders") {
		t.Fatalf("did not emit the param-bearing /api/orders endpoint: %+v", res.Assets)
	}
	// A bare API path becomes testable by synthesizing mined params onto it.
	if !has(res.Assets, "/api/v1/users") {
		t.Fatalf("did not emit the mined /api/v1/users endpoint: %+v", res.Assets)
	}
	// Static asset paths must NOT become endpoints.
	if has(res.Assets, "main.css") {
		t.Fatalf("static .css path leaked into endpoints: %+v", res.Assets)
	}
	// Every emitted endpoint must be an `endpoint` asset (the injection-loop shape).
	for _, a := range res.Assets {
		if a.Type != "endpoint" {
			t.Fatalf("asset %q has type %q, want endpoint", a.Value, a.Type)
		}
	}

	// The exposed AWS key must be reported as a high-severity finding, redacted.
	var found bool
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "AWS access key") {
			found = true
			if f.Severity != state.SeverityHigh {
				t.Errorf("AWS key finding severity = %v, want High", f.Severity)
			}
			if strings.Contains(f.Evidence, "AKIAIOSFODNN7EXAMPLE") {
				t.Errorf("evidence leaked the full secret (should be redacted): %q", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("AWS key in JS was not reported; findings=%v", titles(res.Findings))
	}
}

func TestJSMineFetchFailureIsNotFatal(t *testing.T) {
	res, err := New().Execute(context.Background(), action.Action{ID: "j2", Target: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("a fetch failure should not be a tool error: %v", err)
	}
	if res.Success {
		t.Fatal("mining a dead host should not report success")
	}
}

// noisyServer ships a bundle laced with the exact minified-JS noise the live
// copperbaytech run mis-mined: ternary-assignment "params" (n.href, M), bundler
// internal paths (/ROOT/node_modules/...), and Next pseudo-routes (/_tree). A real
// route (/about) and a real form param (email) sit alongside them and must survive.
func noisyServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><head><script src="/static/min.js"></script></head><body>hi</body></html>`))
	})
	mux.HandleFunc("/static/min.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`
			e?n.href=t:0; var x=c?M=1:T=2; a.listener=f;
			fetch("/ROOT/node_modules/next/dist/compiled/process/");
			r("/_tree"); r("/_head");
			const real = "/about";
			fetch("/api/contact?email=1&name=2");
		`))
	})
	return httptest.NewServer(mux)
}

func TestJSMineFiltersMinifiedNoise(t *testing.T) {
	srv := noisyServer(t)
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "j3", Target: srv.URL})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Bundler internals and framework pseudo-routes must NOT become endpoints.
	for _, junk := range []string{"node_modules", "/ROOT/", "/_tree", "/_head"} {
		if has(res.Assets, junk) {
			t.Errorf("noise path %q leaked into endpoints: %+v", junk, assetVals(res.Assets))
		}
	}
	// The real route and the real param-bearing endpoint must survive.
	if !has(res.Assets, "/about") {
		t.Errorf("real route /about was dropped: %+v", assetVals(res.Assets))
	}
	if !has(res.Assets, "/api/contact") {
		t.Errorf("real /api/contact endpoint was dropped: %+v", assetVals(res.Assets))
	}
	// Minified-identifier params (n.href, a.listener, lone-uppercase M/T) must be
	// filtered; the real form params must remain.
	for _, a := range res.Assets {
		for _, bad := range []string{"n.href", "a.listener", "M=", "T="} {
			if strings.Contains(a.Value, bad) {
				t.Errorf("minified param %q leaked onto endpoint %q", bad, a.Value)
			}
		}
	}
	if !isPlausibleParam("email") || !isPlausibleParam("company_website") {
		t.Error("real form params must be considered plausible")
	}
	if isPlausibleParam("a.listener") || isPlausibleParam("M") || isPlausibleParam("n.href") {
		t.Error("minified identifiers must be rejected as params")
	}
}

func assetVals(as []state.Asset) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.Value
	}
	return out
}

func titles(fs []state.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Title
	}
	return out
}
