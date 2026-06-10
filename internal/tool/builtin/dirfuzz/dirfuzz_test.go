package dirfuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// stableNotFound is the body returned for every non-existent path (including
// the soft-404 probe), so the baseline is consistent.
const stableNotFound = "<html><body><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p></body></html>"

func run(t *testing.T, target string, params map[string]string) action.Result {
	t.Helper()
	res, err := New().Execute(context.Background(), action.Action{
		ID:     "t1",
		Tool:   "dirfuzz",
		Target: target,
		Params: params,
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	return res
}

func findingTitles(res action.Result) map[string]state.Finding {
	m := map[string]state.Finding{}
	for _, f := range res.Findings {
		m[f.Title] = f
	}
	return m
}

func TestDiscovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/.git/config":
			w.WriteHeader(200)
			_, _ = w.Write([]byte("OK: " + r.URL.Path + " exists, here is some content."))
		case "/login":
			w.Header().Set("Location", "/dashboard")
			w.WriteHeader(302)
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(stableNotFound))
		}
	}))
	defer srv.Close()

	res := run(t, srv.URL, nil)
	if !res.Success {
		t.Fatalf("expected success, got Err=%q", res.Err)
	}

	titles := findingTitles(res)
	want := []string{
		"Discovered: /admin (HTTP 200)",
		"Discovered: /.git/config (HTTP 200)",
		"Discovered: /login (HTTP 302)",
	}
	for _, wt := range want {
		if _, ok := titles[wt]; !ok {
			t.Errorf("missing expected finding %q; got findings: %v", wt, keys(titles))
		}
	}

	// .git/config must be bumped to Low (sensitive); admin/login generic -> Info.
	if f := titles["Discovered: /.git/config (HTTP 200)"]; f.Severity != state.SeverityLow {
		t.Errorf(".git/config severity = %s, want low", f.Severity)
	}
	if f := titles["Discovered: /admin (HTTP 200)"]; f.Severity != state.SeverityInfo {
		t.Errorf("admin severity = %s, want info", f.Severity)
	}

	// Random misses must not be reported.
	for title := range titles {
		if strings.Contains(title, soft404Probe) {
			t.Errorf("reported the soft-404 probe path: %q", title)
		}
	}
	if len(res.Findings) != 3 {
		t.Errorf("expected exactly 3 findings, got %d: %v", len(res.Findings), keys(titles))
	}

	// Endpoint assets for 200/3xx hits (admin, .git/config, login).
	assetVals := map[string]string{}
	for _, as := range res.Assets {
		if as.Type != "endpoint" {
			t.Errorf("asset %q has type %q, want endpoint", as.Value, as.Type)
		}
		assetVals[as.Value] = as.Attrs["status"]
	}
	for _, suffix := range []string{"/admin", "/.git/config", "/login"} {
		if _, ok := assetVals[srv.URL+suffix]; !ok {
			t.Errorf("missing endpoint asset for %s; got %v", suffix, assetVals)
		}
	}
	if len(res.Assets) != 3 {
		t.Errorf("expected 3 endpoint assets, got %d", len(res.Assets))
	}
}

func TestSoft404CatchAll(t *testing.T) {
	// Server returns 200 with the SAME body for everything (a soft-404 trap).
	const sameBody = "<html><body>Welcome — this is the single-page app shell.</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(sameBody))
	}))
	defer srv.Close()

	res := run(t, srv.URL, nil)
	if !res.Success {
		t.Fatalf("expected success, got Err=%q", res.Err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("soft-404 catch-all should yield no findings, got %d: %v",
			len(res.Findings), keys(findingTitles(res)))
	}
	if len(res.Assets) != 0 {
		t.Errorf("soft-404 catch-all should yield no assets, got %d", len(res.Assets))
	}
}

func TestConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := srv.URL
	srv.Close() // now unreachable

	res := run(t, addr, nil)
	if res.Err == "" {
		t.Error("expected res.Err on unreachable base")
	}
	if res.Output == "" {
		t.Error("expected res.Output describing the failure")
	}
}

func TestExternalWordlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/onlyword" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("found onlyword content"))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(stableNotFound))
	}))
	defer srv.Close()

	wl := t.TempDir() + "/wl.txt"
	if err := os.WriteFile(wl, []byte("# comment\nonlyword\nmissingword\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res := run(t, srv.URL, map[string]string{"wordlist": wl})
	if !res.Success {
		t.Fatalf("expected success, got Err=%q", res.Err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Title != "Discovered: /onlyword (HTTP 200)" {
		t.Errorf("external wordlist: want single onlyword hit, got %v", keys(findingTitles(res)))
	}
}

func TestEmbeddedWordlistLoads(t *testing.T) {
	words, err := loadWords("")
	if err != nil {
		t.Fatalf("loadWords: %v", err)
	}
	if len(words) < 150 {
		t.Errorf("embedded wordlist smaller than expected: %d entries", len(words))
	}
	for _, w := range words {
		if strings.HasPrefix(w, "/") || strings.HasPrefix(w, "#") || strings.TrimSpace(w) == "" {
			t.Errorf("bad wordlist entry %q", w)
		}
	}
	t.Logf("embedded wordlist entries: %d", len(words))
}

func keys(m map[string]state.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
