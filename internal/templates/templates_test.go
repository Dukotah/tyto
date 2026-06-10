package templates

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const inlineExample = `
id: exposed-git-config
info:
  name: Exposed .git/config
  severity: high
  description: Version-control metadata is publicly readable.
requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["[core]", "repositoryformatversion"]
        condition: or
`

func TestLoadEmbedded(t *testing.T) {
	tmpls, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if len(tmpls) < 10 {
		t.Fatalf("got %d embedded templates, want >= 10", len(tmpls))
	}
	for _, tmpl := range tmpls {
		if tmpl.ID == "" {
			t.Errorf("template has empty ID: %+v", tmpl)
		}
		if tmpl.Info.Name == "" {
			t.Errorf("template %q has empty Info.Name", tmpl.ID)
		}
		if !ValidSeverity(tmpl.Info.Severity) {
			t.Errorf("template %q has invalid severity %q", tmpl.ID, tmpl.Info.Severity)
		}
		if len(tmpl.Requests) == 0 {
			t.Errorf("template %q has no requests", tmpl.ID)
		}
	}
}

func TestParseInlineExample(t *testing.T) {
	tmpl, err := Parse([]byte(inlineExample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tmpl.ID != "exposed-git-config" {
		t.Errorf("ID = %q, want exposed-git-config", tmpl.ID)
	}
	if tmpl.Info.Severity != "high" {
		t.Errorf("Severity = %q, want high", tmpl.Info.Severity)
	}
	if len(tmpl.Requests) != 1 {
		t.Fatalf("got %d requests, want 1", len(tmpl.Requests))
	}
	req := tmpl.Requests[0]
	if req.Method != "GET" {
		t.Errorf("Method = %q, want GET", req.Method)
	}
	if req.MatchersCondition != "and" {
		t.Errorf("MatchersCondition = %q, want and", req.MatchersCondition)
	}
	if len(req.Matchers) != 2 {
		t.Fatalf("got %d matchers, want 2", len(req.Matchers))
	}
	if req.Matchers[1].Condition != "or" {
		t.Errorf("word matcher condition = %q, want or", req.Matchers[1].Condition)
	}
}

func TestRunMatchAndNoMatch(t *testing.T) {
	const tmplYAML = `
id: test-secret
info:
  name: Test Secret
  severity: high
  description: A test secret file.
requests:
  - method: GET
    path:
      - "{{BaseURL}}/secret.txt"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["TOP-SECRET"]
`
	tmpl, err := Parse([]byte(tmplYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Server that serves the matching path.
	hit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/secret.txt" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("this is TOP-SECRET data"))
			return
		}
		http.NotFound(w, r)
	}))
	defer hit.Close()

	hits, err := tmpl.Run(context.Background(), hit.Client(), hit.URL)
	if err != nil {
		t.Fatalf("Run (hit): %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	wantURL := hit.URL + "/secret.txt"
	if hits[0].URL != wantURL {
		t.Errorf("hit URL = %q, want %q", hits[0].URL, wantURL)
	}
	if hits[0].TemplateID != "test-secret" || hits[0].Severity != "high" {
		t.Errorf("hit metadata wrong: %+v", hits[0])
	}

	// Server that 404s everything.
	miss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer miss.Close()

	hits, err = tmpl.Run(context.Background(), miss.Client(), miss.URL)
	if err != nil {
		t.Fatalf("Run (miss): %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("got %d hits, want 0", len(hits))
	}
}

func TestNegativeMatcher(t *testing.T) {
	// Fires when the body does NOT contain the forbidden word and status is 200.
	const tmplYAML = `
id: test-negative
info:
  name: Test Negative
  severity: low
  description: Negative matcher exercise.
requests:
  - method: GET
    path:
      - "{{BaseURL}}/page"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["maintenance"]
        negative: true
`
	tmpl, err := Parse([]byte(tmplYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Body without "maintenance" -> negative matcher is true -> hit.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome, all systems normal"))
	}))
	defer up.Close()
	hits, err := tmpl.Run(context.Background(), up.Client(), up.URL)
	if err != nil {
		t.Fatalf("Run (up): %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("negative matcher: got %d hits, want 1", len(hits))
	}

	// Body WITH "maintenance" -> negative matcher is false -> no hit.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("down for maintenance"))
	}))
	defer down.Close()
	hits, err = tmpl.Run(context.Background(), down.Client(), down.URL)
	if err != nil {
		t.Fatalf("Run (down): %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("negative matcher: got %d hits, want 0", len(hits))
	}
}

func TestOrMatchersCondition(t *testing.T) {
	// matchers-condition: or -> any matcher firing is enough. Here status is 404
	// (status matcher fails) but the body word matcher fires, so we get a hit.
	const tmplYAML = `
id: test-or
info:
  name: Test Or
  severity: medium
  description: Or matchers-condition exercise.
requests:
  - method: GET
    path:
      - "{{BaseURL}}/x"
    matchers-condition: or
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["NEEDLE"]
`
	tmpl, err := Parse([]byte(tmplYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("contains a NEEDLE in the haystack"))
	}))
	defer srv.Close()

	hits, err := tmpl.Run(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("or condition: got %d hits, want 1", len(hits))
	}
}

func TestBaseURLSubstitution(t *testing.T) {
	// Trailing slash on base must be stripped; resulting URL must be absolute.
	got := substitute("{{BaseURL}}/.git/config", "https://example.com")
	if got != "https://example.com/.git/config" {
		t.Errorf("substitute = %q", got)
	}

	// Verify the actual request URL recorded in a Hit is correct, including
	// stripping a trailing slash on the supplied baseURL.
	const tmplYAML = `
id: test-url
info:
  name: Test URL
  severity: info
  description: URL substitution check.
requests:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: status
        status: [200]
`
	tmpl, err := Parse([]byte(tmplYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hits, err := tmpl.Run(context.Background(), srv.Client(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	if hits[0].URL != srv.URL+"/probe" {
		t.Errorf("hit URL = %q, want %q", hits[0].URL, srv.URL+"/probe")
	}
}

func TestParseHTTPKey(t *testing.T) {
	// Newer nuclei templates use the `http:` key instead of `requests:`.
	const httpKey = `
id: http-key-template
info:
  name: HTTP Key Template
  severity: medium
  description: Uses the newer http key.
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status: [200]
`
	tmpl, err := Parse([]byte(httpKey))
	if err != nil {
		t.Fatalf("Parse http-key: %v", err)
	}
	if tmpl.ID != "http-key-template" {
		t.Errorf("ID = %q", tmpl.ID)
	}
	if len(tmpl.Requests) != 1 {
		t.Fatalf("got %d requests, want 1", len(tmpl.Requests))
	}
	if got := tmpl.Requests[0].Path; len(got) != 1 || got[0] != "{{BaseURL}}/admin" {
		t.Errorf("path = %v", got)
	}
}

func TestParseDropsUnsupportedMatchers(t *testing.T) {
	// A request with one supported (status) and one unsupported (dsl) matcher
	// keeps only the supported matcher.
	const mixed = `
id: mixed-matchers
info:
  name: Mixed
  severity: low
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: status
        status: [200]
      - type: dsl
        dsl: ["len(body) > 0"]
`
	tmpl, err := Parse([]byte(mixed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(tmpl.Requests) != 1 {
		t.Fatalf("got %d requests, want 1", len(tmpl.Requests))
	}
	if len(tmpl.Requests[0].Matchers) != 1 {
		t.Fatalf("got %d matchers, want 1 (dsl dropped)", len(tmpl.Requests[0].Matchers))
	}
	if tmpl.Requests[0].Matchers[0].Type != "status" {
		t.Errorf("kept matcher = %q, want status", tmpl.Requests[0].Matchers[0].Type)
	}
}

func TestParseUnsupportedTemplate(t *testing.T) {
	// A dsl-only template has no runnable matcher -> ErrUnsupported.
	const dslOnly = `
id: dsl-only
info:
  name: DSL only
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: dsl
        dsl: ["true"]
`
	if _, err := Parse([]byte(dslOnly)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("dsl-only: err = %v, want ErrUnsupported", err)
	}

	// A raw: request is an unsupported transport -> ErrUnsupported.
	const rawReq = `
id: raw-req
info:
  name: Raw
  severity: info
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: status
        status: [200]
`
	if _, err := Parse([]byte(rawReq)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("raw: err = %v, want ErrUnsupported", err)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()

	httpTmpl := `
id: http-tmpl
info:
  name: HTTP Tmpl
  severity: high
http:
  - method: GET
    path: ["{{BaseURL}}/a"]
    matchers:
      - type: status
        status: [200]
`
	requestsTmpl := `
id: requests-tmpl
info:
  name: Requests Tmpl
  severity: medium
requests:
  - method: GET
    path: ["{{BaseURL}}/b"]
    matchers:
      - type: word
        words: ["needle"]
`
	unsupportedTmpl := `
id: dsl-tmpl
info:
  name: DSL Tmpl
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/c"]
    matchers:
      - type: dsl
        dsl: ["true"]
`
	mustWrite(t, filepath.Join(dir, "http.yaml"), httpTmpl)
	mustWrite(t, filepath.Join(dir, "requests.yml"), requestsTmpl)
	// Nested dir to exercise recursion.
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(sub, "dsl.yaml"), unsupportedTmpl)
	// A .git dir that must be skipped (contents would otherwise count).
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(gitDir, "junk.yaml"), "not: valid: yaml: [")

	loaded, skipped, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded = %d, want 2", len(loaded))
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}

	// The http: template parsed its request.
	var httpT *Template
	for i := range loaded {
		if loaded[i].ID == "http-tmpl" {
			httpT = &loaded[i]
		}
	}
	if httpT == nil {
		t.Fatalf("http-tmpl not loaded; got %+v", loaded)
	}
	if len(httpT.Requests) != 1 || len(httpT.Requests[0].Path) != 1 || httpT.Requests[0].Path[0] != "{{BaseURL}}/a" {
		t.Errorf("http-tmpl request not parsed: %+v", httpT.Requests)
	}
}

func TestLoadDirMissing(t *testing.T) {
	loaded, skipped, err := LoadDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("LoadDir(missing) err = %v, want nil", err)
	}
	if loaded != nil || skipped != 0 {
		t.Fatalf("LoadDir(missing) = (%v, %d), want (nil, 0)", loaded, skipped)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			_, _ = w.Write([]byte("APP_KEY=base64:abcd\nDB_PASSWORD=hunter2"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	tmpls, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	hits := RunAll(context.Background(), srv.Client(), srv.URL, tmpls)
	found := false
	for _, h := range hits {
		if h.TemplateID == "exposed-env-file" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RunAll did not detect exposed .env; hits=%+v", hits)
	}
}
