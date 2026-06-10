package templates

import (
	"context"
	"net/http"
	"net/http/httptest"
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
