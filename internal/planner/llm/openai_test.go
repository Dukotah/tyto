package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OpenAI must satisfy both the base Client and the optional SchemaClient so the
// planner's structured-output path accepts it.
var (
	_ Client       = (*OpenAI)(nil)
	_ SchemaClient = (*OpenAI)(nil)
)

func TestOpenAIGenerate(t *testing.T) {
	var gotPath, gotAuth string
	var gotReq openAIRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotReq)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"{\"ok\":true}"}}]}`)
	}))
	defer srv.Close()

	c := NewOpenAI(srv.URL+"/v1", "gpt-test", "sk-secret")
	out, err := c.Generate(context.Background(), "reply as json", "do the thing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if out != `{"ok":true}` {
		t.Fatalf("content = %q", out)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %q, want /v1/chat/completions", gotPath)
	}
	if gotAuth != "Bearer sk-secret" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotReq.Model != "gpt-test" {
		t.Errorf("model = %q", gotReq.Model)
	}
	if len(gotReq.Messages) != 2 || gotReq.Messages[0].Role != "system" || gotReq.Messages[1].Role != "user" {
		t.Errorf("messages = %+v", gotReq.Messages)
	}
	// "json" appears in the system prompt, so json_object mode must be set.
	if string(gotReq.ResponseFormat) != `{"type":"json_object"}` {
		t.Errorf("response_format = %q, want json_object", string(gotReq.ResponseFormat))
	}
	if c.Name() != "openai:gpt-test" {
		t.Errorf("name = %q", c.Name())
	}
}

func TestOpenAINoJSONFormatWithoutToken(t *testing.T) {
	var gotReq openAIRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotReq)
		io.WriteString(w, `{"choices":[{"message":{"content":"hi"}}]}`)
	}))
	defer srv.Close()

	// No "json" anywhere in the prompt: we must NOT send json_object (the OpenAI
	// API would reject it), and a local server gets a plain request.
	c := NewOpenAI(srv.URL, "m", "")
	if _, err := c.Generate(context.Background(), "be terse", "say hi"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if gotReq.ResponseFormat != nil {
		t.Errorf("response_format should be omitted, got %q", string(gotReq.ResponseFormat))
	}
}

func TestOpenAIErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"error":{"message":"rate limited"}}`)
	}))
	defer srv.Close()

	c := NewOpenAI(srv.URL, "m", "")
	_, err := c.Generate(context.Background(), "json", "x")
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("want 429 error, got %v", err)
	}
}

func TestNewOpenAIDefaultsAndTrim(t *testing.T) {
	c := NewOpenAI("", "m", "")
	if c.BaseURL != "https://api.openai.com/v1" {
		t.Errorf("default base = %q", c.BaseURL)
	}
	c2 := NewOpenAI("http://localhost:1234/v1/", "m", "")
	if c2.BaseURL != "http://localhost:1234/v1" {
		t.Errorf("trailing slash not trimmed: %q", c2.BaseURL)
	}
}
