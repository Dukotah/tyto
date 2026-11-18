package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAI talks to any server that speaks the OpenAI Chat Completions API. That
// is the de-facto standard, so this one backend covers OpenAI, Groq, Together,
// Mistral, OpenRouter and — crucially for "bring your own model" — every local
// server that exposes an OpenAI-compatible endpoint: LM Studio, vLLM, llama.cpp,
// text-generation-webui, and Ollama's own /v1 shim. Pick the model and base URL
// and the same planner loop runs on all of them.
//
// Unlike the Ollama backend this is NOT inherently offline — if BaseURL points
// at a hosted provider, prompts leave the machine. Point it at a localhost
// server to keep an engagement air-gapped.
type OpenAI struct {
	BaseURL string // e.g. https://api.openai.com/v1 or http://localhost:1234/v1
	Model   string
	APIKey  string // Bearer token; may be empty for local servers that ignore auth
	http    *http.Client
}

// NewOpenAI returns an OpenAI-compatible client. An empty baseURL defaults to the
// public OpenAI endpoint; a trailing slash is trimmed so callers can pass either
// form. The model has no default (the right name is provider-specific) and must
// be supplied by the caller.
func NewOpenAI(baseURL, model, apiKey string) *OpenAI {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return &OpenAI{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Model:   model,
		APIKey:  apiKey,
		http:    &http.Client{Timeout: 240 * time.Second},
	}
}

// Name implements Client.
func (o *OpenAI) Name() string { return "openai:" + o.Model }

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Temperature float64         `json:"temperature"`
	// ResponseFormat is raw JSON so we can send {"type":"json_object"} when we
	// want JSON, or omit it entirely for a free-form chat reply.
	ResponseFormat json.RawMessage `json:"response_format,omitempty"`
}

type openAIResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// jsonObjectFormat is the widely-supported structured-output mode. We prefer it
// over strict json_schema because many OpenAI-compatible servers (local ones in
// particular) implement json_object but not json_schema; the planner already
// embeds its schema in the prompt, so json_object is enough to get valid JSON.
var jsonObjectFormat = json.RawMessage(`{"type":"json_object"}`)

// Generate implements Client, requesting a JSON object.
func (o *OpenAI) Generate(ctx context.Context, system, user string) (string, error) {
	return o.complete(ctx, system, user, true)
}

// GenerateSchema implements SchemaClient. For maximum compatibility across
// OpenAI-compatible servers it uses json_object mode (same as Generate) rather
// than strict json_schema, which is unevenly supported; the planner's prompt
// carries the schema. An empty schema is treated identically.
func (o *OpenAI) GenerateSchema(ctx context.Context, system, user string, schema json.RawMessage) (string, error) {
	return o.complete(ctx, system, user, true)
}

// Chat generates a free-form natural-language reply (no JSON constraint) — for
// the operator-facing console assistant, mirroring Ollama.Chat.
func (o *OpenAI) Chat(ctx context.Context, system, user string) (string, error) {
	return o.complete(ctx, system, user, false)
}

func (o *OpenAI) complete(ctx context.Context, system, user string, wantJSON bool) (string, error) {
	msgs := make([]openAIMessage, 0, 2)
	if system != "" {
		msgs = append(msgs, openAIMessage{Role: "system", Content: system})
	}
	msgs = append(msgs, openAIMessage{Role: "user", Content: user})

	reqBody := openAIRequest{
		Model:       o.Model,
		Messages:    msgs,
		Temperature: 0.2,
	}
	// The OpenAI API rejects json_object mode unless the word "json" appears in
	// the prompt. The planner prompt always asks for JSON, but guard against a
	// hard 400 by only setting the format when that token is present.
	if wantJSON && mentionsJSON(system, user) {
		reqBody.ResponseFormat = jsonObjectFormat
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.APIKey)
	}

	resp, err := o.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai-compatible request to %s failed: %w", o.BaseURL, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai-compatible endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var r openAIResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return "", fmt.Errorf("decode openai response: %w", err)
	}
	if r.Error != nil && r.Error.Message != "" {
		return "", fmt.Errorf("openai error: %s", r.Error.Message)
	}
	if len(r.Choices) == 0 {
		return "", fmt.Errorf("openai response had no choices")
	}
	return r.Choices[0].Message.Content, nil
}

func mentionsJSON(system, user string) bool {
	return strings.Contains(strings.ToLower(system+" "+user), "json")
}
