package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Ollama talks to a local Ollama server over HTTP. No data leaves the machine.
type Ollama struct {
	BaseURL string
	Model   string
	http    *http.Client
}

// NewOllama returns an Ollama client. Empty args fall back to sensible defaults.
func NewOllama(baseURL, model string) *Ollama {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "qwen3:14b"
	}
	return &Ollama{
		BaseURL: baseURL,
		Model:   model,
		http:    &http.Client{Timeout: 240 * time.Second},
	}
}

// Name implements Client.
func (o *Ollama) Name() string { return "ollama:" + o.Model }

type ollamaRequest struct {
	Model  string `json:"model"`
	System string `json:"system,omitempty"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
	// Format is raw JSON: the string "json" for a plain JSON hint, or a full JSON
	// Schema object, which Ollama compiles to a GBNF grammar (structured output).
	Format json.RawMessage `json:"format,omitempty"`
	// Think toggles the reasoning pass on "thinking" models (qwen3, etc.). We set
	// it false so planning skips the long <think> stream — far faster on CPU and
	// it keeps the structured-output grammar clean. Ignored by non-thinking models.
	Think *bool `json:"think,omitempty"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Error    string `json:"error,omitempty"`
}

// Generate implements Client by calling Ollama with a plain JSON-mode hint.
func (o *Ollama) Generate(ctx context.Context, system, user string) (string, error) {
	return o.generate(ctx, system, user, json.RawMessage(`"json"`))
}

// GenerateSchema implements SchemaClient: it sends the JSON Schema as the format,
// which Ollama turns into a token-level grammar so the output is valid by
// construction. An empty schema falls back to the plain JSON hint.
func (o *Ollama) GenerateSchema(ctx context.Context, system, user string, schema json.RawMessage) (string, error) {
	if len(schema) == 0 {
		return o.Generate(ctx, system, user)
	}
	return o.generate(ctx, system, user, schema)
}

func (o *Ollama) generate(ctx context.Context, system, user string, format json.RawMessage) (string, error) {
	noThink := false
	body, err := json.Marshal(ollamaRequest{
		Model:  o.Model,
		System: system,
		Prompt: user,
		Stream: false,
		Format: format,
		Think:  &noThink,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.BaseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request failed (is `ollama serve` running?): %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(data))
	}

	var r ollamaResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return "", fmt.Errorf("decode ollama response: %w", err)
	}
	if r.Error != "" {
		return "", fmt.Errorf("ollama error: %s", r.Error)
	}
	return r.Response, nil
}
