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
		model = "llama3.1"
	}
	return &Ollama{
		BaseURL: baseURL,
		Model:   model,
		http:    &http.Client{Timeout: 120 * time.Second},
	}
}

// Name implements Client.
func (o *Ollama) Name() string { return "ollama:" + o.Model }

type ollamaRequest struct {
	Model  string `json:"model"`
	System string `json:"system,omitempty"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
	Format string `json:"format,omitempty"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Error    string `json:"error,omitempty"`
}

// Generate implements Client by calling Ollama's /api/generate endpoint with
// JSON-mode output enabled.
func (o *Ollama) Generate(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(ollamaRequest{
		Model:  o.Model,
		System: system,
		Prompt: user,
		Stream: false,
		Format: "json",
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
