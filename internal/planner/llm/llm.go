// Package llm is the pluggable language-model backend for the planner. The
// interface is deliberately tiny so backends are easy to swap. Ollama (local,
// offline) is the default; Mock is used for tests and dry runs.
package llm

import (
	"context"
	"encoding/json"
)

// Client is a text-in, text-out language model.
type Client interface {
	// Name identifies the backend (for logs and audit).
	Name() string
	// Generate returns the model's completion for the given system+user prompt.
	// Implementations should request JSON output where the backend supports it.
	Generate(ctx context.Context, system, user string) (string, error)
}

// SchemaClient is an optional capability: a backend that can constrain its
// output to a JSON Schema (e.g. Ollama's structured-output / grammar mode). The
// planner uses it when available and falls back to Generate otherwise, so plain
// Client implementations (Mock, test doubles) need not implement it.
type SchemaClient interface {
	GenerateSchema(ctx context.Context, system, user string, schema json.RawMessage) (string, error)
}
