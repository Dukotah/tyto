// Package llm is the pluggable language-model backend for the planner. The
// interface is deliberately tiny so backends are easy to swap. Ollama (local,
// offline) is the default; Mock is used for tests and dry runs.
package llm

import "context"

// Client is a text-in, text-out language model.
type Client interface {
	// Name identifies the backend (for logs and audit).
	Name() string
	// Generate returns the model's completion for the given system+user prompt.
	// Implementations should request JSON output where the backend supports it.
	Generate(ctx context.Context, system, user string) (string, error)
}
