package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/engine"
)

// scriptedSchema is a SchemaClient test double that returns canned step JSON in
// order, ignoring the prompt — enough to drive the operator loop deterministically.
type scriptedSchema struct {
	steps []string
	i     int
}

func (s *scriptedSchema) Name() string { return "scripted" }
func (s *scriptedSchema) Generate(context.Context, string, string) (string, error) {
	return s.next(), nil
}
func (s *scriptedSchema) GenerateSchema(context.Context, string, string, json.RawMessage) (string, error) {
	return s.next(), nil
}
func (s *scriptedSchema) next() string {
	if s.i >= len(s.steps) {
		return `{"action":"done","summary":"out of script"}`
	}
	r := s.steps[s.i]
	s.i++
	return r
}

// collect drains the broadcast history into the messages it streamed.
func (c *console) feedMessages() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, e := range c.history {
		out = append(out, e.Message)
	}
	return out
}

func newOperatorConsole() *console {
	return &console{subs: map[chan engine.Event]struct{}{}, pending: map[string]chan bool{}}
}

func TestOperator_RunsReadOnlyAndFinishes(t *testing.T) {
	c := newOperatorConsole()
	client := &scriptedSchema{steps: []string{
		`{"thought":"check the wordlists dir","action":"shell","command":"echo rockyou.txt"}`,
		`{"action":"done","summary":"rockyou.txt is present"}`,
	}}
	c.runOperator(context.Background(), "is rockyou here", client)

	msgs := strings.Join(c.feedMessages(), "\n")
	if !strings.Contains(msgs, "$ echo rockyou.txt") {
		t.Errorf("expected the read-only command to be streamed; got:\n%s", msgs)
	}
	if !strings.Contains(msgs, "rockyou.txt is present") {
		t.Errorf("expected the done summary; got:\n%s", msgs)
	}
	if c.operatorCancel != nil {
		t.Errorf("operatorCancel should be cleared after the loop returns")
	}
}

func TestOperator_BlocksMutatingWhenLockedDown(t *testing.T) {
	c := newOperatorConsole() // operatorFreeRun defaults false
	client := &scriptedSchema{steps: []string{
		`{"thought":"delete something","action":"shell","command":"rm -rf /tmp/whatever"}`,
		`{"action":"done","summary":"gave up"}`,
	}}
	c.runOperator(context.Background(), "clean up", client)

	msgs := strings.Join(c.feedMessages(), "\n")
	if !strings.Contains(msgs, "BLOCKED") {
		t.Errorf("expected the mutating command to be BLOCKED with free-run off; got:\n%s", msgs)
	}
}

func TestOperator_FreeRunAllowsMutating(t *testing.T) {
	c := newOperatorConsole()
	c.operatorFreeRun = true
	client := &scriptedSchema{steps: []string{
		// Harmless but non-read-only (redirect) so it only runs under free-run.
		`{"action":"shell","command":"echo hi > /dev/null"}`,
		`{"action":"done","summary":"done"}`,
	}}
	c.runOperator(context.Background(), "write a thing", client)

	msgs := strings.Join(c.feedMessages(), "\n")
	if strings.Contains(msgs, "BLOCKED") {
		t.Errorf("free-run should not block a mutating command; got:\n%s", msgs)
	}
}
