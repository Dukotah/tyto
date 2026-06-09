// Package audit writes an append-only JSONL record of every decision and action.
// This is the accountability trail you hand the client to prove what was — and
// was not — done, and that the engagement stayed in scope.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Entry is one line in the audit log.
type Entry struct {
	Time time.Time      `json:"time"`
	Kind string         `json:"kind"` // decision | action | result | info
	Data map[string]any `json:"data,omitempty"`
}

// Log is a concurrency-safe append-only writer.
type Log struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewLog writes entries to w.
func NewLog(w io.Writer) *Log {
	return &Log{enc: json.NewEncoder(w)}
}

// Open opens (creating/appending) a JSONL audit file. The returned closer must
// be called when the engagement ends.
func Open(path string) (*Log, func() error, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return NewLog(f), f.Close, nil
}

// Record appends an entry. Encoding errors are ignored to never block the
// engagement on a logging failure (the engine still surfaces results to stdout).
func (l *Log) Record(kind string, data map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(Entry{Time: time.Now().UTC(), Kind: kind, Data: data})
}
