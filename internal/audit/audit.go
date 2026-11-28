// Package audit writes an append-only, hash-chained JSONL record of every
// decision and action. This is the accountability trail you hand the client to
// prove what was — and was not — done, and that the engagement stayed in scope.
//
// Tamper-evidence: each entry carries a Seq, the previous entry's Hash, and its
// own Hash = SHA256 over its chained fields. Editing or deleting any past entry
// breaks the chain at that point, which a verifier detects. Honest framing: on a
// single offline machine the operator can still rewrite the whole file from
// scratch — what the chain guarantees is that the log is *not silently
// self-modifiable in place* and that any tampering is *detectable*, not that it
// is impossible. Writes fail CLOSED: a write error is returned, never swallowed,
// so the engine can halt rather than act without an audit record.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// GenesisHash is the PrevHash of the first entry in a chain.
const GenesisHash = "GENESIS"

// Entry is one line in the audit log.
type Entry struct {
	Seq      uint64         `json:"seq"`
	Time     time.Time      `json:"time"`
	Kind     string         `json:"kind"` // decision | action | result | approval | info
	Data     map[string]any `json:"data,omitempty"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

// Approval is the typed per-action human sign-off record. It is distinct from the
// engagement-level Authorization (who approved the whole test): this records who
// approved one specific high-consequence action and what the guard said about it.
type Approval struct {
	Approver    string
	ApprovedAt  time.Time
	ActionID    string
	GuardReason string
	Approved    bool
}

// Log is a concurrency-safe, append-only, hash-chained writer.
type Log struct {
	mu       sync.Mutex
	enc      *json.Encoder
	syncer   interface{ Sync() error } // non-nil when the sink can fsync (a file)
	seq      uint64
	prevHash string
}

// NewLog writes entries to w, starting a fresh chain at the genesis hash. If w can
// fsync (i.e. it is a file), each record is durably flushed — see Record.
func NewLog(w io.Writer) *Log {
	l := &Log{enc: json.NewEncoder(w), prevHash: GenesisHash}
	if s, ok := w.(interface{ Sync() error }); ok {
		l.syncer = s
	}
	return l
}

// Open opens (creating/appending) a JSONL audit file. If the file already has
// entries, the chain is resumed from the last one so appends continue it across
// process restarts. A corrupt trailing entry is a hard error (fail closed). The
// returned closer must be called when the engagement ends.
func Open(path string) (*Log, func() error, error) {
	seq, prev := uint64(0), GenesisHash
	if data, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(data)) > 0 {
		lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
		var last Entry
		if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil {
			return nil, nil, fmt.Errorf("audit log %s is corrupt (last entry unreadable): %w", path, err)
		}
		seq, prev = last.Seq+1, last.Hash
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	l := NewLog(f)
	l.seq, l.prevHash = seq, prev
	return l, f.Close, nil
}

// Record appends a hash-chained entry. It returns any write/encode error instead
// of swallowing it: the audit trail is load-bearing, so the caller must be able
// to fail closed. The chain is only advanced after a successful write.
func (l *Log) Record(kind string, data map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{Seq: l.seq, Time: time.Now().UTC(), Kind: kind, Data: data, PrevHash: l.prevHash}
	e.Hash = hashEntry(e)
	if err := l.enc.Encode(e); err != nil {
		return fmt.Errorf("audit: write entry %d: %w", e.Seq, err)
	}
	// Fail closed on a durability failure: an entry the OS hasn't committed to disk
	// is not a real audit record. fsync per entry guarantees a crash can't silently
	// drop the trailing (pre-crash) records while leaving an intact-looking chain.
	if l.syncer != nil {
		if err := l.syncer.Sync(); err != nil {
			return fmt.Errorf("audit: fsync entry %d: %w", e.Seq, err)
		}
	}
	// Advance the chain only after the entry is durably written.
	l.seq++
	l.prevHash = e.Hash
	return nil
}

// RecordApproval chains a typed per-action approval entry.
func (l *Log) RecordApproval(ap Approval) error {
	return l.Record("approval", map[string]any{
		"approver":     ap.Approver,
		"approved_at":  ap.ApprovedAt.UTC(),
		"action_id":    ap.ActionID,
		"guard_reason": ap.GuardReason,
		"approved":     ap.Approved,
	})
}

// Head returns the current chain head (the latest entry's Hash, or GenesisHash on
// a fresh log). Print/anchor it to bind the trail to a point in time.
func (l *Log) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.prevHash
}

// hashEntry is the SHA256 hex over the canonical JSON of an entry's chained
// fields (everything except Hash itself). encoding/json sorts map keys, so this
// is deterministic.
func hashEntry(e Entry) string {
	chained := struct {
		Seq      uint64         `json:"seq"`
		Time     time.Time      `json:"time"`
		Kind     string         `json:"kind"`
		Data     map[string]any `json:"data,omitempty"`
		PrevHash string         `json:"prev_hash"`
	}{e.Seq, e.Time, e.Kind, e.Data, e.PrevHash}
	b, _ := json.Marshal(chained)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// RedactSecret turns a secret into a loggable handle: a stable SHA256 and the
// last 4 characters, never the plaintext. Use it for anything sensitive that
// must be referenced in the audit trail.
func RedactSecret(v string) map[string]any {
	sum := sha256.Sum256([]byte(v))
	last4 := v
	if len(v) > 4 {
		last4 = v[len(v)-4:]
	}
	return map[string]any{
		"handle": "redacted",
		"sha256": hex.EncodeToString(sum[:]),
		"last4":  last4,
	}
}

// ReadFile loads every entry of a JSONL audit log, in order. It does not check
// the hash chain — call Verify for that. Blank lines are skipped; a line that is
// not a valid entry is a hard error (fail closed: a consumer must never build on
// a partially-understood trail).
func ReadFile(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit: read %s: %w", path, err)
	}
	var entries []Entry
	for i, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("audit: %s line %d is not a valid entry: %w", path, i+1, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Verify checks the hash chain over entries: sequence numbers are contiguous from
// 0, each PrevHash matches the previous entry's Hash (GenesisHash for the first),
// and each Hash matches the recomputed hash of its chained fields. It returns nil
// for an intact chain and an error naming the first broken entry otherwise.
func Verify(entries []Entry) error {
	prev := GenesisHash
	for i, e := range entries {
		if e.Seq != uint64(i) {
			return fmt.Errorf("audit: chain broken at position %d: seq is %d (an entry was removed or reordered)", i, e.Seq)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("audit: chain broken at seq %d: prev_hash does not match the preceding entry", e.Seq)
		}
		if got := hashEntry(e); got != e.Hash {
			return fmt.Errorf("audit: chain broken at seq %d: entry content does not match its hash (modified after writing)", e.Seq)
		}
		prev = e.Hash
	}
	return nil
}
