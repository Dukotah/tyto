package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainLinksEntries(t *testing.T) {
	var buf bytes.Buffer
	l := NewLog(&buf)
	if l.Head() != GenesisHash {
		t.Fatalf("fresh log head = %q, want %q", l.Head(), GenesisHash)
	}
	for i := 0; i < 3; i++ {
		if err := l.Record("info", map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	entries := decodeAll(t, buf.Bytes())
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(entries))
	}
	if entries[0].Seq != 0 || entries[0].PrevHash != GenesisHash {
		t.Fatalf("entry 0 not seeded from genesis: %+v", entries[0])
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].Seq != uint64(i) {
			t.Errorf("entry %d Seq = %d", i, entries[i].Seq)
		}
		if entries[i].PrevHash != entries[i-1].Hash {
			t.Errorf("entry %d PrevHash does not chain to entry %d Hash", i, i-1)
		}
	}
	if l.Head() != entries[2].Hash {
		t.Fatalf("Head() = %q, want last entry hash %q", l.Head(), entries[2].Hash)
	}
}

func TestHashDeterministicAndDataSensitive(t *testing.T) {
	e := Entry{Seq: 1, Kind: "info", Data: map[string]any{"a": "b"}, PrevHash: "x"}
	if hashEntry(e) != hashEntry(e) {
		t.Fatal("hashEntry not deterministic")
	}
	e2 := e
	e2.Data = map[string]any{"a": "c"}
	if hashEntry(e) == hashEntry(e2) {
		t.Fatal("changing Data must change the hash")
	}
}

func TestTamperBreaksChain(t *testing.T) {
	var buf bytes.Buffer
	l := NewLog(&buf)
	for i := 0; i < 3; i++ {
		_ = l.Record("info", map[string]any{"n": i})
	}
	entries := decodeAll(t, buf.Bytes())
	// Tamper with the middle entry's data and recompute its (now different) hash.
	entries[1].Data = map[string]any{"n": 99}
	tampered := hashEntry(entries[1])
	if tampered == entries[1].Hash {
		t.Fatal("expected tampered hash to differ")
	}
	// The link is now broken: entry 2 still points at the ORIGINAL hash of entry 1.
	if entries[2].PrevHash == tampered {
		t.Fatal("chain should not validate after tampering")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRecordFailsClosed(t *testing.T) {
	l := NewLog(failingWriter{})
	if err := l.Record("info", map[string]any{"x": 1}); err == nil {
		t.Fatal("Record must return an error when the write fails, not swallow it")
	}
}

func TestOpenResumesChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "e.audit.jsonl")

	l1, close1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = l1.Record("info", map[string]any{"n": 0})
	_ = l1.Record("info", map[string]any{"n": 1})
	head := l1.Head()
	_ = close1()

	l2, close2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer close2()
	if err := l2.Record("info", map[string]any{"n": 2}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	entries := decodeAll(t, data)
	if len(entries) != 3 {
		t.Fatalf("want 3 entries after resume, got %d", len(entries))
	}
	if entries[2].Seq != 2 {
		t.Errorf("resumed entry Seq = %d, want 2", entries[2].Seq)
	}
	if entries[2].PrevHash != head {
		t.Errorf("resumed entry does not chain to the pre-restart head")
	}
}

func TestRecordApproval(t *testing.T) {
	var buf bytes.Buffer
	l := NewLog(&buf)
	if err := l.RecordApproval(Approval{Approver: "op", ActionID: "a1", GuardReason: "exploit needs sign-off", Approved: false}); err != nil {
		t.Fatal(err)
	}
	e := decodeAll(t, buf.Bytes())[0]
	if e.Kind != "approval" {
		t.Fatalf("kind = %q, want approval", e.Kind)
	}
	if e.Data["approver"] != "op" || e.Data["action_id"] != "a1" || e.Data["approved"] != false {
		t.Fatalf("approval data not recorded faithfully: %+v", e.Data)
	}
}

func TestRedactSecret(t *testing.T) {
	r := RedactSecret("hunter2")
	for k, v := range r {
		if v == "hunter2" {
			t.Fatalf("RedactSecret leaked the plaintext in field %q", k)
		}
	}
	if r["last4"] != "ter2" {
		t.Errorf("last4 = %v, want ter2", r["last4"])
	}
	if s, _ := r["sha256"].(string); len(s) != 64 {
		t.Errorf("sha256 hex length = %d, want 64", len(s))
	}
}

func decodeAll(t *testing.T, b []byte) []Entry {
	t.Helper()
	var out []Entry
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}
