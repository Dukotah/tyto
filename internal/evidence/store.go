// Package evidence captures the exact HTTP request/response pairs behind a
// finding and binds them to that finding by its existing ID. A finding records
// *what* was observed; evidence records the *proof* — the literal traffic — so a
// report can show a triager the request tyto sent and the response that confirmed
// the issue.
//
// Evidence is stored separately from state.Finding and keyed by the finding's own
// ID string: nothing in this package mutates or depends on the Finding struct. A
// tool (or the engine) associates one or more evidence records with a finding by
// that ID after the fact.
//
// The capture path is decoupled from storage via a recording http.RoundTripper
// (see roundtripper.go): tyto's HTTP tools make ordinary requests and never learn
// where — or whether — the traffic is stored.
//
// Only the in-memory Store (MemStore) exists today; the Store interface is the
// seam a persistent (sqlstore-backed) implementation would satisfy later.
package evidence

import (
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Record is one captured HTTP request/response pair. Header maps and bodies are
// size-capped and secret-redacted at capture time (see roundtripper.go), so a
// Record is safe to serialize into an operator-facing report. Bodies are kept as
// strings; the *Truncated flags mark where a cap was hit.
type Record struct {
	EvidenceID        string      `json:"evidence_id"`
	FindingID         string      `json:"finding_id,omitempty"`
	Method            string      `json:"method"`
	URL               string      `json:"url"`
	Status            int         `json:"status"`
	RequestHeaders    http.Header `json:"request_headers,omitempty"`
	RequestBody       string      `json:"request_body,omitempty"`
	RequestTruncated  bool        `json:"request_truncated,omitempty"`
	ResponseHeaders   http.Header `json:"response_headers,omitempty"`
	ResponseBody      string      `json:"response_body,omitempty"`
	ResponseTruncated bool        `json:"response_truncated,omitempty"`
	CapturedAt        time.Time   `json:"captured_at"`
}

// Store records HTTP evidence and associates it with findings by finding ID. The
// zero value is not usable; construct a MemStore with NewMemStore. Implementations
// must be safe for concurrent use — tyto runs tools in parallel.
type Store interface {
	// Put stores a record, assigns and returns a fresh evidence ID. Any
	// EvidenceID already set on rec is ignored; the store owns ID assignment.
	Put(rec Record) string
	// Get returns the record for an evidence ID.
	Get(id string) (Record, bool)
	// Associate binds one or more evidence IDs to a finding ID. Unknown or
	// duplicate evidence IDs are ignored. Calling it again adds to the set.
	Associate(findingID string, evidenceIDs ...string)
	// For returns the records associated with a finding ID, each with its
	// FindingID populated, ordered by capture time. It returns nil when the
	// finding has no evidence.
	For(findingID string) []Record
}

// MemStore is an in-memory Store. It is the default for a single engagement run;
// a report is built from it before the process exits.
type MemStore struct {
	mu        sync.RWMutex
	seq       int
	records   map[string]Record
	byFinding map[string][]string
}

// NewMemStore returns an empty in-memory Store.
func NewMemStore() *MemStore {
	return &MemStore{records: map[string]Record{}, byFinding: map[string][]string{}}
}

// Put implements Store.
func (s *MemStore) Put(rec Record) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	id := evidenceID(s.seq)
	rec.EvidenceID = id
	rec.FindingID = "" // association is tracked separately, not on the stored record
	if rec.CapturedAt.IsZero() {
		rec.CapturedAt = time.Now().UTC()
	}
	s.records[id] = rec
	return id
}

// Get implements Store.
func (s *MemStore) Get(id string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[id]
	return rec, ok
}

// Associate implements Store.
func (s *MemStore) Associate(findingID string, evidenceIDs ...string) {
	if findingID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := map[string]bool{}
	for _, id := range s.byFinding[findingID] {
		existing[id] = true
	}
	for _, id := range evidenceIDs {
		if id == "" || existing[id] {
			continue
		}
		if _, ok := s.records[id]; !ok {
			continue // never associate an ID we did not store
		}
		existing[id] = true
		s.byFinding[findingID] = append(s.byFinding[findingID], id)
	}
}

// For implements Store.
func (s *MemStore) For(findingID string) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.byFinding[findingID]
	if len(ids) == 0 {
		return nil
	}
	out := make([]Record, 0, len(ids))
	for _, id := range ids {
		if rec, ok := s.records[id]; ok {
			rec.FindingID = findingID
			out = append(out, rec)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CapturedAt.Before(out[j].CapturedAt) })
	return out
}

// evidenceID formats a sequential evidence identifier. Sequential (not random)
// keeps capture order legible in a report and reproducible in tests.
func evidenceID(seq int) string {
	return "EV-" + strconv.Itoa(seq)
}
