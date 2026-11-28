// Package store persists an engagement's progress so a run can be resumed after
// a restart. It is a dep-free JSON snapshot of discovered assets, findings, and
// the canonical keys of completed actions (so resume doesn't re-run them).
//
// Roadmap note: a relational SQLite store (ncruces/go-sqlite3, no-CGO) replaces
// this when host→service→vuln querying and the AD attack-graph need it; the
// snapshot shape here is the migration source.
package store

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dukotah/tyto/internal/state"
)

// Snapshot is the serializable state of an engagement in progress.
type Snapshot struct {
	Assets           []*state.Asset  `json:"assets"`
	Findings         []state.Finding `json:"findings"`
	CompletedActions []string        `json:"completed_actions"`
	// Defenses are the defensive reactions observed so far, so a resumed run's
	// report still shows what the earlier session ran into.
	Defenses []state.DefenseObservation `json:"defenses,omitempty"`
}

// Capture builds a snapshot from live state plus the engine's completed-action
// keys.
func Capture(st *state.State, completedActions []string) Snapshot {
	return Snapshot{
		Assets:           st.Assets(),
		Findings:         st.Findings(),
		CompletedActions: completedActions,
		Defenses:         st.Defenses(),
	}
}

// Into replays a snapshot into a State (assets + findings; dedup-safe).
func (s Snapshot) Into(st *state.State) {
	for _, a := range s.Assets {
		st.AddAsset(a)
	}
	for _, f := range s.Findings {
		st.AddFinding(f)
	}
	for _, d := range s.Defenses {
		st.ObserveDefense(d)
	}
}

// Save writes the snapshot to path (0600 — it may reference sensitive targets).
func Save(path string, s Snapshot) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Load reads a snapshot from path.
func Load(path string) (Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return Snapshot{}, fmt.Errorf("parse state snapshot %s: %w", path, err)
	}
	return s, nil
}
