package store

import (
	"path/filepath"
	"testing"

	"github.com/dukotah/tyto/internal/state"
)

func TestSnapshotRoundTrip(t *testing.T) {
	st := state.New()
	st.AddAsset(&state.Asset{ID: "h", Type: "host", Value: "h"})
	st.AddAsset(&state.Asset{ID: "h:80", Type: "service", Value: "h:80", Attrs: map[string]string{"service": "http"}})
	st.AddFinding(state.Finding{Title: "open port", Severity: state.SeverityInfo, Target: "h", Tool: "portscan"})

	path := filepath.Join(t.TempDir(), "e.state.json")
	if err := Save(path, Capture(st, []string{"keyA", "keyB"})); err != nil {
		t.Fatal(err)
	}

	snap, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Assets) != 2 || len(snap.Findings) != 1 || len(snap.CompletedActions) != 2 {
		t.Fatalf("snapshot lost data: %d assets, %d findings, %d actions", len(snap.Assets), len(snap.Findings), len(snap.CompletedActions))
	}

	// Replaying into a fresh state restores it.
	restored := state.New()
	snap.Into(restored)
	if len(restored.Assets()) != 2 || len(restored.Findings()) != 1 {
		t.Fatalf("restore failed: %d assets, %d findings", len(restored.Assets()), len(restored.Findings()))
	}
}

func TestLoadMissingFileErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("loading a missing snapshot should error")
	}
}
