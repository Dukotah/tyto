package sqlstore

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/state"
)

// buildState returns a State seeded with 2 assets (one carrying Attrs) and 2
// findings (one with CVSS + Validated), plus the completed-action keys to save.
func buildState() (*state.State, []string) {
	st := state.New()
	st.AddAsset(&state.Asset{
		ID:        "asset-1",
		Type:      "host",
		Value:     "10.0.0.1",
		FirstSeen: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	st.AddAsset(&state.Asset{
		ID:        "asset-2",
		Type:      "service",
		Value:     "10.0.0.1:443",
		Attrs:     map[string]string{"product": "nginx", "version": "1.25.3"},
		FirstSeen: time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC),
	})

	st.AddFinding(state.Finding{
		ID:          "find-1",
		Title:       "Open SSH",
		Severity:    state.SeverityInfo,
		Target:      "10.0.0.1",
		Description: "port 22 open",
		Tool:        "nmap",
		FoundAt:     time.Date(2026, 1, 2, 4, 0, 0, 0, time.UTC),
	})
	st.AddFinding(state.Finding{
		ID:          "find-2",
		Title:       "Heartbleed",
		Severity:    state.SeverityCritical,
		Target:      "10.0.0.1:443",
		Description: "TLS memory disclosure",
		Evidence:    "raw tool output",
		Tool:        "nuclei",
		CVSS:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Validated:   true,
		FoundAt:     time.Date(2026, 1, 2, 4, 1, 0, 0, time.UTC),
	})

	return st, []string{"nmap:10.0.0.1", "nuclei:10.0.0.1:443"}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engagement.db")
	const eng = "eng-A"

	st, completed := buildState()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.SaveState(eng, st, completed); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen the same DB file to prove persistence, not in-memory caching.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen Open: %v", err)
	}
	defer s2.Close()

	assets, findings, keys, err := s2.LoadState(eng)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	if len(assets) != 2 {
		t.Fatalf("assets = %d, want 2", len(assets))
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	if len(keys) != 2 {
		t.Fatalf("completed keys = %d, want 2", len(keys))
	}

	// Attrs map round-trip (assets ordered by id).
	byID := map[string]*state.Asset{}
	for _, a := range assets {
		byID[a.ID] = a
	}
	a2 := byID["asset-2"]
	if a2 == nil {
		t.Fatal("asset-2 missing")
	}
	if got := a2.Attrs["product"]; got != "nginx" {
		t.Errorf("asset-2 Attrs[product] = %q, want nginx", got)
	}
	if got := a2.Attrs["version"]; got != "1.25.3" {
		t.Errorf("asset-2 Attrs[version] = %q, want 1.25.3", got)
	}
	if a1 := byID["asset-1"]; a1.Attrs != nil {
		t.Errorf("asset-1 Attrs = %v, want nil", a1.Attrs)
	}
	if !a2.FirstSeen.Equal(time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)) {
		t.Errorf("asset-2 FirstSeen = %v, not round-tripped", a2.FirstSeen)
	}

	// Finding fields: Severity, CVSS, Validated.
	fByID := map[string]state.Finding{}
	for _, f := range findings {
		fByID[f.ID] = f
	}
	f2 := fByID["find-2"]
	if f2.Severity != state.SeverityCritical {
		t.Errorf("find-2 Severity = %v, want critical", f2.Severity)
	}
	if f2.CVSS != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" {
		t.Errorf("find-2 CVSS = %q, not round-tripped", f2.CVSS)
	}
	if !f2.Validated {
		t.Error("find-2 Validated = false, want true")
	}
	if fByID["find-1"].Severity != state.SeverityInfo {
		t.Errorf("find-1 Severity = %v, want info", fByID["find-1"].Severity)
	}

	// Completed keys round-trip.
	keySet := map[string]bool{}
	for _, k := range keys {
		keySet[k] = true
	}
	for _, want := range completed {
		if !keySet[want] {
			t.Errorf("completed key %q missing", want)
		}
	}
}

func TestInto(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engagement.db")
	const eng = "eng-B"

	st, completed := buildState()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.SaveState(eng, st, completed); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	fresh := state.New()
	keys, err := s.Into(eng, fresh)
	if err != nil {
		t.Fatalf("Into: %v", err)
	}
	if len(fresh.Assets()) != 2 {
		t.Errorf("replayed assets = %d, want 2", len(fresh.Assets()))
	}
	if len(fresh.Findings()) != 2 {
		t.Errorf("replayed findings = %d, want 2", len(fresh.Findings()))
	}
	if len(keys) != 2 {
		t.Errorf("Into keys = %d, want 2", len(keys))
	}
}

func TestSaveStateIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engagement.db")
	const eng = "eng-C"

	st, completed := buildState()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	for i := 0; i < 3; i++ {
		if err := s.SaveState(eng, st, completed); err != nil {
			t.Fatalf("SaveState #%d: %v", i, err)
		}
	}

	assets, findings, keys, err := s.LoadState(eng)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(assets) != 2 {
		t.Errorf("assets = %d after 3 saves, want 2 (no dupes)", len(assets))
	}
	if len(findings) != 2 {
		t.Errorf("findings = %d after 3 saves, want 2 (no dupes)", len(findings))
	}
	if len(keys) != 2 {
		t.Errorf("completed keys = %d after 3 saves, want 2 (no dupes)", len(keys))
	}
}
