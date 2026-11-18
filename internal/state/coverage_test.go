package state

import "testing"

func TestAddCoverageDedupsAndIndexes(t *testing.T) {
	s := New()
	a := CoverageAnchor{AssetRef: "10.0.0.1:443", Kind: CoverageAction, Ref: "httpx", Direction: "http fingerprinting"}
	if !s.AddCoverage(a) {
		t.Fatal("first AddCoverage should be new")
	}
	if s.AddCoverage(a) {
		t.Fatal("identical AddCoverage should dedup")
	}
	if len(s.Coverage()) != 1 {
		t.Fatalf("coverage len = %d, want 1", len(s.Coverage()))
	}
	// A different direction on the same asset is a distinct anchor.
	if !s.AddCoverage(CoverageAnchor{AssetRef: "10.0.0.1:443", Kind: CoverageAction, Ref: "nuclei", Direction: "web content discovery"}) {
		t.Fatal("different-direction anchor should be new")
	}
	if !s.Covered("10.0.0.1:443") {
		t.Error("asset should report covered")
	}
	// Lookup normalizes case + trailing dot.
	if !s.Covered("10.0.0.1:443 ") {
		t.Error("covered lookup should normalize surrounding whitespace")
	}
	if s.Covered("10.0.0.2:443") {
		t.Error("untouched asset must not report covered")
	}
}

func TestFindingAutoAnchorsCoverage(t *testing.T) {
	s := New()
	s.AddFinding(Finding{ID: "f1", Title: "x", Target: "host.example.com", Severity: SeverityLow})
	if !s.Covered("host.example.com") {
		t.Error("a finding should auto-anchor coverage on its target")
	}
	cov := s.Coverage()
	if len(cov) != 1 || cov[0].Kind != CoverageFinding {
		t.Fatalf("want 1 finding anchor, got %+v", cov)
	}
	// Re-adding the same (deduped) finding must not add a second anchor.
	s.AddFinding(Finding{ID: "f1", Title: "x", Target: "host.example.com", Severity: SeverityLow})
	if len(s.Coverage()) != 1 {
		t.Errorf("deduped finding re-add inflated coverage to %d", len(s.Coverage()))
	}
}

func TestFrontierDistinguishesCoveredDirections(t *testing.T) {
	s := New()
	s.AddAsset(&Asset{ID: "svc", Type: "service", Value: "10.0.0.1:80",
		Attrs: map[string]string{"port": "80", "service": "http"}})
	// http suggests "web content discovery" + "http fingerprinting"; cover one.
	s.AddCoverage(CoverageAnchor{AssetRef: "10.0.0.1:80", Kind: CoverageAction, Ref: "httpx", Direction: "http fingerprinting"})

	fr := s.Frontier()
	if len(fr) != 1 {
		t.Fatalf("want 1 frontier, got %d", len(fr))
	}
	f := fr[0]
	if !f.Covered {
		t.Error("asset with a coverage anchor should be Covered")
	}
	if len(f.CoveredDirections) != 1 || f.CoveredDirections[0] != "http fingerprinting" {
		t.Errorf("CoveredDirections = %v, want [http fingerprinting]", f.CoveredDirections)
	}
	wantOpen := false
	for _, d := range f.UncoveredDirections {
		if d == "web content discovery" {
			wantOpen = true
		}
		if d == "http fingerprinting" {
			t.Error("covered direction leaked into UncoveredDirections")
		}
	}
	if !wantOpen {
		t.Errorf("UncoveredDirections = %v, want it to include web content discovery", f.UncoveredDirections)
	}
}

func TestFrontierUncoveredByDefault(t *testing.T) {
	s := New()
	s.AddAsset(&Asset{ID: "svc", Type: "service", Value: "10.0.0.1:22",
		Attrs: map[string]string{"port": "22", "service": "ssh"}})
	f := s.Frontier()[0]
	if f.Covered {
		t.Error("untouched service should not be Covered")
	}
	if len(f.CoveredDirections) != 0 {
		t.Errorf("CoveredDirections = %v, want empty", f.CoveredDirections)
	}
	if len(f.UncoveredDirections) != len(f.Suggested) {
		t.Errorf("all %d suggestions should be uncovered, got %d", len(f.Suggested), len(f.UncoveredDirections))
	}
}
