package attack

import (
	"sort"
	"strings"
	"testing"
)

func TestEmbeddedLoadsAndLookup(t *testing.T) {
	c := Embedded()
	if c == nil {
		t.Fatal("Embedded() returned nil")
	}
	if got := c.Len(); got < 50 {
		t.Fatalf("embedded catalog has %d techniques, want >= 50", got)
	}

	tech, ok := c.Lookup("T1059")
	if !ok {
		t.Fatal(`Lookup("T1059") not found`)
	}
	if tech.Name != "Command and Scripting Interpreter" {
		t.Errorf("T1059 name = %q, want %q", tech.Name, "Command and Scripting Interpreter")
	}
	if tech.IsSubtechnique {
		t.Error("T1059 should not be a sub-technique")
	}
	if len(tech.Tactics) == 0 || tech.Tactics[0] != "execution" {
		t.Errorf("T1059 tactics = %v, want [execution]", tech.Tactics)
	}
	if !strings.HasPrefix(tech.URL, "https://attack.mitre.org/techniques/T1059") {
		t.Errorf("T1059 url = %q, unexpected", tech.URL)
	}

	// Sub-technique id flagging.
	sub, ok := c.Lookup("T1059.001")
	if !ok {
		t.Fatal(`Lookup("T1059.001") not found`)
	}
	if !sub.IsSubtechnique {
		t.Error("T1059.001 should be flagged as a sub-technique")
	}

	// Lookup trims whitespace and misses are reported.
	if _, ok := c.Lookup("  T1059 "); !ok {
		t.Error("Lookup should trim surrounding whitespace")
	}
	if _, ok := c.Lookup("T9999"); ok {
		t.Error("Lookup of unknown id should report not found")
	}
}

func TestAllStablySorted(t *testing.T) {
	c := Embedded()
	all := c.All()
	if len(all) != c.Len() {
		t.Fatalf("All() returned %d, Len() = %d", len(all), c.Len())
	}
	ids := make([]string, len(all))
	for i, tech := range all {
		ids[i] = tech.ID
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("All() is not sorted by ID: %v", ids)
	}
}

func TestByTactic(t *testing.T) {
	c := Embedded()
	exec := c.ByTactic("execution")
	if len(exec) == 0 {
		t.Fatal(`ByTactic("execution") returned nothing`)
	}
	foundT1059 := false
	for _, tech := range exec {
		foundT1059 = foundT1059 || tech.ID == "T1059"
		hit := false
		for _, tac := range tech.Tactics {
			if tac == "execution" {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s returned by ByTactic(execution) but has tactics %v", tech.ID, tech.Tactics)
		}
	}
	if !foundT1059 {
		t.Error(`ByTactic("execution") did not include T1059`)
	}
	// Case-insensitive.
	if len(c.ByTactic("EXECUTION")) != len(exec) {
		t.Error("ByTactic should be case-insensitive")
	}
	if got := c.ByTactic("not-a-tactic"); got != nil {
		t.Errorf("ByTactic of unknown tactic = %v, want nil", got)
	}
}

// loadFixture is a small, hand-written STIX 2.1 bundle: two live
// attack-patterns, one revoked attack-pattern (must be skipped), and a
// non-attack-pattern object (must be ignored).
const stixFixture = `{
  "type": "bundle",
  "id": "bundle--fixture",
  "objects": [
    {
      "type": "attack-pattern",
      "name": "Command and Scripting Interpreter",
      "description": "First line of the description.\nSecond line that must be dropped.",
      "external_references": [
        { "source_name": "mitre-attack", "external_id": "T1059", "url": "https://attack.mitre.org/techniques/T1059" }
      ],
      "kill_chain_phases": [
        { "kill_chain_name": "mitre-attack", "phase_name": "execution" }
      ]
    },
    {
      "type": "attack-pattern",
      "name": "Scheduled Task/Job",
      "description": "Schedules work.",
      "external_references": [
        { "source_name": "capec", "external_id": "CAPEC-999" },
        { "source_name": "mitre-attack", "external_id": "T1053", "url": "https://attack.mitre.org/techniques/T1053" }
      ],
      "kill_chain_phases": [
        { "kill_chain_name": "mitre-attack", "phase_name": "execution" },
        { "kill_chain_name": "mitre-attack", "phase_name": "persistence" },
        { "kill_chain_name": "some-other-chain", "phase_name": "ignore-me" }
      ]
    },
    {
      "type": "attack-pattern",
      "name": "Revoked Technique",
      "revoked": true,
      "external_references": [
        { "source_name": "mitre-attack", "external_id": "T0000", "url": "https://attack.mitre.org/techniques/T0000" }
      ],
      "kill_chain_phases": [
        { "kill_chain_name": "mitre-attack", "phase_name": "execution" }
      ]
    },
    {
      "type": "attack-pattern",
      "name": "Deprecated Technique",
      "x_mitre_deprecated": true,
      "external_references": [
        { "source_name": "mitre-attack", "external_id": "T0001", "url": "https://attack.mitre.org/techniques/T0001" }
      ]
    },
    {
      "type": "intrusion-set",
      "name": "Not A Technique",
      "external_references": [
        { "source_name": "mitre-attack", "external_id": "G0001" }
      ]
    }
  ]
}`

func TestLoadSTIX(t *testing.T) {
	c, err := LoadSTIX(strings.NewReader(stixFixture))
	if err != nil {
		t.Fatalf("LoadSTIX error: %v", err)
	}
	if got := c.Len(); got != 2 {
		t.Fatalf("LoadSTIX parsed %d techniques, want 2 (revoked/deprecated and non-technique skipped)", got)
	}

	// Revoked / deprecated / non-attack-pattern must be absent.
	for _, id := range []string{"T0000", "T0001", "G0001"} {
		if _, ok := c.Lookup(id); ok {
			t.Errorf("%s should have been skipped", id)
		}
	}

	t1059, ok := c.Lookup("T1059")
	if !ok {
		t.Fatal("T1059 missing from parsed bundle")
	}
	if t1059.Name != "Command and Scripting Interpreter" {
		t.Errorf("name = %q", t1059.Name)
	}
	if t1059.Description != "First line of the description." {
		t.Errorf("description = %q, want single first line", t1059.Description)
	}
	if t1059.URL != "https://attack.mitre.org/techniques/T1059" {
		t.Errorf("url = %q", t1059.URL)
	}
	if len(t1059.Tactics) != 1 || t1059.Tactics[0] != "execution" {
		t.Errorf("tactics = %v, want [execution]", t1059.Tactics)
	}

	t1053, ok := c.Lookup("T1053")
	if !ok {
		t.Fatal("T1053 missing from parsed bundle")
	}
	// Only mitre-attack phase_names, sorted: execution, persistence.
	want := []string{"execution", "persistence"}
	if len(t1053.Tactics) != len(want) {
		t.Fatalf("T1053 tactics = %v, want %v", t1053.Tactics, want)
	}
	for i := range want {
		if t1053.Tactics[i] != want[i] {
			t.Errorf("T1053 tactics = %v, want %v", t1053.Tactics, want)
		}
	}

	// All() stays sorted after a STIX load too.
	all := c.All()
	if len(all) != 2 || all[0].ID != "T1053" || all[1].ID != "T1059" {
		t.Errorf("All() order = %v, want [T1053 T1059]", []string{all[0].ID, all[1].ID})
	}
}
