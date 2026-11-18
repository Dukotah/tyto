package detect

import (
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/blue/event"
)

// newDetector is a test helper that fails fast if the embedded corpus won't load.
func newDetector(t *testing.T) *Detector {
	t.Helper()
	d, err := NewDetector()
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	return d
}

// hasDetection reports whether dets contains a match for the given technique id,
// returning the first such detection for further assertions.
func hasDetection(dets []Detection, technique string) (Detection, bool) {
	for _, d := range dets {
		if d.Technique == technique {
			return d, true
		}
	}
	return Detection{}, false
}

// TestMaliciousEncodedPowerShell: an encoded-powershell command line must fire the
// T1059.001 rule and carry the correct technique id + severity.
func TestMaliciousEncodedPowerShell(t *testing.T) {
	d := newDetector(t)

	e := event.Event{
		ID:          "evt-1",
		Sensor:      "sysmon",
		Time:        time.Now().UTC(),
		Class:       "process_activity",
		Activity:    "created",
		Process:     `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine: `powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA`,
		Host:        "WS-01",
		User:        "victim",
	}

	dets := d.Eval(e)
	got, ok := hasDetection(dets, "T1059.001")
	if !ok {
		t.Fatalf("expected a T1059.001 detection, got %d detections: %+v", len(dets), dets)
	}
	if !got.Matched {
		t.Errorf("detection.Matched = false, want true")
	}
	if got.Severity != event.SevHigh {
		t.Errorf("severity = %v, want high", got.Severity)
	}
	if got.RuleAuthor == "" {
		t.Errorf("RuleAuthor empty; attribution must be carried through")
	}
	if got.Event.ID != e.ID {
		t.Errorf("detection carries wrong event: got %q want %q", got.Event.ID, e.ID)
	}
}

// TestMaliciousOfficeSpawnsShell: Word spawning cmd.exe must fire the T1059.003 rule.
func TestMaliciousOfficeSpawnsShell(t *testing.T) {
	d := newDetector(t)

	e := event.Event{
		ID:            "evt-2",
		Sensor:        "sysmon",
		Class:         "process_activity",
		Activity:      "created",
		ParentProcess: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
		Process:       `C:\Windows\System32\cmd.exe`,
		CommandLine:   `cmd.exe /c start payload.exe`,
	}

	dets := d.Eval(e)
	if _, ok := hasDetection(dets, "T1059.003"); !ok {
		t.Fatalf("expected a T1059.003 detection, got %d detections: %+v", len(dets), dets)
	}
}

// TestMaliciousMetasploitPort: an outbound network connection to port 4444 fires
// the T1571 network rule.
func TestMaliciousMetasploitPort(t *testing.T) {
	d := newDetector(t)

	e := event.Event{
		ID:      "evt-3",
		Sensor:  "suricata",
		Class:   "network_activity",
		SrcIP:   "10.0.0.5",
		DstIP:   "203.0.113.7",
		DstPort: 4444,
	}

	if _, ok := hasDetection(d.Eval(e), "T1571"); !ok {
		t.Fatalf("expected a T1571 detection for DstPort 4444")
	}
}

// TestWebScannerUserAgent: a scanner User-Agent parked in RawFields reaches the
// web rule and fires T1595.002 (proves RawFields field mapping).
func TestWebScannerUserAgent(t *testing.T) {
	d := newDetector(t)

	e := event.Event{
		ID:     "evt-4",
		Sensor: "jsonl",
		Class:  "http_activity",
		RawFields: map[string]string{
			"c-useragent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
			"cs-uri":      "/login.php?id=1",
		},
	}

	if _, ok := hasDetection(d.Eval(e), "T1595.002"); !ok {
		t.Fatalf("expected a T1595.002 detection for sqlmap user agent")
	}
}

// TestBenignBaselineNoDetection: an ordinary interactive process event must not
// trip any rule (precision / false-positive guard).
func TestBenignBaselineNoDetection(t *testing.T) {
	d := newDetector(t)

	benign := []event.Event{
		{
			ID:            "b-1",
			Sensor:        "sysmon",
			Class:         "process_activity",
			Activity:      "created",
			ParentProcess: `C:\Windows\explorer.exe`,
			Process:       `C:\Program Files\Google\Chrome\Application\chrome.exe`,
			CommandLine:   `"chrome.exe" --restore-last-session`,
			Host:          "WS-02",
			User:          "alice",
		},
		{
			ID:          "b-2",
			Sensor:      "sysmon",
			Class:       "process_activity",
			Activity:    "created",
			Process:     `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CommandLine: `powershell.exe -Command Get-ChildItem C:\Users`,
		},
		{
			ID:      "b-3",
			Sensor:  "suricata",
			Class:   "network_activity",
			SrcIP:   "10.0.0.5",
			DstIP:   "93.184.216.34",
			DstPort: 443,
		},
	}

	for _, e := range benign {
		if dets := d.Eval(e); len(dets) != 0 {
			t.Errorf("benign event %q produced %d detection(s): %+v", e.ID, len(dets), dets)
		}
	}
}

// TestCorpusInvariants: every embedded rule parses, loads, and carries an ATT&CK
// technique id, a title and an author.
func TestCorpusInvariants(t *testing.T) {
	d := newDetector(t)

	if d.RuleCount() < 15 {
		t.Errorf("rule count = %d, want >= 15", d.RuleCount())
	}

	seen := map[string]bool{}
	for _, m := range d.Rules() {
		if m.Technique == "" {
			t.Errorf("rule %q (%s) has no ATT&CK technique", m.Title, m.Source)
		}
		if m.Title == "" {
			t.Errorf("rule %s has no title", m.Source)
		}
		if m.Author == "" {
			t.Errorf("rule %q (%s) has no author", m.Title, m.Source)
		}
		if m.Severity == event.SevUnknown {
			t.Errorf("rule %q (%s) level %q mapped to SevUnknown", m.Title, m.Source, m.Level)
		}
		if m.ID != "" {
			if seen[m.ID] {
				t.Errorf("duplicate rule id %q (%s)", m.ID, m.Source)
			}
			seen[m.ID] = true
		}
	}
}
