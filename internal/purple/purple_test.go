package purple

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/audit"
)

var t0 = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

func at(min, sec int) time.Time {
	return t0.Add(time.Duration(min)*time.Minute + time.Duration(sec)*time.Second)
}

// act returns the action+result entry pair for one executed action.
func act(id, tool, target string, start, end time.Time) []audit.Entry {
	return []audit.Entry{
		{Time: start, Kind: "action", Data: map[string]any{"action": id, "tool": tool, "target": target}},
		{Time: end, Kind: "result", Data: map[string]any{"action": id, "success": true, "findings": float64(1)}},
	}
}

func fixture() []audit.Entry {
	var es []audit.Entry
	es = append(es, audit.Entry{Time: at(0, 0), Kind: "info", Data: map[string]any{"event": "engagement_start", "id": "acme-q1", "client": "Acme"}})
	es = append(es, audit.Entry{Time: at(0, 0), Kind: "info", Data: map[string]any{"event": "traffic_marker", "header": "X-Tyto-Engagement", "value": "acme-q1"}})
	// A guard denial: never executed, must not appear in the timeline.
	es = append(es, audit.Entry{Time: at(0, 1), Kind: "decision", Data: map[string]any{"action": "d1", "tool": "portscan", "target": "8.8.8.8", "allowed": false}})
	es = append(es, act("a1", "portscan", "10.0.0.5", at(1, 0), at(2, 0))...)
	es = append(es, act("a2", "webinject", "http://app.acme.test:8080/search?q=1", at(5, 0), at(6, 0))...)
	es = append(es, act("a3", "dirfuzz", "http://app.acme.test:8080/", at(20, 0), at(21, 0))...)
	es = append(es, act("a4", "subfinder", "acme.test", at(30, 0), at(30, 5))...) // off-target
	es = append(es, audit.Entry{Time: at(21, 0), Kind: "defense_observed", Data: map[string]any{"target": "http://app.acme.test:8080/", "kind": "rate-limiting", "after_actions": float64(2)}})
	// Interrupted: an action with no result.
	es = append(es, audit.Entry{Time: at(40, 0), Kind: "action", Data: map[string]any{"action": "a5", "tool": "kali", "target": "10.0.0.5"}})
	return es
}

func TestBuildTimeline(t *testing.T) {
	tl := Build(fixture(), BuildOptions{Source: "203.0.113.7"})
	if tl.EngagementID != "acme-q1" || tl.Client != "Acme" {
		t.Fatalf("engagement not read: %+v", tl)
	}
	if tl.Marker == nil || tl.Marker.Header != "X-Tyto-Engagement" {
		t.Fatalf("traffic marker not read: %+v", tl.Marker)
	}
	if len(tl.Activities) != 5 {
		t.Fatalf("want 5 executed activities (denial excluded), got %d", len(tl.Activities))
	}
	a := tl.Activities[1]
	if a.Host != "app.acme.test" || a.Techniques[0].ID != "T1190" || !a.Mapped || a.Findings != 1 {
		t.Fatalf("webinject activity wrong: %+v", a)
	}
	if !tl.Activities[3].OffTarget {
		t.Fatal("subfinder must be off-target")
	}
	last := tl.Activities[4]
	if !last.Incomplete || last.Mapped || !last.End.Equal(last.Start) {
		t.Fatalf("interrupted kali action wrong: %+v", last)
	}
	if !tl.Start.Equal(at(1, 0)) || !tl.End.Equal(at(40, 0)) {
		t.Fatalf("window wrong: %s → %s", tl.Start, tl.End)
	}
	if len(tl.Defenses) != 1 || tl.Defenses[0].AfterActions != 2 {
		t.Fatalf("defense events wrong: %+v", tl.Defenses)
	}
	if tl.ChainVerified {
		t.Fatal("hand-built entries carry no hashes; the chain must not verify")
	}
}

func TestBuildVerifiesRealChain(t *testing.T) {
	var buf bytes.Buffer
	l := audit.NewLog(&buf)
	_ = l.Record("action", map[string]any{"action": "a1", "tool": "portscan", "target": "10.0.0.5"})
	_ = l.Record("result", map[string]any{"action": "a1", "success": true, "findings": 0})
	var entries []audit.Entry
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	if tl := Build(entries, BuildOptions{}); !tl.ChainVerified || len(tl.Activities) != 1 || tl.Activities[0].Incomplete {
		t.Fatalf("real chain should verify and pair: %+v", tl)
	}
}

func TestRecurringActionIDsPairInOrder(t *testing.T) {
	es := append(act("a1", "portscan", "10.0.0.1", at(1, 0), at(2, 0)), act("a1", "portscan", "10.0.0.2", at(3, 0), at(4, 0))...)
	tl := Build(es, BuildOptions{})
	if len(tl.Activities) != 2 || !tl.Activities[0].End.Equal(at(2, 0)) || !tl.Activities[1].End.Equal(at(4, 0)) {
		t.Fatalf("reused action ids must pair first-in-first-out: %+v", tl.Activities)
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"http://App.Acme.test:8080/x?y=1": "app.acme.test",
		"app.acme.test:443":               "app.acme.test",
		"app.acme.test/path":              "app.acme.test",
		"10.0.0.5":                        "10.0.0.5",
		"10.0.0.0/24":                     "10.0.0.0/24",
		"[2001:db8::1]:443":               "2001:db8::1",
		"2001:db8::1":                     "2001:db8::1",
		"":                                "",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScore(t *testing.T) {
	tl := Build(fixture(), BuildOptions{Resolve: func(h string) []string {
		if h == "app.acme.test" {
			return []string{"10.0.0.9"}
		}
		return nil
	}})
	alerts := []Alert{
		// Port scan detected 30s in, technique-tagged at the parent level.
		{Line: 1, Time: at(1, 30), Name: "ET SCAN portscan", Target: "10.0.0.5", Techniques: []string{"T1046"}},
		// SQLi alert keyed by IP: matches webinject only via the resolved address.
		{Line: 2, Time: at(5, 20), Name: "WAF SQLi", Target: "10.0.0.9"},
		// An alert about an unrelated machine during the engagement.
		{Line: 3, Time: at(5, 30), Name: "Malware beacon", Target: "10.9.9.9"},
		// Long after everything.
		{Line: 4, Time: at(500, 0), Name: "late", Target: "10.0.0.5"},
	}
	sc := Score(tl, alerts, ScoreOptions{})

	if sc.Scored != 4 || sc.NotScored != 1 {
		t.Fatalf("scored=%d notScored=%d, want 4/1 (subfinder excluded)", sc.Scored, sc.NotScored)
	}
	if sc.Detected != 2 || sc.Missed != 2 || sc.Weak != 0 {
		t.Fatalf("detected=%d weak=%d missed=%d, want 2/0/2", sc.Detected, sc.Weak, sc.Missed)
	}
	if sc.CoveragePct != 50 {
		t.Fatalf("coverage = %v, want 50", sc.CoveragePct)
	}
	ps := sc.Results[0]
	if ps.Status != StatusDetected || !ps.TechniqueConfirmed || *ps.TimeToDetectSec != 30 {
		t.Fatalf("portscan result wrong: %+v", ps)
	}
	if sc.Results[1].Status != StatusDetected || *sc.Results[1].TimeToDetectSec != 20 {
		t.Fatalf("webinject should match by resolved IP: %+v", sc.Results[1])
	}
	if sc.Results[2].Status != StatusMissed {
		t.Fatalf("dirfuzz had no alert and must be missed: %+v", sc.Results[2])
	}
	if sc.Results[3].Status != StatusNotScore {
		t.Fatal("off-target subfinder must not be scored")
	}
	if len(sc.Unattributed) != 1 || sc.Unattributed[0].Name != "Malware beacon" {
		t.Fatalf("unattributed wrong: %+v", sc.Unattributed)
	}
	if sc.OutsideWindow != 1 {
		t.Fatalf("outside window = %d, want 1", sc.OutsideWindow)
	}
	if *sc.MedianTimeToDetectSec != 25 {
		t.Fatalf("median ttd = %v, want 25", *sc.MedianTimeToDetectSec)
	}
	// Per-host: app.acme.test had 2 actions (webinject, dirfuzz), one detected.
	var app HostCoverage
	for _, h := range sc.ByHost {
		if h.Host == "app.acme.test" {
			app = h
		}
	}
	if app.Exercised != 2 || app.Detected != 1 || app.TimeToFirstDetectSec == nil || *app.TimeToFirstDetectSec != 20 {
		t.Fatalf("host coverage wrong: %+v", app)
	}
}

func TestScoreOneAlertCreditsOneActivity(t *testing.T) {
	// Three concurrent actions on one host; a single alert must not mark all three.
	var es []audit.Entry
	es = append(es, act("a1", "webcheck", "http://h.test/", at(1, 0), at(2, 0))...)
	es = append(es, act("a2", "webinject", "http://h.test/", at(1, 0), at(2, 0))...)
	es = append(es, act("a3", "dirfuzz", "http://h.test/", at(1, 0), at(2, 0))...)
	sc := Score(Build(es, BuildOptions{}), []Alert{{Time: at(1, 10), Target: "h.test", Techniques: []string{"T1190"}}}, ScoreOptions{})
	if sc.Detected != 1 || sc.Missed != 2 {
		t.Fatalf("one alert must credit exactly one activity, got detected=%d missed=%d", sc.Detected, sc.Missed)
	}
	if sc.Results[1].Status != StatusDetected {
		t.Fatalf("the technique-matching activity (webinject/T1190) should win the credit: %+v", sc.Results)
	}
}

func TestScoreWeakWhenAlertNamesNoTarget(t *testing.T) {
	sc := Score(Build(act("a1", "portscan", "10.0.0.5", at(1, 0), at(2, 0)), BuildOptions{}),
		[]Alert{{Time: at(1, 10), Name: "something happened"}}, ScoreOptions{})
	if sc.Weak != 1 || sc.Detected != 0 || sc.CoveragePct != 0 {
		t.Fatalf("a targetless alert is only a weak correlation and must not raise coverage: %+v", sc)
	}
}

func TestScoreCIDRAndGrace(t *testing.T) {
	tl := Build(act("a1", "netsweep", "10.0.0.0/24", at(1, 0), at(2, 0)), BuildOptions{})
	in := Score(tl, []Alert{{Time: at(11, 0), Target: "10.0.0.77"}}, ScoreOptions{})
	if in.Detected != 1 {
		t.Fatal("alert for an address inside the swept CIDR, within grace, must match")
	}
	late := Score(tl, []Alert{{Time: at(13, 0), Target: "10.0.0.77"}}, ScoreOptions{})
	if late.Detected != 0 {
		t.Fatal("alert past the grace window must not match")
	}
	out := Score(tl, []Alert{{Time: at(1, 30), Target: "10.0.1.77"}}, ScoreOptions{})
	if out.Detected != 0 || len(out.Unattributed) != 1 {
		t.Fatal("alert for an address outside the CIDR must be unattributed")
	}
}

func TestParseAlertsFormats(t *testing.T) {
	cases := map[string]string{
		"json array (ECS)": `[{"@timestamp":"2026-03-01T10:01:30Z","rule":{"name":"Port scan"},"destination":{"ip":"10.0.0.5"},"source":{"ip":"203.0.113.7"},"threat":{"technique":{"id":["T1046"]}},"event":{"severity":3}}]`,
		"ndjson (splunk)":  `{"_time":"2026-03-01 10:01:30","signature":"Port scan","dest":"10.0.0.5","src":"203.0.113.7","mitre_technique_id":"T1046","severity":"high"}` + "\n",
		"elastic hits":     `{"hits":{"hits":[{"_source":{"@timestamp":"2026-03-01T10:01:30.000Z","rule":{"name":"Port scan"},"destination":{"ip":"10.0.0.5"},"source":{"ip":"203.0.113.7"},"threat":{"technique":{"id":"T1046"}}}}]}}`,
		"csv":              "Timestamp,Rule Name,dest_ip,src_ip,Technique,Severity\n2026-03-01T10:01:30Z,Port scan,10.0.0.5,203.0.113.7,T1046,high\n",
		"epoch millis":     `[{"timestamp":1772359290000,"name":"Port scan","dest_ip":"10.0.0.5","src_ip":"203.0.113.7","technique":"T1046"}]`,
		"id in rule name":  `[{"time":"2026-03-01T10:01:30Z","title":"Port scan (T1046)","host":"10.0.0.5","src":"203.0.113.7"}]`,
	}
	for name, in := range cases {
		alerts, skipped, err := ParseAlerts(strings.NewReader(in), nil)
		if err != nil || len(skipped) != 0 || len(alerts) != 1 {
			t.Errorf("%s: alerts=%d skipped=%v err=%v", name, len(alerts), skipped, err)
			continue
		}
		a := alerts[0]
		if !a.Time.Equal(at(1, 30)) || a.Target != "10.0.0.5" || a.Source != "203.0.113.7" ||
			!strings.Contains(a.Name, "Port scan") || len(a.Techniques) != 1 || a.Techniques[0] != "T1046" {
			t.Errorf("%s: parsed wrong: %+v", name, a)
		}
	}
}

func TestParseAlertsZoneAndSkips(t *testing.T) {
	chicago, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	in := "time,name\n2026-03-01 04:01:30,ok\nnot-a-time,bad\n,empty\n"
	alerts, skipped, err := ParseAlerts(strings.NewReader(in), chicago)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || !alerts[0].Time.Equal(at(1, 30)) {
		t.Fatalf("zoneless timestamp must be read in the given zone: %+v", alerts)
	}
	if len(skipped) != 2 || skipped[0] != 2 {
		t.Fatalf("rows without a readable time must be skipped, not fatal: %v", skipped)
	}
}

func TestRenderers(t *testing.T) {
	tl := Build(fixture(), BuildOptions{Source: "203.0.113.7"})
	md := RenderTimelineMarkdown(tl)
	for _, want := range []string{"acme-q1", "203.0.113.7", "X-Tyto-Engagement: acme-q1", "T1190", "off-target", "BROKEN", "rate-limiting", "interrupted"} {
		if !strings.Contains(md, want) {
			t.Errorf("timeline markdown missing %q", want)
		}
	}
	csvOut, err := RenderTimelineCSV(tl)
	if err != nil || strings.Count(string(csvOut), "\n") != 6 {
		t.Fatalf("csv should have header + 5 rows: err=%v\n%s", err, csvOut)
	}

	sc := Score(tl, []Alert{{Time: at(1, 30), Name: "scan | with pipe", Target: "10.0.0.5"}}, ScoreOptions{})
	smd := RenderScoreMarkdown(sc)
	for _, want := range []string{"**1 of 4**", "25%", "## Detection gaps", "scan \\| with pipe", "T1595.003"} {
		if !strings.Contains(smd, want) {
			t.Errorf("score markdown missing %q", want)
		}
	}

	for _, s := range []*Scorecard{nil, &sc} {
		raw, err := RenderNavigatorLayer(tl, s)
		if err != nil {
			t.Fatal(err)
		}
		var layer struct {
			Domain     string `json:"domain"`
			Techniques []struct {
				TechniqueID string `json:"techniqueID"`
				Score       int    `json:"score"`
				Color       string `json:"color"`
			} `json:"techniques"`
		}
		if err := json.Unmarshal(raw, &layer); err != nil {
			t.Fatal(err)
		}
		if layer.Domain != "enterprise-attack" || len(layer.Techniques) == 0 {
			t.Fatalf("bad layer: %s", raw)
		}
		for _, lt := range layer.Techniques {
			if lt.TechniqueID == "T1596" {
				t.Error("off-target technique (subfinder/T1596) must not appear in a layer")
			}
			if s != nil && lt.TechniqueID == "T1046" && (lt.Score != 100 || lt.Color != navGreen) {
				t.Errorf("T1046 was detected every time, want score 100 green: %+v", lt)
			}
			if s != nil && lt.TechniqueID == "T1190" && lt.Color != navRed {
				t.Errorf("T1190 was never detected, want red: %+v", lt)
			}
		}
	}
}
