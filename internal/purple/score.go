package purple

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/attack"
)

// Detection statuses for a scored activity.
const (
	StatusDetected = "detected" // an alert naming this target fired in the window
	StatusWeak     = "weak"     // an alert fired in the window but named no target
	StatusMissed   = "missed"   // nothing fired
	StatusNotScore = "not-scored"
)

// ScoreOptions tunes alert-to-activity correlation.
type ScoreOptions struct {
	// Grace is how long after an activity ends an alert may still be credited to
	// it (detection pipelines lag). Default 10 minutes.
	Grace time.Duration
	// Skew is the tolerated clock difference between the tyto host and the
	// defender's tooling, applied before an activity starts. Default 2 minutes.
	Skew time.Duration
}

func (o ScoreOptions) withDefaults() ScoreOptions {
	if o.Grace <= 0 {
		o.Grace = 10 * time.Minute
	}
	if o.Skew <= 0 {
		o.Skew = 2 * time.Minute
	}
	return o
}

// ActivityResult is one activity plus its detection outcome.
type ActivityResult struct {
	Activity
	Status string  `json:"status"`
	Alerts []Alert `json:"alerts,omitempty"`
	// TimeToDetectSec is seconds from the activity starting to its first credited
	// alert (clamped at 0 for alerts inside the clock-skew allowance). Nil when
	// not detected.
	TimeToDetectSec *float64 `json:"time_to_detect_seconds,omitempty"`
	// TechniqueConfirmed is true when a credited alert carried an ATT&CK id that
	// matches the activity's technique — the SOC not only saw it, it classified it.
	TechniqueConfirmed bool `json:"technique_confirmed,omitempty"`
}

// TechniqueCoverage is detection coverage for one ATT&CK technique.
type TechniqueCoverage struct {
	attack.Technique
	Exercised int `json:"exercised"`
	Detected  int `json:"detected"`
	Weak      int `json:"weak"`
}

// HostCoverage is detection coverage for one target host.
type HostCoverage struct {
	Host          string     `json:"host"`
	Exercised     int        `json:"exercised"`
	Detected      int        `json:"detected"`
	Weak          int        `json:"weak"`
	FirstActivity time.Time  `json:"first_activity"`
	FirstAlert    *time.Time `json:"first_alert,omitempty"`
	// TimeToFirstDetectSec is how long the host was under test before the first
	// alert naming it fired. Nil when the host was never detected.
	TimeToFirstDetectSec *float64 `json:"time_to_first_detect_seconds,omitempty"`
}

// Scorecard is the detection-coverage result for an engagement.
type Scorecard struct {
	Timeline Timeline      `json:"timeline"`
	Grace    time.Duration `json:"-"`
	Skew     time.Duration `json:"-"`
	// GraceSeconds / SkewSeconds are the correlation settings, for the JSON form.
	GraceSeconds float64 `json:"grace_seconds"`
	SkewSeconds  float64 `json:"skew_seconds"`

	AlertsLoaded int `json:"alerts_loaded"`
	// Scored excludes off-target activity, which no client sensor could see.
	Scored    int `json:"scored"`
	Detected  int `json:"detected"`
	Weak      int `json:"weak"`
	Missed    int `json:"missed"`
	NotScored int `json:"not_scored"`
	// CoveragePct counts only target-confirmed detections; weak (time-only)
	// correlations are reported separately and never inflate the headline.
	CoveragePct float64 `json:"coverage_pct"`
	// MedianTimeToDetectSec is over target-confirmed detections; nil when none.
	MedianTimeToDetectSec *float64 `json:"median_time_to_detect_seconds,omitempty"`

	Results     []ActivityResult    `json:"results"`
	ByTechnique []TechniqueCoverage `json:"by_technique"`
	ByHost      []HostCoverage      `json:"by_host"`
	// Unattributed alerts fired during the engagement but could not be tied to
	// any tyto activity. They are either noise or something else happening on the
	// network during the test — the SOC should look at every one.
	Unattributed []Alert `json:"unattributed_alerts,omitempty"`
	// OutsideWindow counts alerts that fell entirely outside the engagement.
	OutsideWindow int `json:"alerts_outside_window"`
}

// Score correlates defender alerts with the attack timeline.
//
// Each alert is credited to at most ONE activity — the best candidate whose
// window contains it — so a single noisy alert cannot mark a whole burst of
// concurrent activity as detected. An alert that names a target only matches
// activity against that target; an alert that names no target can only ever
// produce a "weak" (time-only) correlation.
func Score(tl Timeline, alerts []Alert, opts ScoreOptions) Scorecard {
	opts = opts.withDefaults()
	sc := Scorecard{
		Timeline: tl, Grace: opts.Grace, Skew: opts.Skew, AlertsLoaded: len(alerts),
		GraceSeconds: opts.Grace.Seconds(), SkewSeconds: opts.Skew.Seconds(),
	}
	sc.Results = make([]ActivityResult, len(tl.Activities))
	for i, a := range tl.Activities {
		st := StatusMissed
		if a.OffTarget {
			st = StatusNotScore
		}
		sc.Results[i] = ActivityResult{Activity: a, Status: st}
	}

	type credit struct {
		strong, technique bool
	}
	credits := make([]map[int]credit, len(tl.Activities)) // activity -> alert index -> credit
	for ai, al := range alerts {
		best, bestRank := -1, -1
		var bestDist time.Duration
		var bestCredit credit
		for i, a := range tl.Activities {
			if a.OffTarget {
				continue
			}
			if al.Time.Before(a.Start.Add(-opts.Skew)) || al.Time.After(a.End.Add(opts.Grace)) {
				continue
			}
			c := credit{technique: techniquesOverlap(al.Techniques, a.Techniques)}
			if al.Target != "" {
				if !hostMatches(al.Target, a.Host, tl.Resolved) {
					continue // the alert is about a different machine
				}
				c.strong = true
			}
			rank := 0
			if c.strong {
				rank += 2
			}
			if c.technique {
				rank++
			}
			dist := al.Time.Sub(a.Start)
			if dist < 0 {
				dist = -dist
			}
			if rank > bestRank || (rank == bestRank && dist < bestDist) {
				best, bestRank, bestDist, bestCredit = i, rank, dist, c
			}
		}
		if best < 0 {
			if tl.Start.IsZero() || al.Time.Before(tl.Start.Add(-opts.Skew)) || al.Time.After(tl.End.Add(opts.Grace)) {
				sc.OutsideWindow++
			} else {
				sc.Unattributed = append(sc.Unattributed, al)
			}
			continue
		}
		if credits[best] == nil {
			credits[best] = map[int]credit{}
		}
		credits[best][ai] = bestCredit
	}

	var ttds []float64
	for i := range sc.Results {
		r := &sc.Results[i]
		if r.Status == StatusNotScore {
			sc.NotScored++
			continue
		}
		sc.Scored++
		if len(credits[i]) == 0 {
			sc.Missed++
			continue
		}
		idxs := make([]int, 0, len(credits[i]))
		for ai := range credits[i] {
			idxs = append(idxs, ai)
		}
		sort.Ints(idxs) // alerts are time-sorted, so this is chronological
		strong := false
		var first *time.Time
		for _, ai := range idxs {
			c := credits[i][ai]
			r.Alerts = append(r.Alerts, alerts[ai])
			r.TechniqueConfirmed = r.TechniqueConfirmed || c.technique
			if c.strong {
				strong = true
				if first == nil {
					t := alerts[ai].Time
					first = &t
				}
			}
		}
		if !strong {
			r.Status = StatusWeak
			sc.Weak++
			continue
		}
		r.Status = StatusDetected
		sc.Detected++
		ttd := first.Sub(r.Start).Seconds()
		if ttd < 0 {
			ttd = 0
		}
		r.TimeToDetectSec = &ttd
		ttds = append(ttds, ttd)
	}
	if sc.Scored > 0 {
		sc.CoveragePct = 100 * float64(sc.Detected) / float64(sc.Scored)
	}
	if len(ttds) > 0 {
		sort.Float64s(ttds)
		med := ttds[len(ttds)/2]
		if len(ttds)%2 == 0 {
			med = (ttds[len(ttds)/2-1] + ttds[len(ttds)/2]) / 2
		}
		sc.MedianTimeToDetectSec = &med
	}

	sc.ByTechnique = techniqueCoverage(sc.Results)
	sc.ByHost = hostCoverage(sc.Results)
	return sc
}

func techniqueCoverage(results []ActivityResult) []TechniqueCoverage {
	by := map[string]*TechniqueCoverage{}
	for _, r := range results {
		if r.Status == StatusNotScore {
			continue
		}
		for _, t := range r.Techniques {
			tc := by[t.ID]
			if tc == nil {
				tc = &TechniqueCoverage{Technique: t}
				by[t.ID] = tc
			}
			tc.Exercised++
			switch r.Status {
			case StatusDetected:
				tc.Detected++
			case StatusWeak:
				tc.Weak++
			}
		}
	}
	out := make([]TechniqueCoverage, 0, len(by))
	for _, tc := range by {
		out = append(out, *tc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func hostCoverage(results []ActivityResult) []HostCoverage {
	by := map[string]*HostCoverage{}
	for _, r := range results {
		if r.Status == StatusNotScore || r.Host == "" {
			continue
		}
		hc := by[r.Host]
		if hc == nil {
			hc = &HostCoverage{Host: r.Host, FirstActivity: r.Start}
			by[r.Host] = hc
		}
		hc.Exercised++
		if r.Start.Before(hc.FirstActivity) {
			hc.FirstActivity = r.Start
		}
		switch r.Status {
		case StatusDetected:
			hc.Detected++
			for _, al := range r.Alerts {
				if al.Target == "" {
					continue
				}
				if hc.FirstAlert == nil || al.Time.Before(*hc.FirstAlert) {
					t := al.Time
					hc.FirstAlert = &t
				}
			}
		case StatusWeak:
			hc.Weak++
		}
	}
	out := make([]HostCoverage, 0, len(by))
	for _, hc := range by {
		if hc.FirstAlert != nil {
			d := hc.FirstAlert.Sub(hc.FirstActivity).Seconds()
			if d < 0 {
				d = 0
			}
			hc.TimeToFirstDetectSec = &d
		}
		out = append(out, *hc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// techniquesOverlap reports whether any alert technique id matches any activity
// technique at the parent level (an alert tagged T1595 matches T1595.002 and
// vice versa — SIEM tagging is rarely sub-technique precise).
func techniquesOverlap(alertIDs []string, ts []attack.Technique) bool {
	for _, id := range alertIDs {
		p := parentID(id)
		for _, t := range ts {
			if parentID(t.ID) == p {
				return true
			}
		}
	}
	return false
}

func parentID(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return id
}

// hostMatches reports whether an alert's target names the activity's host:
// equal names/addresses, an address inside the activity's CIDR, or an address
// the activity's hostname resolved to.
func hostMatches(alertTarget, activityHost string, resolved map[string][]string) bool {
	at, ah := strings.ToLower(alertTarget), strings.ToLower(activityHost)
	if at == "" || ah == "" {
		return false
	}
	if at == ah {
		return true
	}
	if addr, err := netip.ParseAddr(at); err == nil {
		if pfx, err := netip.ParsePrefix(ah); err == nil {
			return pfx.Contains(addr)
		}
		if other, err := netip.ParseAddr(ah); err == nil {
			return addr.Unmap() == other.Unmap()
		}
		for _, ip := range resolved[ah] {
			if r, err := netip.ParseAddr(ip); err == nil && r.Unmap() == addr.Unmap() {
				return true
			}
		}
	}
	return false
}
