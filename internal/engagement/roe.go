package engagement

import (
	"fmt"
	"time"

	"github.com/dukotah/tyto/internal/action"
)

// TimeWindow is an allowed operating window in UTC "HH:MM" form.
type TimeWindow struct {
	Start string `yaml:"start"`
	End   string `yaml:"end"`
}

// Contains reports whether t (in UTC) falls within the window. Windows that
// wrap past midnight (e.g. 22:00-02:00) are supported.
func (w TimeWindow) Contains(t time.Time) bool {
	start, err1 := parseHM(w.Start)
	end, err2 := parseHM(w.End)
	if err1 != nil || err2 != nil {
		return false
	}
	mins := t.Hour()*60 + t.Minute()
	if start <= end {
		return mins >= start && mins < end
	}
	// wraps midnight
	return mins >= start || mins < end
}

func parseHM(s string) (int, error) {
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, fmt.Errorf("invalid time %q: %w", s, err)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("time out of range %q", s)
	}
	return h*60 + m, nil
}

// RoE holds the rules of engagement the Scope Guard enforces.
type RoE struct {
	MaxRisk             string       `yaml:"max_risk"`
	AllowedCategories   []string     `yaml:"allowed_categories"`
	ForbiddenCategories []string     `yaml:"forbidden_categories"`
	TimeWindows         []TimeWindow `yaml:"time_windows"`
	MaxRPS              float64      `yaml:"max_requests_per_second"`
	MaxConcurrent       int          `yaml:"max_concurrent_actions"`
}

// MaxRiskLevel parses the configured risk ceiling.
func (r RoE) MaxRiskLevel() (action.RiskLevel, error) {
	return action.ParseRiskLevel(r.MaxRisk)
}

// Deadline returns the UTC instant at which the current operating window closes,
// if now falls within one. The engine uses it as a hard stop (via
// context.WithDeadline) so a run never spills past the permitted window.
//
// TimeWindows are recurring daily HH:MM windows with no calendar date, so this
// expresses "stop when today's permitted window ends," not a multi-day absolute
// deadline — that would need an explicit dated field (left for a later phase).
// ok is false when there are no windows (no time-based deadline) or now is
// outside them all (the guard already denies actions in that case). When several
// windows currently apply, the latest close wins (run as long as permitted).
func (r RoE) Deadline(now time.Time) (time.Time, bool) {
	now = now.UTC()
	nowMins := now.Hour()*60 + now.Minute()
	var best time.Time
	found := false
	for _, w := range r.TimeWindows {
		if !w.Contains(now) {
			continue
		}
		start, err1 := parseHM(w.Start)
		end, err2 := parseHM(w.End)
		if err1 != nil || err2 != nil {
			continue
		}
		endT := time.Date(now.Year(), now.Month(), now.Day(), end/60, end%60, 0, 0, time.UTC)
		// A window that wraps midnight (start > end) and currently contains now in
		// its pre-midnight portion closes tomorrow.
		if start > end && nowMins >= start {
			endT = endT.AddDate(0, 0, 1)
		}
		if !endT.After(now) {
			continue
		}
		if !found || endT.After(best) {
			best, found = endT, true
		}
	}
	return best, found
}

func (r RoE) validate() error {
	if _, err := r.MaxRiskLevel(); err != nil {
		return fmt.Errorf("rules_of_engagement.max_risk: %w", err)
	}
	// Categories must name members of the closed taxonomy so a typo fails CLOSED
	// at load instead of silently never-matching a forbidden-list entry.
	for _, c := range r.AllowedCategories {
		if _, err := action.ParseCategory(c); err != nil {
			return fmt.Errorf("rules_of_engagement.allowed_categories: %w", err)
		}
	}
	for _, c := range r.ForbiddenCategories {
		if _, err := action.ParseCategory(c); err != nil {
			return fmt.Errorf("rules_of_engagement.forbidden_categories: %w", err)
		}
	}
	for _, w := range r.TimeWindows {
		if _, err := parseHM(w.Start); err != nil {
			return fmt.Errorf("rules_of_engagement.time_windows.start: %w", err)
		}
		if _, err := parseHM(w.End); err != nil {
			return fmt.Errorf("rules_of_engagement.time_windows.end: %w", err)
		}
	}
	return nil
}
