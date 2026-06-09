package engagement

import (
	"fmt"
	"time"

	"github.com/dukotah/strix/internal/action"
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

func (r RoE) validate() error {
	if _, err := r.MaxRiskLevel(); err != nil {
		return fmt.Errorf("rules_of_engagement.max_risk: %w", err)
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
