package engagement

import (
	"fmt"
	"math"
	"strings"
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
	// TrafficMarker controls the engagement marker header tyto stamps on its HTTP
	// requests so the client's defenders can tell test traffic from a real attack.
	TrafficMarker TrafficMarker `yaml:"traffic_marker"`
}

// DefaultMarkerHeader is the request header carrying the engagement marker.
const DefaultMarkerHeader = "X-Tyto-Engagement"

// TrafficMarker configures the engagement marker. The zero value means "on, with
// the default header and the engagement id as its value": attributable traffic is
// the default, and going unmarked (e.g. a covert detection exercise the client
// asked for) is an explicit, recorded choice.
type TrafficMarker struct {
	// Disabled turns the marker off.
	Disabled bool `yaml:"disabled"`
	// Header overrides the header name (default X-Tyto-Engagement). Bug-bounty
	// programs that mandate their own header (e.g. "X-Bug-Bounty") set it here.
	Header string `yaml:"header"`
	// Value overrides the header value (default: the engagement id).
	Value string `yaml:"value"`
}

func (m TrafficMarker) validate() error {
	if m.Header != "" && !isHeaderToken(m.Header) {
		return fmt.Errorf("rules_of_engagement.traffic_marker.header %q is not a valid HTTP header name", m.Header)
	}
	if !isHeaderValue(m.Value) {
		return fmt.Errorf("rules_of_engagement.traffic_marker.value must be printable ASCII with no line breaks")
	}
	return nil
}

// isHeaderToken reports whether s is a valid HTTP field name (RFC 9110 token).
func isHeaderToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// isHeaderValue reports whether s is safe as a header value: printable ASCII
// only, so it can never smuggle a CR/LF into a request.
func isHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
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
	// Pacing knobs must be sane so a typo can't silently disable throttling.
	if math.IsNaN(r.MaxRPS) || math.IsInf(r.MaxRPS, 0) || r.MaxRPS < 0 {
		return fmt.Errorf("rules_of_engagement.max_requests_per_second must be a non-negative number")
	}
	if r.MaxConcurrent < 0 {
		return fmt.Errorf("rules_of_engagement.max_concurrent_actions must be >= 0")
	}
	return r.TrafficMarker.validate()
}
