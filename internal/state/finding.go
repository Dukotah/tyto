package state

import "time"

// Severity ranks the impact of a finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Finding is something worth reporting that a tool discovered.
type Finding struct {
	ID          string
	Title       string
	Severity    Severity
	Target      string
	Description string
	Evidence    string
	Tool        string
	FoundAt     time.Time
}
