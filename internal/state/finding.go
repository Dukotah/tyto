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
//
// The planner tags classify each exported string field for the quarantine
// boundary (see quarantine.go): "safe" fields may enter the planner prompt
// (sanitized); "quarantined" free-text fields are tool-controlled and must
// never reach the model. Operator-facing report rendering sees every field.
type Finding struct {
	ID          string   `planner:"quarantined"`
	Title       string   `planner:"safe"`
	Severity    Severity // enum, rendered safely
	Target      string   `planner:"safe"`
	Description string   `planner:"quarantined"`
	Evidence    string   `planner:"quarantined"` // raw tool output — never into the prompt
	Tool        string   `planner:"quarantined"`
	// Validated is true when a tool DIRECTLY observed the condition (vs an
	// inference). The report separates validated findings from candidates —
	// tyto's "confirm before you report" discipline.
	Validated bool
	FoundAt   time.Time
}
