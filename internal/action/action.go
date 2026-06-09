// Package action defines the unit of work the planner proposes and the engine
// executes: an Action, plus the Result a tool returns for it.
package action

import (
	"fmt"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/state"
)

// RiskLevel describes how intrusive an action is. The Scope Guard compares it
// against the engagement's ceiling.
type RiskLevel int

const (
	// RiskPassive sends nothing to the target (OSINT, passive DNS, cert logs).
	RiskPassive RiskLevel = iota
	// RiskLow is benign active contact (ping, single banner grab).
	RiskLow
	// RiskMedium is active scanning (port/service enumeration).
	RiskMedium
	// RiskHigh is intrusive (exploit attempts, auth brute force).
	RiskHigh
)

func (r RiskLevel) String() string {
	switch r {
	case RiskPassive:
		return "passive"
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	default:
		return "unknown"
	}
}

// ParseRiskLevel parses a risk level name (case-insensitive).
func ParseRiskLevel(s string) (RiskLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "passive":
		return RiskPassive, nil
	case "low":
		return RiskLow, nil
	case "medium":
		return RiskMedium, nil
	case "high":
		return RiskHigh, nil
	default:
		return RiskPassive, fmt.Errorf("unknown risk level %q", s)
	}
}

// Action is a single concrete step proposed by the planner.
type Action struct {
	ID        string
	Tool      string            // name of the tool to run
	Category  string            // recon | scan | exploit | ...
	Target    string            // host, IP, CIDR, or URL
	Params    map[string]string // tool-specific parameters
	Risk      RiskLevel
	Rationale string // why the planner chose this (for audit + reports)
}

// Result is what a tool returns after executing an Action.
type Result struct {
	ActionID string
	Tool     string
	Success  bool
	Output   string
	Findings []state.Finding
	// Assets are the typed entities (hosts, services, URLs) the tool discovered.
	// The engine persists them so the planner can pick service-specific follow-ups
	// from State.Frontier() — computed deterministically in Go, never by the model
	// parsing raw output.
	Assets     []state.Asset
	Err        string
	StartedAt  time.Time
	FinishedAt time.Time
}
