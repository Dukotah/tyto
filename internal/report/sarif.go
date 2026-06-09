package report

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/pkg/version"
)

// SARIF 2.1.0 export. SARIF is the standard interchange format for static- and
// dynamic-analysis findings (GitHub code scanning, DefectDojo, etc.), so this
// lets tyto results flow into existing security tooling. Hand-built (no external
// dependency) to keep the offline/single-binary constraint.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func ruleID(title string) string {
	s := slugRe.ReplaceAllString(strings.ToLower(title), "-")
	return "tyto." + strings.Trim(s, "-")
}

// sarifLevel maps a finding severity to a SARIF result level.
func sarifLevel(sev state.Severity) string {
	switch sev {
	case state.SeverityCritical, state.SeverityHigh:
		return "error"
	case state.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// RenderSARIF returns the engagement's findings as a SARIF 2.1.0 log.
func RenderSARIF(eng *engagement.Engagement, st *state.State) ([]byte, error) {
	var rules []sarifRule
	ruleIndex := map[string]int{}
	var results []sarifResult

	for _, f := range st.Findings() {
		id := ruleID(f.Title)
		idx, ok := ruleIndex[id]
		if !ok {
			idx = len(rules)
			ruleIndex[id] = idx
			rules = append(rules, sarifRule{
				ID:               id,
				Name:             f.Title,
				ShortDescription: sarifText{Text: f.Title},
				Properties:       map[string]any{"tool": f.Tool},
			})
		}
		results = append(results, sarifResult{
			RuleID:    id,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: messageText(f)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.Target}}}},
			Properties: map[string]any{
				"severity": f.Severity.String(), "validated": f.Validated, "tool": f.Tool,
			},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "tyto",
				Version:        version.Version,
				InformationURI: "https://github.com/dukotah/tyto",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

func messageText(f state.Finding) string {
	if f.Description != "" {
		return f.Description
	}
	return f.Title
}
