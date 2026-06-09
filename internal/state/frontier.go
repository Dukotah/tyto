package state

import "sort"

// Frontier is a deterministic, Go-computed next-step hint for one discovered
// service asset. The engine derives the frontier from State.Assets() and
// surfaces it to the planner so the model SELECTS a service-appropriate action
// rather than parsing raw tool output to work out what to do next. This is a
// minimal placeholder for the full methodology task tree (a later roadmap item);
// the Suggested strings are free-text hints, not authoritative tool names.
//
// Display fields are sanitized like any other planner-facing text, so the
// frontier cannot become a side channel around the quarantine boundary.
type Frontier struct {
	AssetID   string // for logic/tests; never rendered into the prompt
	AssetType string
	Value     string
	Service   string
	Port      string
	Suggested []string
}

// Frontier computes the current technique frontier from known service assets,
// sorted by Value for a deterministic prompt.
func (s *State) Frontier() []Frontier {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Frontier
	for _, a := range s.assets {
		if a.Type != "service" {
			continue
		}
		svc := a.Attrs["service"]
		out = append(out, Frontier{
			AssetID:   a.ID,
			AssetType: sanitizeField(a.Type),
			Value:     sanitizeField(a.Value),
			Service:   sanitizeField(svc),
			Port:      sanitizeField(a.Attrs["port"]),
			Suggested: suggestionsFor(svc),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

// suggestionsFor maps a coarse service label to deterministic next-step hints.
func suggestionsFor(service string) []string {
	switch service {
	case "http", "https":
		return []string{"web content discovery", "http fingerprinting"}
	case "ssh":
		return []string{"ssh version and auth enumeration"}
	case "ftp":
		return []string{"ftp anonymous-login check"}
	case "smb":
		return []string{"smb share enumeration"}
	case "mysql":
		return []string{"database service enumeration"}
	case "rdp":
		return []string{"rdp exposure check"}
	case "dns":
		return []string{"dns record enumeration"}
	case "smtp":
		return []string{"smtp user and relay enumeration"}
	case "":
		return []string{"service fingerprinting"}
	default:
		return []string{"service-specific enumeration"}
	}
}
