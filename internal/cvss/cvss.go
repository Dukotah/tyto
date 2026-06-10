// Package cvss implements a dependency-free CVSS v3.1 base score calculator.
package cvss

import (
	"fmt"
	"math"
	"strings"
)

// metricWeights maps a metric abbreviation to its allowed values and weights.
var (
	avWeights  = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acWeights  = map[string]float64{"L": 0.77, "H": 0.44}
	uiWeights  = map[string]float64{"N": 0.85, "R": 0.62}
	ciaWeights = map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}

	// PR weight depends on Scope.
	prUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
)

// requiredMetrics lists the base metrics that must be present in a vector.
var requiredMetrics = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

// BaseScore parses a CVSS v3.1 vector string and computes its base score per the
// official CVSS v3.1 specification. The "CVSS:3.1/" prefix is optional.
//
// It returns an error if any required base metric (AV, AC, PR, UI, S, C, I, A)
// is missing or has an invalid value.
func BaseScore(vector string) (float64, error) {
	metrics, err := parseVector(vector)
	if err != nil {
		return 0, err
	}

	// Scope must be parsed first; it influences the PR weight.
	scope, ok := metrics["S"]
	if !ok {
		return 0, fmt.Errorf("cvss: missing required metric S")
	}
	if scope != "U" && scope != "C" {
		return 0, fmt.Errorf("cvss: invalid value %q for metric S", scope)
	}
	scopeChanged := scope == "C"

	av, err := lookup(metrics, "AV", avWeights)
	if err != nil {
		return 0, err
	}
	ac, err := lookup(metrics, "AC", acWeights)
	if err != nil {
		return 0, err
	}
	ui, err := lookup(metrics, "UI", uiWeights)
	if err != nil {
		return 0, err
	}
	c, err := lookup(metrics, "C", ciaWeights)
	if err != nil {
		return 0, err
	}
	i, err := lookup(metrics, "I", ciaWeights)
	if err != nil {
		return 0, err
	}
	a, err := lookup(metrics, "A", ciaWeights)
	if err != nil {
		return 0, err
	}

	prTable := prUnchanged
	if scopeChanged {
		prTable = prChanged
	}
	pr, err := lookup(metrics, "PR", prTable)
	if err != nil {
		return 0, err
	}

	iscBase := 1 - ((1 - c) * (1 - i) * (1 - a))

	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}

	exploitability := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		return 0.0, nil
	}

	var score float64
	if scopeChanged {
		score = roundup(math.Min(1.08*(impact+exploitability), 10))
	} else {
		score = roundup(math.Min(impact+exploitability, 10))
	}
	return score, nil
}

// Severity returns the CVSS v3.1 qualitative rating for a base score.
func Severity(score float64) string {
	switch {
	case score <= 0.0:
		return "none"
	case score < 4.0:
		return "low"
	case score < 7.0:
		return "medium"
	case score < 9.0:
		return "high"
	default:
		return "critical"
	}
}

// parseVector splits a vector string into a metric->value map, validating the
// optional "CVSS:3.1/" prefix and the metric:value syntax.
func parseVector(vector string) (map[string]string, error) {
	vector = strings.TrimSpace(vector)
	if vector == "" {
		return nil, fmt.Errorf("cvss: empty vector")
	}

	parts := strings.Split(vector, "/")
	metrics := make(map[string]string)

	for _, part := range parts {
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("cvss: malformed component %q", part)
		}
		key, val := kv[0], kv[1]

		// Handle the optional version prefix "CVSS:3.1".
		if key == "CVSS" {
			if val != "3.1" {
				return nil, fmt.Errorf("cvss: unsupported version %q", val)
			}
			continue
		}

		if _, dup := metrics[key]; dup {
			return nil, fmt.Errorf("cvss: duplicate metric %q", key)
		}
		metrics[key] = val
	}

	for _, m := range requiredMetrics {
		if _, ok := metrics[m]; !ok {
			return nil, fmt.Errorf("cvss: missing required metric %s", m)
		}
	}

	return metrics, nil
}

// lookup resolves a metric's weight from a table, returning an error on an
// invalid value.
func lookup(metrics map[string]string, name string, table map[string]float64) (float64, error) {
	val := metrics[name]
	w, ok := table[val]
	if !ok {
		return 0, fmt.Errorf("cvss: invalid value %q for metric %s", val, name)
	}
	return w, nil
}

// roundup rounds x up to the nearest 0.1 using the official CVSS v3.1 integer
// method.
func roundup(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000.0
	}
	return (math.Floor(float64(i)/10000) + 1) / 10.0
}
