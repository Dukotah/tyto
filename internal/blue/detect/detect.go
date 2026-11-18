// Package detect is tyto blue's Sigma-based detection engine. It loads a corpus of
// Sigma rules (SigmaHQ YAML format) and evaluates a normalized event.Event against
// every loaded rule, emitting one Detection per rule with Matched set accordingly.
//
// # Why Sigma
//
// Sigma is the de-facto portable detection-rule format. Adopting it lets tyto blue
// reuse the large public corpus of community detections and lets analysts author
// new rules in a format they already know, instead of a bespoke DSL. The embedded
// evaluator is github.com/bradleyjkemp/sigma-go (MIT licensed).
//
// # Field mapping (event.Event -> Sigma field names)
//
// sigma-go evaluates a rule against an opaque event that it indexes as either a
// map[string]string or map[string]interface{} by the field names the rule's
// detection block references. eventMap below projects an event.Event onto such a
// map. The chosen key names follow the Sysmon / SigmaHQ process_creation and
// web/proxy conventions so the embedded rules read naturally:
//
//	Sigma field        <- event.Event source
//	-----------------     -------------------------------
//	Image, Process     <- Process
//	ParentImage,
//	  ParentProcess    <- ParentProcess
//	CommandLine        <- CommandLine
//	User               <- User
//	Computer, Host     <- Host
//	TargetFilename,
//	  FilePath         <- FilePath
//	SrcIp, SrcIP       <- SrcIP
//	DstIp, DstIP       <- DstIP
//	SrcPort            <- SrcPort (decimal string)
//	DstPort            <- DstPort (decimal string)
//	Class              <- Class
//	Activity           <- Activity
//	Category           <- Category
//	Message            <- Message
//
// Every key/value from Event.RawFields is additionally copied in verbatim (never
// overwriting a mapped key), which is how web/proxy rules reach fields such as
// c-useragent and cs-uri that adapters park in RawFields. Event values here are the
// raw (un-sanitized) strings: Sigma matching needs the original bytes, and a
// Detection never renders them into a model prompt — event.Event.Content() /
// SafeMeta() remain the only model-facing projections.
//
// # Limitations (v1)
//
// sigma-go has no cross-event aggregation or correlation state, so count()/near
// style rules and Sigma correlation rules are out of scope here: each Eval call
// judges a single event in isolation.
//
// TODO(correlation): add a stateful correlation layer above Detector (sliding
// windows keyed by host/user, count thresholds, rule chaining) so multi-event
// detections — brute-force bursts, beaconing, tool sequences — can fire. That layer
// should consume the per-event Detection stream this package already emits.
package detect

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"

	"github.com/dukotah/tyto/internal/blue/event"
)

//go:embed rules/*.yml
var ruleFS embed.FS

// Detection is the result of evaluating one Sigma rule against one event. One is
// produced per loaded rule on every Eval call; Matched reports whether the rule
// fired. RuleAuthor is carried through so a UI can honor Sigma's DRL attribution
// requirement for rules adapted from the community corpus.
type Detection struct {
	RuleID     string         // Sigma rule id
	RuleTitle  string         // Sigma rule title
	RuleAuthor string         // Sigma rule author (attribution)
	Technique  string         // ATT&CK technique id extracted from tags, e.g. "T1059.001" ("" if none)
	Severity   event.Severity // mapped from the rule's level:
	Event      event.Event    // the event that was evaluated
	Matched    bool           // whether the rule matched the event
}

// loadedRule bundles a parsed Sigma rule with its compiled evaluator and the
// metadata we pre-extract once at load time.
type loadedRule struct {
	meta      RuleMeta
	evaluator *evaluator.RuleEvaluator
}

// RuleMeta is the immutable metadata of a loaded rule, exposed via Rules().
type RuleMeta struct {
	ID        string
	Title     string
	Author    string
	Level     string
	Technique string
	Severity  event.Severity
	Tags      []string
	Source    string // embedded file name the rule was parsed from
}

// Detector holds a compiled corpus of Sigma rules and evaluates events against them.
// Construct with NewDetector. A Detector is read-only after construction and safe
// for concurrent use by multiple goroutines.
type Detector struct {
	rules []loadedRule
}

// NewDetector parses and compiles the embedded Sigma rule corpus. It returns an
// error if any embedded rule fails to parse or carries no ATT&CK technique tag
// (the corpus invariant that keeps every detection technique-attributable).
func NewDetector() (*Detector, error) {
	entries, err := fs.ReadDir(ruleFS, "rules")
	if err != nil {
		return nil, fmt.Errorf("detect: reading embedded rules: %w", err)
	}

	// Deterministic order by filename so Eval output ordering is stable.
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	d := &Detector{}
	for _, name := range names {
		raw, err := ruleFS.ReadFile("rules/" + name)
		if err != nil {
			return nil, fmt.Errorf("detect: reading embedded rule %s: %w", name, err)
		}
		rule, err := sigma.ParseRule(raw)
		if err != nil {
			return nil, fmt.Errorf("detect: parsing rule %s: %w", name, err)
		}
		technique := techniqueFromTags(rule.Tags)
		if technique == "" {
			return nil, fmt.Errorf("detect: rule %s (%q) has no attack.tXXXX technique tag", name, rule.Title)
		}
		d.rules = append(d.rules, loadedRule{
			meta: RuleMeta{
				ID:        rule.ID,
				Title:     rule.Title,
				Author:    rule.Author,
				Level:     rule.Level,
				Technique: technique,
				Severity:  severityFromLevel(rule.Level),
				Tags:      rule.Tags,
				Source:    name,
			},
			evaluator: evaluator.ForRule(rule),
		})
	}

	if len(d.rules) == 0 {
		return nil, fmt.Errorf("detect: embedded rule corpus is empty")
	}
	return d, nil
}

// Eval evaluates e against every loaded rule and returns the Detections that
// matched. The returned slice is ordered by rule source filename (stable). A rule
// whose evaluation errors (malformed at runtime) is skipped rather than failing the
// whole batch; such errors are not expected from the embedded corpus, which is
// validated at load time.
func (d *Detector) Eval(e event.Event) []Detection {
	evt := eventMap(e)
	ctx := context.Background()

	out := make([]Detection, 0, 4)
	for _, r := range d.rules {
		res, err := r.evaluator.Matches(ctx, evt)
		if err != nil || !res.Match {
			continue
		}
		out = append(out, Detection{
			RuleID:     r.meta.ID,
			RuleTitle:  r.meta.Title,
			RuleAuthor: r.meta.Author,
			Technique:  r.meta.Technique,
			Severity:   r.meta.Severity,
			Event:      e,
			Matched:    true,
		})
	}
	return out
}

// RuleCount reports how many rules are loaded.
func (d *Detector) RuleCount() int { return len(d.rules) }

// Rules returns a copy of the loaded rules' metadata, ordered by source filename.
func (d *Detector) Rules() []RuleMeta {
	metas := make([]RuleMeta, 0, len(d.rules))
	for _, r := range d.rules {
		metas = append(metas, r.meta)
	}
	return metas
}

// eventMap projects an event.Event onto the field-name map sigma-go evaluates
// against. See the package doc for the full mapping table. RawFields are copied in
// without clobbering mapped keys.
func eventMap(e event.Event) map[string]interface{} {
	m := map[string]interface{}{
		"Image":          e.Process,
		"Process":        e.Process,
		"ParentImage":    e.ParentProcess,
		"ParentProcess":  e.ParentProcess,
		"CommandLine":    e.CommandLine,
		"User":           e.User,
		"Computer":       e.Host,
		"Host":           e.Host,
		"TargetFilename": e.FilePath,
		"FilePath":       e.FilePath,
		"SrcIp":          e.SrcIP,
		"SrcIP":          e.SrcIP,
		"DstIp":          e.DstIP,
		"DstIP":          e.DstIP,
		"Class":          e.Class,
		"Activity":       e.Activity,
		"Category":       e.Category,
		"Message":        e.Message,
	}
	if e.SrcPort != 0 {
		m["SrcPort"] = strconv.Itoa(e.SrcPort)
	}
	if e.DstPort != 0 {
		m["DstPort"] = strconv.Itoa(e.DstPort)
	}
	for k, v := range e.RawFields {
		if _, taken := m[k]; !taken {
			m[k] = v
		}
	}
	return m
}

// techniqueFromTags extracts the first MITRE ATT&CK technique id from Sigma tags.
// Sigma encodes techniques as lowercase "attack.tXXXX" / "attack.tXXXX.YYY" tags;
// this returns the canonical uppercase id (e.g. "T1059.001"), or "" if none.
func techniqueFromTags(tags []string) string {
	for _, t := range tags {
		lt := strings.ToLower(strings.TrimSpace(t))
		const prefix = "attack.t"
		if !strings.HasPrefix(lt, prefix) {
			continue
		}
		id := strings.TrimPrefix(lt, "attack.") // "t1059.001"
		if len(id) < 2 || id[0] != 't' || id[1] < '0' || id[1] > '9' {
			continue
		}
		return strings.ToUpper(id)
	}
	return ""
}

// severityFromLevel maps a Sigma level: string to an event.Severity.
func severityFromLevel(level string) event.Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return event.SevCritical
	case "high":
		return event.SevHigh
	case "medium":
		return event.SevMedium
	case "low":
		return event.SevLow
	case "informational", "info":
		return event.SevInfo
	default:
		return event.SevUnknown
	}
}
