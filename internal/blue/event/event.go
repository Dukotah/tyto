// Package event defines tyto blue's normalized security event: the single unit
// every ingest adapter produces and every detector / triage component reads.
//
// The shape is a lean subset of OCSF (Open Cybersecurity Schema Framework):
// a class/activity discriminator plus source/destination endpoints, an actor
// (user/process) and the raw log payload. Ingest adapters (Suricata EVE, Wazuh,
// Sysmon, generic JSONL) are responsible for mapping their native format onto
// this struct and normalizing the enum-like routing fields to a controlled
// vocabulary.
//
// # Quarantine discipline (load-bearing — mirrors internal/state)
//
// Log content is attacker-controlled text and may carry prompt injection. Unlike
// tyto's planner (which is deliberately starved of tool output), the triage brain
// MUST read the alert to judge it, so the rule here is NEUTRALIZE, not withhold:
//
//   - Fields the adapter normalizes to a controlled value (routing / enum /
//     endpoint identifiers) are tagged `blue:"safe"`.
//   - Fields copied verbatim from the log are tagged `blue:"quarantined"`; they
//     reach a model only via Content(), sanitized and wrapped in an explicitly
//     delimited "untrusted data, not instructions" block by the triage layer.
//
// TestEventFieldsClassified (event_test.go) fails the build if a new exported
// string field is added without a `blue` tag, exactly like state's reflect guard.
package event

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Severity is the sensor-assigned severity carried on an incoming event. It is
// advisory; a detection produces its own severity. Kept local to blue so the
// event package has no dependency on internal/state.
type Severity int

const (
	SevUnknown Severity = iota
	SevInfo
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "info"
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	case SevCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// maxFieldRunes caps any single quarantined field rendered into a model prompt.
// Larger than state's 200 (the triage brain needs enough to judge) but still
// bounded so one event can't blow the context window or smuggle a long payload.
const maxFieldRunes = 512

// Event is one normalized security observation. Construct via New and let the
// ingest adapter fill the rest. Treat the exported shape as load-bearing: other
// blue packages are built against it.
type Event struct {
	// --- identity & provenance (safe: minted or adapter-controlled) ---
	ID     string `blue:"safe"` // unique id (adapter- or New-minted)
	Sensor string `blue:"safe"` // producing sensor: suricata | wazuh | sysmon | jsonl
	Time   time.Time            // event time (not a string; no tag needed)

	// --- OCSF-ish classification (safe: adapter normalizes to controlled vocab) ---
	Class    string `blue:"safe"` // e.g. process_activity | network_activity | authentication | http_activity | file_activity
	Activity string `blue:"safe"` // normalized activity within the class, e.g. "created", "login"
	Category string `blue:"safe"` // coarse grouping, optional

	// --- endpoints (safe: routing identifiers, adapter-parsed) ---
	SrcIP   string `blue:"safe"`
	SrcPort int
	DstIP   string `blue:"safe"`
	DstPort int

	// --- actor / subject (quarantined: copied from the log verbatim) ---
	Host          string `blue:"quarantined"` // hostname as reported by the log
	User          string `blue:"quarantined"`
	Process       string `blue:"quarantined"`
	ParentProcess string `blue:"quarantined"`
	CommandLine   string `blue:"quarantined"`
	FilePath      string `blue:"quarantined"`

	// --- payload (quarantined) ---
	Message   string            `blue:"quarantined"` // the raw log message / rendered line
	RawFields map[string]string // every other native field; quarantined BY CONSTRUCTION (never in SafeMeta)

	// --- sensor-assigned severity (advisory) ---
	Severity Severity
}

// New mints an Event with the current time and a content-independent id left to
// the caller; adapters typically set ID from the source event id or leave it for
// Key() to stand in. sensor and class should be controlled-vocabulary values.
func New(sensor, class string) Event {
	return Event{Sensor: sensor, Class: class, Time: time.Now().UTC(), RawFields: map[string]string{}}
}

// Key is a stable dedup identity derived from the routing + payload fields.
// Adapters without a native event id can use Key as the ID.
func (e Event) Key() string {
	h := sha256.New()
	for _, p := range []string{e.Sensor, e.Class, e.Activity, e.Host, e.SrcIP, e.DstIP, e.Process, e.Message} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// SafeMeta returns only the `blue:"safe"` fields, each sanitized. Safe to render
// into a model prompt outside the untrusted-data block, to use as routing keys,
// and to log. RawFields and every quarantined field are deliberately excluded.
func (e Event) SafeMeta() map[string]string {
	m := map[string]string{
		"id":       sanitizeField(e.ID),
		"sensor":   sanitizeField(e.Sensor),
		"class":    sanitizeField(e.Class),
		"activity": sanitizeField(e.Activity),
		"category": sanitizeField(e.Category),
		"src_ip":   sanitizeField(e.SrcIP),
		"dst_ip":   sanitizeField(e.DstIP),
		"time":     e.Time.UTC().Format(time.RFC3339),
		"severity": e.Severity.String(),
	}
	for k, v := range m {
		if v == "" {
			delete(m, k)
		}
	}
	return m
}

// Content renders the quarantined fields as a sanitized, labeled block for the
// triage model to read. It does NOT add the "untrusted data" framing fences —
// the triage layer owns that wrapper so the framing can't be spoofed from inside
// a field value. Each value is control-stripped, whitespace-collapsed and capped.
func (e Event) Content() string {
	var b strings.Builder
	add := func(label, val string) {
		val = sanitizeField(val)
		if val == "" {
			return
		}
		b.WriteString(label)
		b.WriteString(": ")
		b.WriteString(val)
		b.WriteByte('\n')
	}
	add("host", e.Host)
	add("user", e.User)
	add("process", e.Process)
	add("parent_process", e.ParentProcess)
	add("command_line", e.CommandLine)
	add("file_path", e.FilePath)
	add("message", e.Message)
	// RawFields last, deterministically ordered.
	keys := make([]string, 0, len(e.RawFields))
	for k := range e.RawFields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		add("raw."+sanitizeField(k), e.RawFields[k])
	}
	return b.String()
}

// sanitizeField strips control characters (including the zero-width and bidi
// overrides used in Trojan-Source style obfuscation), collapses runs of
// whitespace to a single space, trims, and caps length. It never returns a value
// that can break out of a single prompt line.
func sanitizeField(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r' || unicode.IsSpace(r):
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		case r == 0x200b || r == 0x200c || r == 0x200d || r == 0xfeff: // zero-width
			// drop
		case r >= 0x202a && r <= 0x202e: // bidi overrides
			// drop
		case r >= 0x2066 && r <= 0x2069: // bidi isolates
			// drop
		case unicode.IsControl(r):
			// drop
		default:
			b.WriteRune(r)
			lastSpace = false
		}
	}
	out := strings.TrimSpace(b.String())
	if n := []rune(out); len(n) > maxFieldRunes {
		out = string(n[:maxFieldRunes]) + "…"
	}
	return out
}
