// Package ingest turns raw security-log bytes/streams into tyto blue's
// normalized event.Event. Each supported log format has an Adapter that reads a
// stream (one record per line) and emits a slice of normalized events.
//
// # Controlled vocabulary
//
// Adapters normalize the routing fields event.Class and event.Activity onto a
// deliberately small, closed vocabulary so downstream detection/triage can match
// on stable values regardless of the producing sensor. Native format-specific
// values that don't map are preserved verbatim in Event.RawFields (stringified),
// never silently dropped.
//
//	Class (the coarse OCSF-ish kind of observation):
//	  network_activity  L3/L4 flows, firewall/IDS network events, TLS
//	  http_activity     HTTP/web requests
//	  dns_activity      DNS queries/answers
//	  file_activity     file create/modify/delete, FIM/syscheck
//	  process_activity  process creation / execution
//	  authentication    login / logon / auth success & failure
//	  alert             a sensor detection with no finer OCSF class
//	  unknown           could not be classified
//
//	Activity (the normalized verb within a Class):
//	  detected          a rule/signature fired (generic alert)
//	  flow              a network flow/connection record
//	  request           an HTTP request
//	  query             a DNS query
//	  login             an authentication success
//	  login_failed      an authentication failure
//	  created           an object (process/file) was created
//	  tls               a TLS handshake/session record
//	  transfer          a file transfer / fileinfo record
//	  observed          a generic observation (fallback)
//
// # Robustness
//
// Blank lines are skipped. A line that fails to parse is skipped and ingestion
// continues over the rest of the stream — one poisoned record never aborts a
// batch. If NOTHING parses (every non-blank line was malformed) the adapter
// returns a *ParseError carrying the skipped count and the first underlying
// error, so the caller can tell "empty input" from "all garbage". A low-level
// stream/IO error is also surfaced as a *ParseError, alongside whatever parsed.
//
// Only the standard library is used (encoding/json, bufio, io, strconv,
// strings, time).
package ingest

import (
	"bufio"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/blue/event"
)

// Controlled Class vocabulary. See the package doc for semantics.
const (
	ClassNetwork = "network_activity"
	ClassHTTP    = "http_activity"
	ClassDNS     = "dns_activity"
	ClassFile    = "file_activity"
	ClassProcess = "process_activity"
	ClassAuth    = "authentication"
	ClassAlert   = "alert"
	ClassUnknown = "unknown"
)

// Controlled Activity vocabulary. See the package doc for semantics.
const (
	ActDetected    = "detected"
	ActFlow        = "flow"
	ActRequest     = "request"
	ActQuery       = "query"
	ActLogin       = "login"
	ActLoginFailed = "login_failed"
	ActCreated     = "created"
	ActTLS         = "tls"
	ActTransfer    = "transfer"
	ActObserved    = "observed"
)

// maxLineBytes bounds a single log record. Realistic EVE/Wazuh lines (full_log,
// long HTTP URLs) routinely exceed bufio.Scanner's 64KiB default, so we raise the
// ceiling to 1MiB; anything larger is treated as a malformed line and skipped.
const maxLineBytes = 1 << 20

// Adapter parses a stream of a single log format into normalized events.
type Adapter interface {
	// Parse consumes r to EOF, returning every event it could normalize. It
	// skips blank and malformed lines; see package doc for the error contract.
	Parse(r io.Reader) ([]event.Event, error)
}

// ParseError reports that ingestion skipped lines. It is returned when nothing
// parsed (so the caller can distinguish empty input from all-malformed input) or
// when the underlying stream errored. Parsed/Skipped are line counts and First
// is the first underlying error message encountered.
type ParseError struct {
	Parsed  int
	Skipped int
	First   string
}

func (e *ParseError) Error() string {
	var b strings.Builder
	b.WriteString("ingest: ")
	if e.Parsed == 0 {
		b.WriteString("no events parsed")
	} else {
		b.WriteString("stream ended with errors")
	}
	b.WriteString(" (parsed=")
	b.WriteString(strconv.Itoa(e.Parsed))
	b.WriteString(", skipped=")
	b.WriteString(strconv.Itoa(e.Skipped))
	b.WriteString(")")
	if e.First != "" {
		b.WriteString(": ")
		b.WriteString(e.First)
	}
	return b.String()
}

// AdapterFor picks an adapter by sensor name. Unknown sensors fall back to the
// generic JSONL adapter so arbitrary flat JSON still ingests.
func AdapterFor(sensor string) Adapter {
	switch strings.ToLower(strings.TrimSpace(sensor)) {
	case "suricata", "eve", "suricata-eve":
		return EVEAdapter{}
	case "wazuh", "ossec", "wazuh-alerts":
		return WazuhAdapter{}
	default:
		return JSONLAdapter{}
	}
}

// Parse is a convenience that selects an adapter by sensor and runs it.
func Parse(sensor string, r io.Reader) ([]event.Event, error) {
	return AdapterFor(sensor).Parse(r)
}

// parseStream is the shared line loop: it scans r, skips blanks, delegates each
// non-blank line to parseLine, and tolerates per-line failures. It enforces the
// package error contract uniformly across adapters.
func parseStream(r io.Reader, parseLine func([]byte) (event.Event, error)) ([]event.Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	var out []event.Event
	var skipped int
	var first string
	for sc.Scan() {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		ev, err := parseLine([]byte(text))
		if err != nil {
			skipped++
			if first == "" {
				first = err.Error()
			}
			continue
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		return out, &ParseError{Parsed: len(out), Skipped: skipped, First: err.Error()}
	}
	if len(out) == 0 && skipped > 0 {
		return out, &ParseError{Parsed: 0, Skipped: skipped, First: first}
	}
	return out, nil
}

// --- shared normalization helpers ---

// timeLayouts are tried in order. Suricata emits a numeric zone offset with no
// colon ("+0000"); Wazuh emits millisecond precision; generic logs vary.
var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999-0700",
	"2006-01-02T15:04:05-0700",
	"2006-01-02T15:04:05.999Z0700",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05.999999",
}

// parseTime best-effort parses a timestamp string (layouts above, then epoch
// seconds). Returns ok=false if nothing matched, letting the caller keep the
// event.New() "now" value.
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil && n > 0 {
		sec := int64(n)
		nsec := int64((n - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC(), true
	}
	return time.Time{}, false
}

// stringify renders a decoded JSON value as a compact string for RawFields.
// Nested objects/arrays are re-marshaled to JSON so nothing is lost.
func stringify(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// addLeftover copies every top-level raw key not already consumed into RawFields,
// stringified. This is how unmapped native fields are preserved rather than lost.
func addLeftover(ev *event.Event, raw map[string]json.RawMessage, consumed map[string]bool) {
	for k, rm := range raw {
		if consumed[k] {
			continue
		}
		var v interface{}
		if err := json.Unmarshal(rm, &v); err != nil {
			if s := strings.TrimSpace(string(rm)); s != "" {
				ev.RawFields[k] = s
			}
			continue
		}
		if s := stringify(v); s != "" {
			ev.RawFields[k] = s
		}
	}
}

// putRaw records a non-empty value under key in RawFields (used for notable
// nested native fields that addLeftover can't reach).
func putRaw(ev *event.Event, key, val string) {
	if val = strings.TrimSpace(val); val != "" {
		ev.RawFields[key] = val
	}
}

// --- severity helpers ---

// severityFromString maps named or numeric-string severities to buckets.
func severityFromString(s string) event.Severity {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "crit", "emergency", "fatal":
		return event.SevCritical
	case "high", "error", "err":
		return event.SevHigh
	case "medium", "med", "moderate", "warning", "warn":
		return event.SevMedium
	case "low", "notice":
		return event.SevLow
	case "info", "informational", "information", "debug":
		return event.SevInfo
	}
	if n, err := strconv.Atoi(s); err == nil {
		return severityFromNumber(n)
	}
	return event.SevUnknown
}

// severityFromNumber maps an unlabeled numeric severity to a bucket. Generic logs
// carry no shared scale, so this is a documented best-effort heuristic.
func severityFromNumber(n int) event.Severity {
	switch {
	case n <= 0:
		return event.SevInfo
	case n <= 3:
		return event.SevLow
	case n <= 6:
		return event.SevMedium
	case n <= 9:
		return event.SevHigh
	default:
		return event.SevCritical
	}
}

// parseSeverity maps a decoded JSON severity value (string or number) to a bucket.
func parseSeverity(v interface{}) event.Severity {
	switch t := v.(type) {
	case string:
		return severityFromString(t)
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return severityFromNumber(int(i))
		}
	case float64:
		return severityFromNumber(int(t))
	}
	return event.SevUnknown
}

// flexString decodes a JSON field that may be either a string or a number into a
// string. Wazuh's data.srcport et al. are sometimes quoted, sometimes not.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" || s == "" {
		*f = ""
		return nil
	}
	if s[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		*f = flexString(str)
		return nil
	}
	*f = flexString(strings.Trim(s, `"`))
	return nil
}

func (f flexString) atoi() int {
	n, err := strconv.Atoi(strings.TrimSpace(string(f)))
	if err != nil {
		return 0
	}
	return n
}
