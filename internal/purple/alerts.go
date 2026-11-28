package purple

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Alert is one defender-side detection, normalized from whatever the SIEM/EDR/
// WAF exported. Only Time is required; everything else sharpens correlation.
type Alert struct {
	Line       int       `json:"line"` // 1-based record number in the export
	Time       time.Time `json:"time"`
	Name       string    `json:"name,omitempty"`
	Source     string    `json:"source,omitempty"` // attacker-side address, if the alert names one
	Target     string    `json:"target,omitempty"` // victim-side host/IP, if the alert names one
	Techniques []string  `json:"techniques,omitempty"`
	Severity   string    `json:"severity,omitempty"`
}

// Field aliases, in priority order. Keys are matched case-insensitively against
// flattened (dotted) field names, first exactly and then by trailing segment, so
// ECS ("destination.ip"), Splunk CIM ("dest"), Sentinel ("TimeGenerated") and
// hand-rolled exports all load without a mapping file.
var (
	timeKeys   = []string{"@timestamp", "timestamp", "_time", "time", "timegenerated", "event_time", "eventtime", "event.created", "created_at", "created", "start_time", "starttime", "first_seen", "firstseen", "date", "datetime"}
	nameKeys   = []string{"rule.name", "rule_name", "alert.signature", "signature", "alertname", "alert_name", "displayname", "search_name", "rule", "name", "title", "message", "description"}
	targetKeys = []string{"destination.ip", "dest_ip", "dst_ip", "destinationip", "destination.address", "destination.domain", "dest_host", "dest", "dst", "destination", "target", "url.domain", "host.name", "hostname", "host", "computer", "devicename", "device", "url"}
	sourceKeys = []string{"source.ip", "src_ip", "sourceip", "source.address", "client.ip", "client_ip", "clientip", "remote_addr", "remoteip", "src", "source", "attacker"}
	techKeys   = []string{"threat.technique.id", "threat.technique.subtechnique.id", "mitre_technique_id", "mitre_attack_id", "technique_id", "techniques", "technique", "mitre_attack", "mitre", "attack_id", "annotations.mitre_attack"}
	sevKeys    = []string{"event.severity", "alert.severity", "alertseverity", "severity", "level", "priority", "urgency"}
)

var techniqueRE = regexp.MustCompile(`\bT\d{4}(?:\.\d{3})?\b`)

// ParseAlerts reads a defender alert export. The format is sniffed: a JSON array,
// a JSON object wrapping an array, newline-delimited JSON, or CSV with a header
// row. loc is the zone assumed for timestamps that carry none (nil = UTC).
// Records with no parseable timestamp are returned in skipped (by record number)
// rather than failing the whole load — one bad row must not hide the rest.
func ParseAlerts(r io.Reader, loc *time.Location) (alerts []Alert, skipped []int, err error) {
	if loc == nil {
		loc = time.UTC
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // UTF-8 BOM
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil, nil
	}

	var records []map[string]string
	switch trimmed[0] {
	case '[':
		var raw []any
		if err := json.Unmarshal(trimmed, &raw); err != nil {
			return nil, nil, fmt.Errorf("alerts: invalid JSON array: %w", err)
		}
		for _, item := range raw {
			records = append(records, flatten(item))
		}
	case '{':
		records, err = parseJSONObjects(trimmed)
		if err != nil {
			return nil, nil, err
		}
	default:
		records, err = parseCSV(trimmed)
		if err != nil {
			return nil, nil, err
		}
	}

	for i, rec := range records {
		ts, ok := parseTime(lookup(rec, timeKeys), loc)
		if !ok {
			skipped = append(skipped, i+1)
			continue
		}
		a := Alert{
			Line: i + 1, Time: ts.UTC(),
			Name:     lookup(rec, nameKeys),
			Source:   HostOf(lookup(rec, sourceKeys)),
			Target:   HostOf(lookup(rec, targetKeys)),
			Severity: lookup(rec, sevKeys),
		}
		// Technique ids can sit in a dedicated field or be embedded in the rule name
		// / tags; scan the dedicated fields first, then the name.
		seen := map[string]bool{}
		for _, src := range []string{lookupAll(rec, techKeys), a.Name} {
			for _, id := range techniqueRE.FindAllString(strings.ToUpper(src), -1) {
				if !seen[id] {
					seen[id] = true
					a.Techniques = append(a.Techniques, id)
				}
			}
		}
		alerts = append(alerts, a)
	}
	sort.SliceStable(alerts, func(i, j int) bool { return alerts[i].Time.Before(alerts[j].Time) })
	return alerts, skipped, nil
}

// parseJSONObjects handles input starting with '{': either NDJSON, or a single
// object that wraps the alert array (e.g. {"alerts":[...]}, Elasticsearch's
// {"hits":{"hits":[...]}}), or one lone alert.
func parseJSONObjects(data []byte) ([]map[string]string, error) {
	var single map[string]any
	if err := json.Unmarshal(data, &single); err == nil {
		if arr := findRecordArray(single); arr != nil {
			var out []map[string]string
			for _, item := range arr {
				out = append(out, flatten(item))
			}
			return out, nil
		}
		return []map[string]string{flatten(single)}, nil
	}
	var out []map[string]string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	n := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		n++
		if len(line) == 0 {
			continue
		}
		var obj any
		if err := json.Unmarshal(line, &obj); err != nil {
			return nil, fmt.Errorf("alerts: line %d is not valid JSON: %w", n, err)
		}
		out = append(out, flatten(obj))
	}
	return out, sc.Err()
}

// findRecordArray looks (two levels deep) for the array of objects a wrapper
// object carries its records in.
func findRecordArray(obj map[string]any) []any {
	for _, k := range []string{"alerts", "results", "hits", "records", "events", "value", "data", "items"} {
		switch v := obj[k].(type) {
		case []any:
			return v
		case map[string]any:
			if inner, ok := v["hits"].([]any); ok {
				return inner
			}
		}
	}
	return nil
}

func parseCSV(data []byte) ([]map[string]string, error) {
	rd := csv.NewReader(bytes.NewReader(data))
	rd.FieldsPerRecord = -1
	rd.LazyQuotes = true
	rows, err := rd.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("alerts: not JSON and not valid CSV: %w", err)
	}
	if len(rows) < 2 {
		return nil, nil
	}
	header := rows[0]
	var out []map[string]string
	for _, row := range rows[1:] {
		rec := map[string]string{}
		for i, cell := range row {
			if i < len(header) {
				rec[normKey(header[i])] = strings.TrimSpace(cell)
			}
		}
		out = append(out, rec)
	}
	return out, nil
}

// flatten turns nested JSON into lower-cased dotted keys with string values.
// Arrays of scalars are comma-joined; arrays of objects are merged key-wise.
func flatten(v any) map[string]string {
	out := map[string]string{}
	var walk func(prefix string, v any)
	add := func(k, s string) {
		if s == "" {
			return
		}
		if prev, ok := out[k]; ok && prev != "" {
			out[k] = prev + "," + s
		} else {
			out[k] = s
		}
	}
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, child := range t {
				key := normKey(k)
				// Elasticsearch wraps the document in _source; drop that level.
				if prefix == "" && key == "_source" {
					walk("", child)
					continue
				}
				if prefix != "" {
					key = prefix + "." + key
				}
				walk(key, child)
			}
		case []any:
			for _, item := range t {
				walk(prefix, item)
			}
		case string:
			add(prefix, strings.TrimSpace(t))
		case float64:
			add(prefix, strconv.FormatFloat(t, 'f', -1, 64))
		case bool:
			add(prefix, strconv.FormatBool(t))
		}
	}
	walk("", v)
	return out
}

// normKey canonicalizes a field name: lower-cased, with spaces and dashes as
// underscores, so "Rule Name" and "rule-name" both match the alias "rule_name".
func normKey(k string) string {
	return strings.NewReplacer(" ", "_", "-", "_").Replace(strings.ToLower(strings.TrimSpace(k)))
}

// lookup returns the first non-empty value for the alias list: exact key match
// in alias priority order, then a trailing-segment match (".alias").
func lookup(rec map[string]string, aliases []string) string {
	for _, a := range aliases {
		if v := rec[a]; v != "" {
			return v
		}
	}
	keys := make([]string, 0, len(rec))
	for k := range rec {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, a := range aliases {
		for _, k := range keys {
			if strings.HasSuffix(k, "."+a) && rec[k] != "" {
				return rec[k]
			}
		}
	}
	return ""
}

// lookupAll joins every value whose key matches any alias (used for technique
// ids, which are often spread across several fields).
func lookupAll(rec map[string]string, aliases []string) string {
	var parts []string
	for k, v := range rec {
		for _, a := range aliases {
			if k == a || strings.HasSuffix(k, "."+a) {
				parts = append(parts, v)
				break
			}
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

var timeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999 Z0700",
	"2006-01-02 15:04:05.999999999 MST",
	time.RFC1123Z,
	time.RFC1123,
}

// zoneless layouts are interpreted in the caller-supplied location.
var zonelessLayouts = []string{
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999",
	"2006/01/02 15:04:05",
	"01/02/2006 15:04:05",
	"Jan 2 2006 15:04:05",
	"Jan 2, 2006 15:04:05",
}

func parseTime(s string, loc *time.Location) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	// A comma-joined value means the field appeared more than once; use the first.
	if i := strings.Index(s, ","); i > 0 && !strings.Contains(s[:i], " ") {
		if t, ok := parseTime(s[:i], loc); ok {
			return t, true
		}
	}
	// Epoch seconds or milliseconds.
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		switch {
		case f > 1e11: // milliseconds
			return time.UnixMilli(int64(f)).UTC(), true
		case f > 1e8: // seconds (2001 onwards)
			sec := int64(f)
			return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC(), true
		}
		return time.Time{}, false
	}
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	for _, l := range zonelessLayouts {
		if t, err := time.ParseInLocation(l, s, loc); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
