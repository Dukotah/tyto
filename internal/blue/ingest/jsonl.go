package ingest

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/dukotah/tyto/internal/blue/event"
)

// JSONLAdapter is the fallback for arbitrary flat JSON objects (one per line). It
// maps common field aliases onto event.Event and drops everything else into
// RawFields, so no data is lost even for an unknown schema.
type JSONLAdapter struct{}

// field alias tables: the first present key wins. Keys are matched exactly (the
// input key is lower-cased before lookup).
var (
	aliasTime    = []string{"timestamp", "time", "@timestamp", "ts", "eventtime", "event_time", "datetime"}
	aliasSrcIP   = []string{"src_ip", "srcip", "source_ip", "source", "client_ip", "clientip", "src"}
	aliasDstIP   = []string{"dest_ip", "dst_ip", "dstip", "destination_ip", "destip", "dst"}
	aliasSrcPort = []string{"src_port", "srcport", "source_port", "sport"}
	aliasDstPort = []string{"dest_port", "dst_port", "dstport", "destination_port", "dport"}
	aliasHost    = []string{"host", "hostname", "computer", "computer_name", "agent_name", "agent", "device"}
	aliasUser    = []string{"user", "username", "user_name", "account", "account_name", "src_user", "srcuser"}
	aliasProc    = []string{"process", "process_name", "image", "proc", "exe"}
	aliasParent  = []string{"parent_process", "parent_process_name", "parent_image", "parent", "parentimage", "ppid_name"}
	aliasCmd     = []string{"command_line", "cmdline", "command", "cmd", "commandline"}
	aliasFile    = []string{"file_path", "filepath", "path", "file", "target_filename", "object", "filename"}
	aliasMsg     = []string{"message", "msg", "full_log", "log", "description", "alert", "event", "reason", "text"}
	aliasClass   = []string{"class", "event_type", "eventtype", "category", "type", "event_class"}
	aliasID      = []string{"id", "event_id", "eventid", "uuid", "_id", "uid"}
	aliasSev     = []string{"severity", "level", "priority", "sev"}
)

// Parse implements Adapter.
func (a JSONLAdapter) Parse(r io.Reader) ([]event.Event, error) {
	return parseStream(r, a.parseLine)
}

func (JSONLAdapter) parseLine(line []byte) (event.Event, error) {
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.UseNumber()
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		return event.Event{}, err
	}

	// Lower-case index so alias lookups are case-insensitive while the ORIGINAL
	// key is preserved for RawFields.
	lower := make(map[string]string, len(m))
	for k := range m {
		lk := strings.ToLower(k)
		if _, dup := lower[lk]; !dup {
			lower[lk] = k
		}
	}
	consumed := map[string]bool{}

	// pick returns the value + original key for the first matching alias.
	pick := func(aliases []string) (interface{}, string, bool) {
		for _, a := range aliases {
			if orig, ok := lower[a]; ok {
				return m[orig], orig, true
			}
		}
		return nil, "", false
	}
	take := func(aliases []string) (string, bool) {
		v, orig, ok := pick(aliases)
		if !ok {
			return "", false
		}
		consumed[orig] = true
		return stringify(v), true
	}

	ev := event.New("jsonl", ClassUnknown)
	ev.Activity = ActObserved

	// Class: normalize if recognized; keep the raw value in RawFields when not.
	if v, orig, ok := pick(aliasClass); ok {
		rawClass := stringify(v)
		if nc := normalizeClass(rawClass); nc != "" {
			ev.Class = nc
			consumed[orig] = true
			if nc == ClassUnknown {
				putRaw(&ev, "event_class_raw", rawClass)
			}
		}
	}

	if s, ok := take(aliasTime); ok {
		if t, ok := parseTime(s); ok {
			ev.Time = t
		}
	}
	if s, ok := take(aliasID); ok {
		ev.ID = s
	}
	if s, ok := take(aliasSrcIP); ok {
		ev.SrcIP = s
	}
	if s, ok := take(aliasDstIP); ok {
		ev.DstIP = s
	}
	if s, ok := take(aliasSrcPort); ok {
		ev.SrcPort = atoiSafe(s)
	}
	if s, ok := take(aliasDstPort); ok {
		ev.DstPort = atoiSafe(s)
	}
	if s, ok := take(aliasHost); ok {
		ev.Host = s
	}
	if s, ok := take(aliasUser); ok {
		ev.User = s
	}
	if s, ok := take(aliasProc); ok {
		ev.Process = s
	}
	if s, ok := take(aliasParent); ok {
		ev.ParentProcess = s
	}
	if s, ok := take(aliasCmd); ok {
		ev.CommandLine = s
	}
	if s, ok := take(aliasFile); ok {
		ev.FilePath = s
	}
	if s, ok := take(aliasMsg); ok {
		ev.Message = s
	}
	if v, orig, ok := pick(aliasSev); ok {
		ev.Severity = parseSeverity(v)
		consumed[orig] = true
	}

	// Everything not consumed is preserved verbatim.
	for k, v := range m {
		if consumed[k] {
			continue
		}
		if s := stringify(v); s != "" {
			ev.RawFields[k] = s
		}
	}
	return ev, nil
}

// normalizeClass maps a free-form class/event_type value onto the controlled
// vocab. Empty input returns "" (leave default); an unrecognized non-empty value
// returns ClassUnknown.
func normalizeClass(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ""
	case "network_activity", "network", "flow", "netflow", "conn", "connection", "traffic":
		return ClassNetwork
	case "http_activity", "http", "https", "web", "request":
		return ClassHTTP
	case "dns_activity", "dns", "query":
		return ClassDNS
	case "file_activity", "file", "fim", "syscheck", "fileinfo":
		return ClassFile
	case "process_activity", "process", "process_creation", "process_create", "proc", "sysmon", "exec", "execution":
		return ClassProcess
	case "authentication", "auth", "login", "logon", "logon_activity":
		return ClassAuth
	case "alert", "detection", "ids", "alerts":
		return ClassAlert
	default:
		return ClassUnknown
	}
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}
