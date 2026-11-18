package ingest

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/dukotah/tyto/internal/blue/event"
)

// EVEAdapter parses Suricata EVE JSON: one JSON object per line, discriminated by
// the "event_type" field (alert, dns, http, flow, tls, fileinfo, ...).
type EVEAdapter struct{}

// eveLine is the subset of EVE fields we map onto event.Event. Everything else on
// the line is preserved via addLeftover / explicit putRaw calls.
type eveLine struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	FlowID    int64  `json:"flow_id"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Host      string `json:"host"`

	Alert *struct {
		Action      string `json:"action"`
		SignatureID int    `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`

	DNS *struct {
		Type   string `json:"type"`
		Rrname string `json:"rrname"`
		Rrtype string `json:"rrtype"`
	} `json:"dns"`

	HTTP *struct {
		Hostname  string `json:"hostname"`
		URL       string `json:"url"`
		Method    string `json:"http_method"`
		Status    int    `json:"status"`
		UserAgent string `json:"http_user_agent"`
	} `json:"http"`
}

// Parse implements Adapter.
func (a EVEAdapter) Parse(r io.Reader) ([]event.Event, error) {
	return parseStream(r, a.parseLine)
}

func (EVEAdapter) parseLine(line []byte) (event.Event, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return event.Event{}, err
	}
	var e eveLine
	if err := json.Unmarshal(line, &e); err != nil {
		return event.Event{}, err
	}

	class, activity := eveClass(e.EventType)
	ev := event.New("suricata", class)
	ev.Activity = activity
	ev.Category = e.EventType

	if t, ok := parseTime(e.Timestamp); ok {
		ev.Time = t
	}
	if e.FlowID != 0 {
		ev.ID = strconv.FormatInt(e.FlowID, 10)
	}
	ev.SrcIP, ev.SrcPort = e.SrcIP, e.SrcPort
	ev.DstIP, ev.DstPort = e.DestIP, e.DestPort
	ev.Host = e.Host

	// Top-level keys we map (or deliberately re-key). proto, app_proto, in_iface,
	// etc. are intentionally NOT listed, so addLeftover carries them to RawFields.
	consumed := map[string]bool{
		"timestamp": true, "event_type": true, "flow_id": true,
		"src_ip": true, "src_port": true, "dest_ip": true, "dest_port": true,
		"host": true, "alert": true, "dns": true, "http": true,
	}

	switch {
	case e.Alert != nil:
		ev.Message = e.Alert.Signature
		if e.Alert.Category != "" {
			ev.Category = e.Alert.Category
		}
		ev.Severity = eveSeverity(e.Alert.Severity)
		putRaw(&ev, "alert.signature_id", strconv.Itoa(e.Alert.SignatureID))
		putRaw(&ev, "alert.action", e.Alert.Action)
	case e.DNS != nil:
		var b strings.Builder
		b.WriteString("DNS ")
		if e.DNS.Type != "" {
			b.WriteString(e.DNS.Type)
			b.WriteByte(' ')
		}
		b.WriteString(e.DNS.Rrname)
		if e.DNS.Rrtype != "" {
			b.WriteString(" (")
			b.WriteString(e.DNS.Rrtype)
			b.WriteByte(')')
		}
		ev.Message = b.String()
		ev.Severity = event.SevInfo
		putRaw(&ev, "dns.rrname", e.DNS.Rrname)
		putRaw(&ev, "dns.rrtype", e.DNS.Rrtype)
	case e.HTTP != nil:
		var b strings.Builder
		if e.HTTP.Method != "" {
			b.WriteString(e.HTTP.Method)
			b.WriteByte(' ')
		}
		b.WriteString(e.HTTP.Hostname)
		b.WriteString(e.HTTP.URL)
		ev.Message = strings.TrimSpace(b.String())
		ev.Severity = event.SevInfo
		putRaw(&ev, "http.hostname", e.HTTP.Hostname)
		putRaw(&ev, "http.url", e.HTTP.URL)
		putRaw(&ev, "http.user_agent", e.HTTP.UserAgent)
		if e.HTTP.Status != 0 {
			putRaw(&ev, "http.status", strconv.Itoa(e.HTTP.Status))
		}
	default:
		ev.Severity = event.SevInfo
	}

	addLeftover(&ev, raw, consumed)
	return ev, nil
}

// eveClass maps a Suricata event_type onto the controlled Class/Activity vocab.
func eveClass(eventType string) (class, activity string) {
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "alert":
		return ClassAlert, ActDetected
	case "dns":
		return ClassDNS, ActQuery
	case "http":
		return ClassHTTP, ActRequest
	case "flow", "netflow":
		return ClassNetwork, ActFlow
	case "tls", "ssl":
		return ClassNetwork, ActTLS
	case "fileinfo", "files":
		return ClassFile, ActTransfer
	default:
		return ClassNetwork, ActObserved
	}
}

// eveSeverity maps Suricata's inverted severity (1 = most severe) to a bucket.
// 0/absent -> Unknown; >=4 -> Info.
func eveSeverity(s int) event.Severity {
	switch {
	case s <= 0:
		return event.SevUnknown
	case s == 1:
		return event.SevHigh
	case s == 2:
		return event.SevMedium
	case s == 3:
		return event.SevLow
	default:
		return event.SevInfo
	}
}
