package ingest

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/dukotah/tyto/internal/blue/event"
)

// WazuhAdapter parses Wazuh/OSSEC alert JSON (one alert object per line, as
// written to alerts.json). It maps rule.description/full_log, rule.level,
// agent.name and the data.* endpoint fields onto event.Event.
type WazuhAdapter struct{}

type wazuhAlert struct {
	Timestamp string `json:"timestamp"`
	FullLog   string `json:"full_log"`
	Location  string `json:"location"`
	ID        string `json:"id"`

	Rule struct {
		Level       int      `json:"level"`
		Description string   `json:"description"`
		ID          string   `json:"id"`
		Groups      []string `json:"groups"`
	} `json:"rule"`

	Agent struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		IP   string `json:"ip"`
	} `json:"agent"`

	Manager struct {
		Name string `json:"name"`
	} `json:"manager"`

	Decoder struct {
		Name string `json:"name"`
	} `json:"decoder"`

	Data struct {
		Srcip   flexString `json:"srcip"`
		Srcport flexString `json:"srcport"`
		Dstip   flexString `json:"dstip"`
		Dstport flexString `json:"dstport"`
		Srcuser flexString `json:"srcuser"`
		Dstuser flexString `json:"dstuser"`
	} `json:"data"`
}

// Parse implements Adapter.
func (a WazuhAdapter) Parse(r io.Reader) ([]event.Event, error) {
	return parseStream(r, a.parseLine)
}

func (WazuhAdapter) parseLine(line []byte) (event.Event, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return event.Event{}, err
	}
	var w wazuhAlert
	if err := json.Unmarshal(line, &w); err != nil {
		return event.Event{}, err
	}

	class, activity := wazuhClass(w.Rule.Groups)
	ev := event.New("wazuh", class)
	ev.Activity = activity

	if t, ok := parseTime(w.Timestamp); ok {
		ev.Time = t
	}
	ev.ID = w.ID
	ev.Host = w.Agent.Name
	ev.Severity = wazuhSeverity(w.Rule.Level)

	// full_log is the raw line; fall back to the rule description.
	if w.FullLog != "" {
		ev.Message = w.FullLog
	} else {
		ev.Message = w.Rule.Description
	}

	ev.SrcIP = string(w.Data.Srcip)
	ev.DstIP = string(w.Data.Dstip)
	ev.SrcPort = w.Data.Srcport.atoi()
	ev.DstPort = w.Data.Dstport.atoi()
	if u := string(w.Data.Srcuser); u != "" {
		ev.User = u
	} else {
		ev.User = string(w.Data.Dstuser)
	}

	// Notable native fields that aren't dedicated event.Event columns.
	putRaw(&ev, "rule.id", w.Rule.ID)
	putRaw(&ev, "rule.level", strconv.Itoa(w.Rule.Level))
	putRaw(&ev, "rule.description", w.Rule.Description)
	putRaw(&ev, "rule.groups", strings.Join(w.Rule.Groups, ","))
	putRaw(&ev, "agent.id", w.Agent.ID)
	putRaw(&ev, "agent.ip", w.Agent.IP)
	putRaw(&ev, "manager.name", w.Manager.Name)
	putRaw(&ev, "decoder.name", w.Decoder.Name)
	putRaw(&ev, "location", w.Location)

	// Any other top-level keys (predecoder, syscheck, mitre, ...).
	consumed := map[string]bool{
		"timestamp": true, "full_log": true, "location": true, "id": true,
		"rule": true, "agent": true, "manager": true, "decoder": true, "data": true,
	}
	addLeftover(&ev, raw, consumed)
	return ev, nil
}

// wazuhClass derives a controlled Class/Activity from the rule's groups. Wazuh
// carries no OCSF class, so we infer from the well-known group names. Failure
// signals are evaluated across ALL groups first, so a generic "sshd" group can't
// mask an "authentication_failures" group on the same alert.
func wazuhClass(groups []string) (class, activity string) {
	var auth, authFail, file, web, net bool
	for _, g := range groups {
		lg := strings.ToLower(g)
		if strings.Contains(lg, "authentication") || strings.Contains(lg, "login") ||
			strings.Contains(lg, "logon") || strings.Contains(lg, "sshd") {
			auth = true
		}
		if strings.Contains(lg, "fail") || strings.Contains(lg, "invalid_login") ||
			strings.Contains(lg, "login_denied") || strings.Contains(lg, "brute") {
			authFail = true
		}
		if strings.Contains(lg, "syscheck") || strings.Contains(lg, "fim") {
			file = true
		}
		if strings.Contains(lg, "web") || strings.Contains(lg, "apache") || strings.Contains(lg, "nginx") {
			web = true
		}
		if strings.Contains(lg, "firewall") || strings.Contains(lg, "ids") ||
			strings.Contains(lg, "ddos") || strings.Contains(lg, "attack") {
			net = true
		}
	}
	switch {
	case auth && authFail:
		return ClassAuth, ActLoginFailed
	case auth:
		return ClassAuth, ActLogin
	case file:
		return ClassFile, ActDetected
	case web:
		return ClassHTTP, ActRequest
	case net:
		return ClassNetwork, ActDetected
	default:
		return ClassAlert, ActDetected
	}
}

// wazuhSeverity buckets Wazuh rule.level (0-15): 0 info, 1-3 low, 4-7 medium,
// 8-11 high, 12-15 critical.
func wazuhSeverity(level int) event.Severity {
	switch {
	case level <= 0:
		return event.SevInfo
	case level <= 3:
		return event.SevLow
	case level <= 7:
		return event.SevMedium
	case level <= 11:
		return event.SevHigh
	default:
		return event.SevCritical
	}
}
