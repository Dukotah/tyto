package ingest

import (
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/blue/event"
)

// Real-shaped Suricata EVE lines: an alert, a DNS query, and an HTTP request.
const eveSample = `
{"timestamp":"2023-09-18T10:12:05.123456+0000","flow_id":2089318379123456,"in_iface":"eth0","event_type":"alert","src_ip":"192.168.1.50","src_port":49620,"dest_ip":"203.0.113.7","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2027758,"rev":3,"signature":"ET POLICY TLS possible TOR SSL traffic","category":"Potential Corporate Privacy Violation","severity":2},"app_proto":"tls"}
{"timestamp":"2023-09-18T10:12:06.000000+0000","flow_id":111,"event_type":"dns","src_ip":"192.168.1.50","src_port":53344,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","dns":{"type":"query","id":4660,"rrname":"malware-c2.example.com","rrtype":"A","tx_id":0}}
{"timestamp":"2023-09-18T10:12:07.500000+0000","flow_id":222,"event_type":"http","src_ip":"192.168.1.50","src_port":51000,"dest_ip":"198.51.100.9","dest_port":80,"proto":"TCP","http":{"hostname":"example.com","url":"/login.php","http_method":"POST","status":200,"http_user_agent":"curl/7.88.1"}}
`

func TestEVEAdapter(t *testing.T) {
	evs, err := EVEAdapter{}.Parse(strings.NewReader(eveSample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("want 3 events, got %d", len(evs))
	}

	a := evs[0]
	if a.Sensor != "suricata" {
		t.Errorf("sensor = %q, want suricata", a.Sensor)
	}
	if a.Class != ClassAlert || a.Activity != ActDetected {
		t.Errorf("class/activity = %q/%q, want %q/%q", a.Class, a.Activity, ClassAlert, ActDetected)
	}
	if a.SrcIP != "192.168.1.50" || a.SrcPort != 49620 || a.DstIP != "203.0.113.7" || a.DstPort != 443 {
		t.Errorf("endpoints wrong: %+v", a.SafeMeta())
	}
	if a.Message != "ET POLICY TLS possible TOR SSL traffic" {
		t.Errorf("message = %q", a.Message)
	}
	if a.Severity != event.SevMedium {
		t.Errorf("severity = %v, want medium (eve sev 2)", a.Severity)
	}
	if a.Category != "Potential Corporate Privacy Violation" {
		t.Errorf("category = %q", a.Category)
	}
	if a.ID != "2089318379123456" {
		t.Errorf("id = %q, want flow_id", a.ID)
	}
	// Unmapped native fields preserved.
	for k, want := range map[string]string{
		"proto": "TCP", "app_proto": "tls", "in_iface": "eth0",
		"alert.signature_id": "2027758", "alert.action": "allowed",
	} {
		if got := a.RawFields[k]; got != want {
			t.Errorf("RawFields[%q] = %q, want %q", k, got, want)
		}
	}

	dns := evs[1]
	if dns.Class != ClassDNS || dns.Activity != ActQuery {
		t.Errorf("dns class/activity = %q/%q", dns.Class, dns.Activity)
	}
	if !strings.Contains(dns.Message, "malware-c2.example.com") {
		t.Errorf("dns message = %q", dns.Message)
	}
	if dns.Severity != event.SevInfo {
		t.Errorf("dns severity = %v, want info", dns.Severity)
	}

	http := evs[2]
	if http.Class != ClassHTTP || http.Activity != ActRequest {
		t.Errorf("http class/activity = %q/%q", http.Class, http.Activity)
	}
	if !strings.Contains(http.Message, "example.com") || !strings.Contains(http.Message, "/login.php") {
		t.Errorf("http message = %q", http.Message)
	}
	if http.RawFields["http.user_agent"] != "curl/7.88.1" {
		t.Errorf("http user_agent raw = %q", http.RawFields["http.user_agent"])
	}
}

// Real-shaped Wazuh alert (sshd failed-password, rule level 10).
const wazuhSample = `{"timestamp":"2023-09-18T10:15:33.123+0000","rule":{"level":10,"description":"sshd: Multiple authentication failures.","id":"5720","firedtimes":4,"mail":false,"groups":["syslog","sshd","authentication_failures"]},"agent":{"id":"003","name":"web-server-01","ip":"10.0.0.15"},"manager":{"name":"wazuh-manager"},"id":"1695032133.1234567","full_log":"Oct 18 10:15:33 web-server-01 sshd[23451]: Failed password for invalid user admin from 198.51.100.23 port 55123 ssh2","predecoder":{"program_name":"sshd"},"decoder":{"name":"sshd"},"data":{"srcip":"198.51.100.23","srcport":"55123","srcuser":"admin"},"location":"/var/log/auth.log"}`

func TestWazuhAdapter(t *testing.T) {
	evs, err := WazuhAdapter{}.Parse(strings.NewReader(wazuhSample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	e := evs[0]
	if e.Sensor != "wazuh" {
		t.Errorf("sensor = %q", e.Sensor)
	}
	if e.Class != ClassAuth || e.Activity != ActLoginFailed {
		t.Errorf("class/activity = %q/%q, want %q/%q", e.Class, e.Activity, ClassAuth, ActLoginFailed)
	}
	if e.Host != "web-server-01" {
		t.Errorf("host = %q", e.Host)
	}
	if e.Severity != event.SevHigh {
		t.Errorf("severity = %v, want high (rule.level 10)", e.Severity)
	}
	if !strings.Contains(e.Message, "Failed password") {
		t.Errorf("message (full_log) = %q", e.Message)
	}
	if e.SrcIP != "198.51.100.23" || e.SrcPort != 55123 {
		t.Errorf("src = %q:%d", e.SrcIP, e.SrcPort)
	}
	if e.User != "admin" {
		t.Errorf("user = %q", e.User)
	}
	if e.ID != "1695032133.1234567" {
		t.Errorf("id = %q", e.ID)
	}
	for k, want := range map[string]string{
		"rule.id": "5720", "rule.level": "10", "agent.id": "003",
		"rule.groups": "syslog,sshd,authentication_failures",
	} {
		if got := e.RawFields[k]; got != want {
			t.Errorf("RawFields[%q] = %q, want %q", k, got, want)
		}
	}
}

func TestWazuhSeverityBuckets(t *testing.T) {
	cases := map[int]event.Severity{
		0: event.SevInfo, 2: event.SevLow, 5: event.SevMedium,
		9: event.SevHigh, 13: event.SevCritical,
	}
	for level, want := range cases {
		if got := wazuhSeverity(level); got != want {
			t.Errorf("wazuhSeverity(%d) = %v, want %v", level, got, want)
		}
	}
}

// Generic flat JSON rows with differing schemas.
const jsonlSample = `
{"ts":"2023-09-18T11:00:00Z","event_type":"process_creation","host":"workstation-7","user":"jdoe","process":"powershell.exe","parent_process":"explorer.exe","command_line":"powershell -enc SQBFAFgA","severity":"high","pid":4821}
{"time":1695034800,"source_ip":"192.0.2.44","destination_ip":"10.0.0.5","dst_port":3389,"message":"RDP brute force detected","severity":5,"rule":"bruteforce-rdp"}
`

func TestJSONLAdapter(t *testing.T) {
	evs, err := JSONLAdapter{}.Parse(strings.NewReader(jsonlSample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d", len(evs))
	}

	p := evs[0]
	if p.Sensor != "jsonl" {
		t.Errorf("sensor = %q", p.Sensor)
	}
	if p.Class != ClassProcess {
		t.Errorf("class = %q, want %q", p.Class, ClassProcess)
	}
	if p.Host != "workstation-7" || p.User != "jdoe" || p.Process != "powershell.exe" || p.ParentProcess != "explorer.exe" {
		t.Errorf("actor fields wrong: %q %q %q %q", p.Host, p.User, p.Process, p.ParentProcess)
	}
	if !strings.Contains(p.CommandLine, "-enc") {
		t.Errorf("command_line = %q", p.CommandLine)
	}
	if p.Severity != event.SevHigh {
		t.Errorf("severity = %v, want high", p.Severity)
	}
	if p.RawFields["pid"] != "4821" {
		t.Errorf("RawFields[pid] = %q, want 4821", p.RawFields["pid"])
	}

	n := evs[1]
	if n.SrcIP != "192.0.2.44" || n.DstIP != "10.0.0.5" || n.DstPort != 3389 {
		t.Errorf("endpoints wrong: %q -> %q:%d", n.SrcIP, n.DstIP, n.DstPort)
	}
	if n.Message != "RDP brute force detected" {
		t.Errorf("message = %q", n.Message)
	}
	if n.Severity != event.SevMedium {
		t.Errorf("severity = %v, want medium (numeric 5)", n.Severity)
	}
	if n.Class != ClassUnknown {
		t.Errorf("class = %q, want unknown (no class field)", n.Class)
	}
	if n.RawFields["rule"] != "bruteforce-rdp" {
		t.Errorf("RawFields[rule] = %q", n.RawFields["rule"])
	}
	if n.Time.Year() != 2023 {
		t.Errorf("epoch time not parsed: %v", n.Time)
	}
}

func TestMalformedLinesSkipped(t *testing.T) {
	// blank lines + one broken line in the middle; the valid ones still parse.
	mixed := "\n" +
		`{"ts":"2023-09-18T11:00:00Z","host":"h1","message":"ok one"}` + "\n" +
		`{this is not valid json` + "\n" +
		"   \n" +
		`{"ts":"2023-09-18T11:01:00Z","host":"h2","message":"ok two"}` + "\n"
	evs, err := JSONLAdapter{}.Parse(strings.NewReader(mixed))
	if err != nil {
		t.Fatalf("err should be nil when some events parsed, got %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 events (malformed skipped), got %d", len(evs))
	}
	if evs[0].Host != "h1" || evs[1].Host != "h2" {
		t.Errorf("wrong events survived: %q, %q", evs[0].Host, evs[1].Host)
	}
}

func TestNothingParsedSurfacesError(t *testing.T) {
	allBad := "{bad\n{also bad]\nnope\n"
	evs, err := JSONLAdapter{}.Parse(strings.NewReader(allBad))
	if len(evs) != 0 {
		t.Fatalf("want 0 events, got %d", len(evs))
	}
	if err == nil {
		t.Fatal("want error when nothing parsed, got nil")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("want *ParseError, got %T", err)
	}
	if pe.Skipped != 3 {
		t.Errorf("skipped = %d, want 3", pe.Skipped)
	}
	if pe.First == "" {
		t.Error("ParseError.First should carry the first underlying error")
	}
}

func TestEmptyInputNoError(t *testing.T) {
	evs, err := JSONLAdapter{}.Parse(strings.NewReader("\n   \n\n"))
	if err != nil {
		t.Errorf("blank-only input should not error, got %v", err)
	}
	if len(evs) != 0 {
		t.Errorf("want 0 events, got %d", len(evs))
	}
}

func TestAdapterFor(t *testing.T) {
	cases := map[string]Adapter{
		"suricata": EVEAdapter{},
		"EVE":      EVEAdapter{},
		"wazuh":    WazuhAdapter{},
		"ossec":    WazuhAdapter{},
		"jsonl":    JSONLAdapter{},
		"whatever": JSONLAdapter{},
	}
	for sensor, want := range cases {
		got := AdapterFor(sensor)
		if got != want {
			t.Errorf("AdapterFor(%q) = %T, want %T", sensor, got, want)
		}
	}
}
