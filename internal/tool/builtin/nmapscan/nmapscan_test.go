package nmapscan

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// sampleXML is a captured `nmap -sV -oX -` document: one host with three open
// ports, one of which (22/ssh) discloses a product+version. A fourth port is
// closed and must be ignored.
const sampleXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX - scanme.example.com" version="7.94">
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="scanme.example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed" reason="reset"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
</nmaprun>`

func TestParseNmapXML(t *testing.T) {
	assets, findings := parseNmapXML(sampleXML)

	if len(assets) != 3 {
		t.Fatalf("expected 3 service assets (open ports only), got %d: %+v", len(assets), assets)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(findings), findings)
	}

	// Index assets/findings by their service value/port for order-independent checks.
	byVal := map[string]state.Asset{}
	for _, a := range assets {
		if a.Type != "service" {
			t.Errorf("asset %q: want Type=service, got %q", a.Value, a.Type)
		}
		byVal[a.Value] = a
	}

	ssh, ok := byVal["scanme.example.com:22"]
	if !ok {
		t.Fatalf("missing ssh service asset; have %+v", byVal)
	}
	if ssh.Attrs["proto"] != "tcp" || ssh.Attrs["service"] != "ssh" ||
		ssh.Attrs["product"] != "OpenSSH" || ssh.Attrs["version"] != "8.9p1" {
		t.Errorf("ssh asset attrs wrong: %+v", ssh.Attrs)
	}

	if _, ok := byVal["scanme.example.com:80"]; !ok {
		t.Errorf("missing http (80) service asset")
	}
	if _, ok := byVal["scanme.example.com:443"]; !ok {
		t.Errorf("missing https (443) service asset")
	}
	if _, ok := byVal["scanme.example.com:3306"]; ok {
		t.Errorf("closed port 3306 should not be emitted as an asset")
	}

	// Severity: the version-disclosing port (22) bumps to Low; the bare ones stay Info.
	sevByPort := map[string]state.Severity{}
	for _, f := range findings {
		if f.Target != "scanme.example.com" {
			t.Errorf("finding target want scanme.example.com, got %q", f.Target)
		}
		switch {
		case strings.Contains(f.Title, "22/tcp"):
			sevByPort["22"] = f.Severity
			if !strings.Contains(f.Title, "OpenSSH") || !strings.Contains(f.Title, "8.9p1") {
				t.Errorf("ssh finding title missing product/version: %q", f.Title)
			}
		case strings.Contains(f.Title, "80/tcp"):
			sevByPort["80"] = f.Severity
		case strings.Contains(f.Title, "443/tcp"):
			sevByPort["443"] = f.Severity
		}
	}
	if sevByPort["22"] != state.SeverityLow {
		t.Errorf("port 22 (product+version) should be SeverityLow, got %v", sevByPort["22"])
	}
	if sevByPort["80"] != state.SeverityInfo {
		t.Errorf("port 80 (no version) should be SeverityInfo, got %v", sevByPort["80"])
	}
	if sevByPort["443"] != state.SeverityInfo {
		t.Errorf("port 443 (no version) should be SeverityInfo, got %v", sevByPort["443"])
	}
}

// TestParseNmapXMLGarbage confirms malformed input parses to nothing, not a panic.
func TestParseNmapXMLGarbage(t *testing.T) {
	assets, findings := parseNmapXML("not xml at all <<<")
	if len(assets) != 0 || len(findings) != 0 {
		t.Errorf("garbage input should yield no assets/findings, got %d/%d", len(assets), len(findings))
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"http://h:8080/x":  "h",
		"https://host/a/b": "host",
		"10.0.0.5":         "10.0.0.5",
		"10.0.0.5:443":     "10.0.0.5",
		"example.com":      "example.com",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExecuteGracefulDegrade asserts that when nmap is not installed, Execute
// still succeeds with the standard "nmap not available" Info finding. Skipped if
// nmap happens to be on PATH (then the live scan path would run instead).
func TestExecuteGracefulDegrade(t *testing.T) {
	if adapter.Detect("nmap") != "" {
		t.Skip("nmap is installed on this host; graceful-degrade path not exercised")
	}
	tool := New()
	res, err := tool.Execute(context.Background(), action.Action{
		ID:     "a1",
		Target: "http://scanme.example.com:8080/path",
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected Success=true on graceful degrade")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo {
		t.Errorf("graceful-degrade finding should be SeverityInfo, got %v", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Title), "nmap not available") {
		t.Errorf("finding title = %q, want it to mention 'nmap not available'", f.Title)
	}
}

// Compile-time assertion that *Tool satisfies the tool.Tool contract.
var (
	_ interface {
		Name() string
		Category() action.Category
		MaxRisk() action.RiskLevel
		Execute(context.Context, action.Action) (action.Result, error)
	} = (*Tool)(nil)
)
