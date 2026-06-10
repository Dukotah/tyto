// Package nmapscan is a deep service-scanning adapter that shells out to the
// EXTERNAL nmap binary (`nmap -sV`) and parses its XML output into typed
// service assets + findings. Like every tyto shell-out adapter it is
// runtime-detected: tyto stays a pure-Go, offline-by-default binary, so if nmap
// is not installed this adapter DEGRADES GRACEFULLY — it emits a single info
// finding and succeeds rather than failing. The live scan path is only taken
// when an operator has nmap on PATH.
//
// It is scan-category and RiskLow (service-version detection is the common,
// non-intrusive deep scan), so the Scope Guard gates it before Execute is ever
// reached. nmap is driven without a shell (args are a slice), and a.Params
// ["args"] is intentionally ignored so a tool/model-controlled string can never
// inject arbitrary nmap flags.
package nmapscan

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool implements an external nmap service-scan adapter.
type Tool struct{}

// New returns an nmapscan Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "nmapscan" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk implements tool.Tool. Service-version detection is benign active
// contact relative to exploitation, so the ceiling is Low.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

// maxFindings caps emitted findings so a host with a huge open-port count (or a
// crafted XML payload) can't balloon the result.
const maxFindings = 100

// Execute resolves the host from the target, detects nmap, and — if present —
// runs `nmap -sV -T4 -oX - <host>` and parses the XML into service assets and
// findings. With nmap not installed it degrades gracefully to a single info
// finding and Success=true. A present-but-failing run with no parseable output
// is reported in res.Output (still returning a nil error).
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	host := hostOf(a.Target)

	bin := adapter.Detect("nmap")
	if bin == "" {
		res.Findings = []state.Finding{adapter.Missing("nmap", a.Target, "apt install nmap")}
		res.Success = true
		res.Output = "nmap not available; service scan skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Honor cancellation before launching the external process. (adapter.Run also
	// binds ctx, so an in-flight scan is killed on cancel too.)
	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	// -sV service/version detection, -T4 reasonable speed, -oX - XML to stdout.
	// a.Params["args"] is deliberately NOT honored (injection safety); only the
	// vetted "ports" param adjusts the scan surface.
	args := []string{"-sV", "-T4", "-oX", "-"}
	if ports := strings.TrimSpace(a.Params["ports"]); ports != "" {
		args = append(args, "-p", ports)
	}
	args = append(args, host)

	out, runErr := adapter.Run(ctx, bin, args, 0)

	assets, findings := parseNmapXML(out)

	// Stamp IDs/host/tool on parsed findings (parseNmapXML stays host/tool-agnostic
	// so it is purely unit-testable on a captured XML string).
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%s-%d", a.ID, i)
		if findings[i].Target == "" {
			findings[i].Target = host
		}
		findings[i].Tool = t.Name()
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = time.Now().UTC()
		}
	}
	res.Findings = append(res.Findings, findings...)
	res.Assets = append(res.Assets, assets...)

	summary := fmt.Sprintf("nmap: %d open port(s)", len(assets))
	if runErr != nil && len(assets) == 0 {
		// nmap present but failed (host down, no perms, etc.) and gave us nothing
		// parseable. Not an error from tyto's perspective — report it and move on.
		summary = fmt.Sprintf("nmap run error with no parseable output: %v", runErr)
	} else if runErr != nil {
		summary += fmt.Sprintf(" (nmap exited non-zero: %v)", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// nmapRun mirrors the subset of `nmap -oX` output this adapter consumes. Fields
// outside this struct are ignored by encoding/xml, and every field is optional
// so malformed/partial documents parse without error.
type nmapRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr     string `xml:"addr,attr"`
			AddrType string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames struct {
			Hostname []struct {
				Name string `xml:"name,attr"`
			} `xml:"hostname"`
		} `xml:"hostnames"`
		Ports struct {
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   string `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// parseNmapXML best-effort parses `nmap -oX -` output into service assets plus
// matching findings. For every open port it emits a "service" Asset
// (Value "<host>:<portid>") and a SeverityInfo "Open port" finding, bumped to
// SeverityLow when a product+version is disclosed. It tolerates missing fields
// and caps findings at ~100. It is host/tool-agnostic for unit-testing.
func parseNmapXML(xmlStr string) ([]state.Asset, []state.Finding) {
	var run nmapRun
	if err := xml.Unmarshal([]byte(xmlStr), &run); err != nil {
		return nil, nil
	}

	var assets []state.Asset
	var findings []state.Finding

	for _, h := range run.Hosts {
		host := hostLabel(h.Addresses, h.Hostnames.Hostname)
		for _, p := range h.Ports.Port {
			if !strings.EqualFold(p.State.State, "open") {
				continue
			}
			if len(findings) >= maxFindings {
				return assets, findings
			}

			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}
			svc := p.Service.Name
			product := p.Service.Product
			version := p.Service.Version

			value := host + ":" + p.PortID

			attrs := map[string]string{"proto": proto}
			if svc != "" {
				attrs["service"] = svc
			}
			if product != "" {
				attrs["product"] = product
			}
			if version != "" {
				attrs["version"] = version
			}
			if p.PortID != "" {
				attrs["port"] = p.PortID
			}
			assets = append(assets, state.Asset{
				ID:    value,
				Type:  "service",
				Value: value,
				Attrs: attrs,
			})

			sev := state.SeverityInfo
			if product != "" && version != "" {
				// A disclosed product+version is fingerprintable attack surface.
				sev = state.SeverityLow
			}

			// Title: "Open port <portid>/<proto> — <service> <product> <version>".
			detail := strings.TrimSpace(strings.Join(nonEmpty(svc, product, version), " "))
			title := fmt.Sprintf("Open port %s/%s", p.PortID, proto)
			if detail != "" {
				title += " — " + detail
			}
			desc := fmt.Sprintf("nmap found %s/%s open on %s", p.PortID, proto, host)
			if detail != "" {
				desc += " running " + detail
			}
			findings = append(findings, state.Finding{
				Title:       title,
				Severity:    sev,
				Target:      host,
				Description: desc,
				Evidence:    strings.TrimSpace(value + " " + detail),
				Validated:   true,
			})
		}
	}
	return assets, findings
}

// hostLabel picks the most useful label for a host: a hostname if nmap resolved
// one, else the IPv4/IPv6 address, else the first address of any type.
func hostLabel(addrs []struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}, names []struct {
	Name string `xml:"name,attr"`
}) string {
	for _, n := range names {
		if n.Name != "" {
			return n.Name
		}
	}
	for _, a := range addrs {
		if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
			if a.Addr != "" {
				return a.Addr
			}
		}
	}
	for _, a := range addrs {
		if a.Addr != "" {
			return a.Addr
		}
	}
	return ""
}

// nonEmpty returns its non-empty arguments, preserving order.
func nonEmpty(vals ...string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// hostOf strips scheme/path/port from a target to get a usable host.
// A URL like "http://h:8080/x" resolves to "h"; an ip/host passes through.
func hostOf(target string) string {
	t := strings.TrimSpace(target)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	return t
}
