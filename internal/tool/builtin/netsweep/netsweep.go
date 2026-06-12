// Package netsweep is host discovery across a CIDR: the missing first step for an
// internal/LAN engagement. The seed deliberately refuses to fabricate hosts from a
// range (it can't know which exist), and the per-host tools (portscan/nmap) each
// target ONE host — so a bare "10.0.0.0/24" target produced an empty asset graph
// and the run stalled. netsweep fills that gap: it expands the range and probes
// each address for liveness, emitting a `host` asset per live host so the normal
// host→service→finding chain takes over.
//
// Liveness is an unprivileged TCP-connect probe to a handful of common ports: a
// successful connect OR a refusal (RST) both prove the host is up (only one means
// a service is listening); a timeout means down/filtered. This needs no raw
// sockets or root, so it runs natively on the operator host — which, for a LAN
// engagement, sits directly on the target segment (no NAT in the way).
//
// It is CategoryRecon / RiskLow: benign liveness contact, the lightest active
// step. The range is hard-capped (maxHosts) so a fat prefix (e.g. a /8) is
// REFUSED with a clear message rather than melting the box — narrow it first.
package netsweep

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{}

func New() *Tool { return &Tool{} }

func (t *Tool) Name() string              { return "netsweep" }
func (t *Tool) Category() action.Category { return action.CategoryRecon }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

const (
	// maxHosts caps the expanded address count so an over-broad range can't kick off
	// a runaway scan. 4096 covers a /20; anything larger is refused, not truncated,
	// so the operator consciously narrows scope.
	maxHosts = 4096
	// defaultTimeout is the per-port connect deadline. Short, because a live host on
	// a LAN answers (or refuses) in single-digit milliseconds; the budget is for the
	// down hosts we wait out.
	defaultTimeout = 400 * time.Millisecond
	// defaultConcurrency bounds in-flight dials so we sweep a /24 in well under a
	// second without exhausting sockets/file descriptors.
	defaultConcurrency = 256
)

// commonPorts are the liveness probe set: a small spread across web, remote-admin,
// file-sharing, and OS-fingerprint services so most real hosts answer at least one.
var commonPorts = []int{80, 443, 22, 445, 3389, 8080, 139, 135, 53, 23, 21, 25, 8443, 5900, 62078}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	hosts, label, err := expand(a.Target)
	if err != nil {
		res.Err = err.Error()
		res.Output = err.Error()
		res.FinishedAt = time.Now().UTC()
		return res, nil // a scoping error is a reportable condition, not a tool crash
	}

	ports := parsePorts(a.Params["ports"])
	timeout := defaultTimeout
	if d, perr := time.ParseDuration(a.Params["timeout"]); perr == nil && d > 0 {
		timeout = d
	}

	// Fan out liveness probes with a bounded worker pool.
	type liveHost struct {
		ip   string
		port int // the first port that answered (0 = refused/no listener but up)
		up   bool
	}
	results := make([]liveHost, len(hosts))
	sem := make(chan struct{}, defaultConcurrency)
	var wg sync.WaitGroup
	for i, h := range hosts {
		if ctx.Err() != nil {
			break // engagement cancelled / timed out — stop launching probes
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			up, port := alive(ctx, ip, ports, timeout)
			results[idx] = liveHost{ip: ip, port: port, up: up}
		}(i, h)
	}
	wg.Wait()

	var live []liveHost
	for _, r := range results {
		if r.up {
			live = append(live, r)
		}
	}
	sort.Slice(live, func(i, j int) bool { return ipLess(live[i].ip, live[j].ip) })

	// Emit a host asset per live host so the host→service→finding chain takes over,
	// plus a per-host info finding recording the responding port for the report.
	var sb strings.Builder
	for _, lh := range live {
		res.Assets = append(res.Assets, state.Asset{
			ID: "host:" + lh.ip, Type: "host", Value: lh.ip,
		})
		detail := "responded on tcp/" + strconv.Itoa(lh.port)
		if lh.port == 0 {
			detail = "up (connection refused — no probed port listening)"
		}
		res.Findings = append(res.Findings, state.Finding{
			ID:        fmt.Sprintf("NETSWEEP-%s-%s", a.ID, sanitize(lh.ip)),
			Title:     "Live host discovered: " + lh.ip,
			Severity:  state.SeverityInfo,
			Target:    lh.ip,
			Tool:      t.Name(),
			Evidence:  detail,
			Validated: true,
			FoundAt:   time.Now().UTC(),
		})
		fmt.Fprintf(&sb, "  %s  (%s)\n", lh.ip, detail)
	}

	res.Findings = append(res.Findings, state.Finding{
		ID:        "NETSWEEP-" + a.ID,
		Title:     fmt.Sprintf("Host discovery: %d live host(s) of %d scanned in %s", len(live), len(hosts), label),
		Severity:  state.SeverityInfo,
		Target:    label,
		Tool:      t.Name(),
		Validated: true,
		FoundAt:   time.Now().UTC(),
	})
	res.Success = true
	res.Output = fmt.Sprintf("%s: %d live host(s) of %d scanned\n%s", label, len(live), len(hosts), sb.String())
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// alive probes ports in order, returning up=true on the first successful connect
// (and the port) or on a refusal (RST → host up, port 0). A timeout/unreachable on
// every port means down.
func alive(ctx context.Context, ip string, ports []int, timeout time.Duration) (bool, int) {
	var d net.Dialer
	for _, p := range ports {
		select {
		case <-ctx.Done():
			return false, 0
		default:
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
		cancel()
		if err == nil {
			conn.Close()
			return true, p
		}
		// A refused connection still proves the host exists (something sent an RST).
		if isRefused(err) {
			return true, 0
		}
	}
	return false, 0
}

// isRefused reports whether the dial error is a connection refusal (host up, port
// closed) as opposed to a timeout / unreachable (host effectively down for us).
func isRefused(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "refused") || strings.Contains(s, "connection was refused")
}

// expand turns a target into the list of host IPs to probe. A CIDR is enumerated
// (network/broadcast skipped for IPv4 prefixes <=30); a bare IP is a single host.
// Returns a clamp error if the range exceeds maxHosts so an over-broad scope fails
// loudly instead of running away.
func expand(target string) (hosts []string, label string, err error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, "", fmt.Errorf("netsweep: no target")
	}
	if !strings.Contains(target, "/") {
		ip := net.ParseIP(target)
		if ip == nil {
			return nil, "", fmt.Errorf("netsweep: %q is not an IP or CIDR", target)
		}
		return []string{ip.String()}, target, nil
	}
	ip, ipnet, perr := net.ParseCIDR(target)
	if perr != nil {
		return nil, "", fmt.Errorf("netsweep: invalid CIDR %q: %v", target, perr)
	}
	ones, bits := ipnet.Mask.Size()
	if total := uint64(1) << uint(bits-ones); total > maxHosts {
		return nil, "", fmt.Errorf("netsweep: %s spans %d addresses (> %d cap) — narrow the range (e.g. a /24) before sweeping", target, total, maxHosts)
	}
	isV4 := ip.To4() != nil
	skipEnds := isV4 && bits-ones >= 2 // skip network + broadcast for /30 and wider
	netIP := ipnet.IP.Mask(ipnet.Mask)
	for cur := cloneIP(netIP); ipnet.Contains(cur); incIP(cur) {
		if skipEnds {
			if isNetworkOrBroadcast(cur, ipnet) {
				continue
			}
		}
		hosts = append(hosts, cur.String())
		if len(hosts) > maxHosts {
			break
		}
	}
	return hosts, ipnet.String(), nil
}

func isNetworkOrBroadcast(ip net.IP, n *net.IPNet) bool {
	network := ip.Mask(n.Mask)
	if ip.Equal(network) {
		return true
	}
	bcast := cloneIP(network)
	for i := range bcast {
		bcast[i] |= ^n.Mask[i]
	}
	return ip.Equal(bcast)
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

// incIP increments an IP address in place (big-endian carry).
func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// parsePorts reads a comma-separated override list, falling back to commonPorts.
func parsePorts(s string) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return commonPorts
	}
	var out []int
	for _, f := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return commonPorts
	}
	return out
}

// ipLess orders IPv4/IPv6 addresses by their byte representation for stable output.
func ipLess(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return a < b
	}
	return strings.Compare(string(ia.To16()), string(ib.To16())) < 0
}

func sanitize(s string) string {
	return strings.NewReplacer(".", "-", ":", "-", "/", "-").Replace(s)
}
