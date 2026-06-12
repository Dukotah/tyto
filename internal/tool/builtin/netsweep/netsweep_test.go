package netsweep

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func TestExpandRefusesOverBroadRange(t *testing.T) {
	if _, _, err := expand("10.0.0.0/8"); err == nil {
		t.Fatal("a /8 must be refused (exceeds the host cap), got nil error")
	}
}

func TestExpandCIDRSkipsNetworkAndBroadcast(t *testing.T) {
	hosts, label, err := expand("192.168.5.0/30")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	// /30 = .0 network, .1, .2 usable, .3 broadcast → 2 hosts.
	if len(hosts) != 2 || hosts[0] != "192.168.5.1" || hosts[1] != "192.168.5.2" {
		t.Fatalf("got %v (label %q), want [192.168.5.1 192.168.5.2]", hosts, label)
	}
}

func TestExpandSingleIP(t *testing.T) {
	hosts, _, err := expand("203.0.113.9")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "203.0.113.9" {
		t.Fatalf("got %v, want [203.0.113.9]", hosts)
	}
}

func hostAssets(as []state.Asset) []string {
	var out []string
	for _, a := range as {
		if a.Type == "host" {
			out = append(out, a.Value)
		}
	}
	return out
}

func TestSweepFindsLiveHost(t *testing.T) {
	// A real listener on loopback gives us a guaranteed-live host + open port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	res, err := New().Execute(context.Background(), action.Action{
		ID:     "s1",
		Target: "127.0.0.1",
		Params: map[string]string{"ports": portStr, "timeout": "300ms"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success {
		t.Fatalf("Success=false: %q", res.Output)
	}
	if got := hostAssets(res.Assets); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1 as a live host asset, got %v", got)
	}
	// The per-host finding should record the responding port.
	if !strings.Contains(res.Output, "tcp/"+portStr) {
		t.Fatalf("output should record the responding port tcp/%s: %q", portStr, res.Output)
	}
}

func TestSweepDownHostNotReported(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737), guaranteed not routable — a probe to a
	// closed port on a free loopback port number must time out, not report alive.
	free := freePort(t)
	res, err := New().Execute(context.Background(), action.Action{
		ID:     "s2",
		Target: "192.0.2.1",
		Params: map[string]string{"ports": strconv.Itoa(free), "timeout": "150ms"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := hostAssets(res.Assets); len(got) != 0 {
		t.Fatalf("a non-routable host must not be reported live, got %v", got)
	}
}

// freePort returns a port number with nothing listening on it (closed on loopback).
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close() // close so the port is now refused/free
	n, _ := strconv.Atoi(p)
	return n
}
