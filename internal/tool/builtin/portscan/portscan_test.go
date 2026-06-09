package portscan

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/action"
)

func TestExecuteEmitsHostAndServiceAssets(t *testing.T) {
	// Two real listeners on 127.0.0.1 give us deterministically-open ports.
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	p1 := l1.Addr().(*net.TCPAddr).Port
	p2 := l2.Addr().(*net.TCPAddr).Port

	res, err := New().Execute(context.Background(), action.Action{
		ID:     "a1",
		Target: "127.0.0.1",
		Params: map[string]string{"ports": fmt.Sprintf("%d,%d", p1, p2)},
	})
	if err != nil {
		t.Fatal(err)
	}

	var hosts, services int
	for _, as := range res.Assets {
		switch as.Type {
		case "host":
			hosts++
		case "service":
			services++
			if as.Attrs["port"] == "" {
				t.Errorf("service asset %q missing port attr", as.Value)
			}
		}
	}
	if hosts != 1 || services != 2 {
		t.Fatalf("want 1 host + 2 service assets, got hosts=%d services=%d", hosts, services)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 info finding, got %d", len(res.Findings))
	}
}

func TestExecuteEmitsHostAssetWhenNoOpenPorts(t *testing.T) {
	// Grab a port then close it so the scan finds it shut.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := New().Execute(ctx, action.Action{
		ID:     "a2",
		Target: "127.0.0.1",
		Params: map[string]string{"ports": fmt.Sprintf("%d", port)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Assets) != 1 || res.Assets[0].Type != "host" {
		t.Fatalf("want exactly 1 host asset when nothing is open, got %+v", res.Assets)
	}
}

func TestServiceNameKnownPorts(t *testing.T) {
	cases := map[int]string{22: "ssh", 80: "http", 443: "https", 445: "smb", 99999 % 65000: ""}
	for port, want := range cases {
		if got := serviceName(port); got != want && want != "" {
			t.Errorf("serviceName(%d) = %q, want %q", port, got, want)
		}
	}
	if serviceName(12345) != "" {
		t.Errorf("unknown port should resolve to empty service")
	}
}
