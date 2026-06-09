package dnsenum

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func TestExtractDomain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"https://example.com", "example.com"},
		{"http://example.com/path/to/page", "example.com"},
		{"https://example.com:8443/x?y=1#z", "example.com"},
		{"example.com:443", "example.com"},
		{"user:pass@example.com", "example.com"},
		{"https://user@sub.example.com/a", "sub.example.com"},
		{"example.com.", "example.com"},
		{"  https://EXAMPLE.com/  ", "EXAMPLE.com"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"127.0.0.1:8080", "127.0.0.1"},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := extractDomain(c.in); got != c.want {
			t.Errorf("extractDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestStaticToolMetadata(t *testing.T) {
	tl := New()
	if tl.Name() != "dnsenum" {
		t.Errorf("Name() = %q, want dnsenum", tl.Name())
	}
	if tl.Category() != action.CategoryRecon {
		t.Errorf("Category() = %v, want CategoryRecon", tl.Category())
	}
	if tl.MaxRisk() != action.RiskPassive {
		t.Errorf("MaxRisk() = %v, want RiskPassive", tl.MaxRisk())
	}
}

func TestExecuteEmptyTarget(t *testing.T) {
	res, err := New().Execute(context.Background(), action.Action{ID: "e1", Target: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Errorf("expected Success=false for empty target")
	}
	if len(res.Findings) != 0 || len(res.Assets) != 0 {
		t.Errorf("expected no findings/assets for empty target")
	}
}

// TestExecuteLocalhost uses "localhost", which deterministically resolves to
// 127.0.0.1 and/or ::1 on virtually every system, so no flaky external network
// is involved. If the CI environment cannot resolve localhost at all, the test
// skips rather than fails.
func TestExecuteLocalhost(t *testing.T) {
	// Sanity-check the environment first; skip if localhost is unresolvable.
	if _, err := net.DefaultResolver.LookupHost(context.Background(), "localhost"); err != nil {
		t.Skipf("environment cannot resolve localhost: %v", err)
	}

	res, err := New().Execute(context.Background(), action.Action{ID: "l1", Target: "localhost"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success, got Err=%q", res.Err)
	}

	// Expect at least one host asset for a loopback address.
	var loopback bool
	for _, as := range res.Assets {
		if as.Type != "host" {
			t.Errorf("asset type = %q, want host", as.Type)
		}
		if ip := net.ParseIP(as.Value); ip != nil && ip.IsLoopback() {
			loopback = true
		}
	}
	if !loopback {
		t.Errorf("expected a loopback host asset, got assets=%v", res.Assets)
	}

	// The A/AAAA finding must be present and Validated.
	var addrFinding bool
	for _, f := range res.Findings {
		if !f.Validated {
			t.Errorf("finding %q should be Validated", f.Title)
		}
		if f.Severity != state.SeverityInfo {
			t.Errorf("finding %q severity = %v, want Info", f.Title, f.Severity)
		}
		if strings.HasPrefix(f.Title, "DNS A/AAAA records") {
			addrFinding = true
		}
	}
	if !addrFinding {
		t.Errorf("expected an A/AAAA-records finding for localhost")
	}
}

// TestExecuteCancelled verifies ctx cancellation is honored (no hang, graceful
// non-success result). Uses an already-cancelled context.
func TestExecuteCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The apex lookups may error under cancellation (fine); the subdomain loop
	// must observe ctx.Done() and bail. Either way it must return promptly.
	res, err := New().Execute(ctx, action.Action{ID: "c1", Target: "localhost"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = res // success flag may be true (apex done) or false (cancelled mid-flight)
}
