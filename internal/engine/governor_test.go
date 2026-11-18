package engine

import (
	"context"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/dukotah/tyto/internal/engagement"
)

func TestTroubleSignal(t *testing.T) {
	tests := []struct {
		name   string
		output string
		errs   string
		want   bool
	}{
		{"clean 200", "HTTP/1.1 200 OK\nbody", "", false},
		{"ordinary finding text", "found 3 headers missing", "", false},
		{"http 429", "HTTP/1.1 429 Too Many Requests", "", true},
		{"http 503", "503 Service Unavailable", "", true},
		{"retry-after header", "Retry-After: 120", "", true},
		{"conn reset in err", "", "read tcp: connection reset by peer", true},
		{"conn refused in err", "", "dial tcp 10.0.0.1:443: connection refused", true},
		{"econnreset", "", "ECONNRESET", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := troubleSignal(tc.output, tc.errs); got != tc.want {
				t.Fatalf("troubleSignal(%q,%q)=%v, want %v", tc.output, tc.errs, got, tc.want)
			}
		})
	}
}

func TestGovernedLimit(t *testing.T) {
	// Pressure 0 never changes the base rate (today's behaviour).
	if got := governedLimit(rate.Inf, 0); got != rate.Inf {
		t.Fatalf("pressure 0 must return base unchanged, got %v", got)
	}
	if got := governedLimit(rate.Limit(5), 0); got != rate.Limit(5) {
		t.Fatalf("pressure 0 must return base unchanged, got %v", got)
	}
	// Any pressure caps an unlimited base at the conservative trouble ceiling, then
	// halves per step down to the floor.
	if got := governedLimit(rate.Inf, 1); got != governorTroubleCeiling {
		t.Fatalf("pressure 1 on Inf base should cap at ceiling %v, got %v", governorTroubleCeiling, got)
	}
	if got := governedLimit(rate.Inf, 2); got != governorTroubleCeiling/2 {
		t.Fatalf("pressure 2 should halve the ceiling, got %v", got)
	}
	if got := governedLimit(rate.Inf, governorMaxPressure); got < governorFloor {
		t.Fatalf("limit must never drop below the floor %v, got %v", governorFloor, got)
	}
}

func TestGovernorBacksOffOnTrouble(t *testing.T) {
	th := newThrottle(engagement.RoE{}) // unlimited by default
	// A trouble signal raises pressure and clamps the target to 1 rps, burst 1.
	th.observe("h", "HTTP/1.1 429 Too Many Requests", "")

	// First acquire drains the single burst token.
	rel, err := th.acquire(context.Background(), "h")
	if err != nil {
		t.Fatal(err)
	}
	rel()
	// The next acquire for the same target must now wait (~1s at 1 rps) — prove the
	// backoff by timing out well under that.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := th.acquire(ctx, "h"); err == nil {
		t.Fatal("a backed-off target should be rate-limited after the burst")
	}
}

func TestGovernorRelaxesWhenClear(t *testing.T) {
	th := newThrottle(engagement.RoE{}) // unlimited base
	th.observe("h", "503 Service Unavailable", "")
	// One clean result decays the single pressure step back to calm, restoring the
	// unlimited base rate so acquires no longer block.
	th.observe("h", "HTTP/1.1 200 OK", "")
	for i := 0; i < 20; i++ {
		rel, err := th.acquire(context.Background(), "h")
		if err != nil {
			t.Fatalf("relaxed target should not block: %v", err)
		}
		rel()
	}
}

func TestGovernorIdleWhenNoTrouble(t *testing.T) {
	th := newThrottle(engagement.RoE{}) // unlimited base
	// Only clean results: pressure must stay at 0 and the limiter at the base rate,
	// so behaviour is identical to the pre-governor throttle.
	for i := 0; i < 10; i++ {
		th.observe("h", "HTTP/1.1 200 OK\nall good", "")
	}
	if p := th.perTarget["h"].pressure; p != 0 {
		t.Fatalf("clean results must not raise pressure, got %d", p)
	}
	for i := 0; i < 50; i++ {
		rel, err := th.acquire(context.Background(), "h")
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
}
