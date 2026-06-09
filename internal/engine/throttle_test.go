package engine

import (
	"context"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/engagement"
)

func TestThrottleConcurrencyLimit(t *testing.T) {
	th := newThrottle(engagement.RoE{MaxConcurrent: 1})
	rel1, err := th.acquire(context.Background(), "h1")
	if err != nil {
		t.Fatal(err)
	}
	// With one slot held, a second acquire must block — prove it by timing out.
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err := th.acquire(ctx, "h2"); err == nil {
		t.Fatal("second acquire should block while the single slot is held")
	}
	rel1()
	rel2, err := th.acquire(context.Background(), "h2")
	if err != nil {
		t.Fatalf("acquire after release should succeed: %v", err)
	}
	rel2()
}

func TestThrottleRateLimitsPerTarget(t *testing.T) {
	th := newThrottle(engagement.RoE{MaxRPS: 5}) // burst = 5
	for i := 0; i < 5; i++ {
		rel, err := th.acquire(context.Background(), "h")
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
	// The burst is spent; the next request for the same target must wait (~200ms).
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := th.acquire(ctx, "h"); err == nil {
		t.Fatal("request beyond the burst should be rate-limited")
	}
}

func TestThrottleTargetsAreIndependent(t *testing.T) {
	th := newThrottle(engagement.RoE{MaxRPS: 1}) // burst 1 per target
	rel, _ := th.acquire(context.Background(), "a")
	rel()
	// A different target has its own fresh limiter and must not be delayed.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	relb, err := th.acquire(ctx, "b")
	if err != nil {
		t.Fatalf("a saturated limiter for 'a' must not delay 'b': %v", err)
	}
	relb()
}

func TestThrottleCancelledContext(t *testing.T) {
	th := newThrottle(engagement.RoE{MaxConcurrent: 1})
	rel, _ := th.acquire(context.Background(), "h")
	defer rel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := th.acquire(ctx, "h2"); err == nil {
		t.Fatal("a cancelled context must abort acquire")
	}
}

func TestThrottleUnlimitedByDefault(t *testing.T) {
	th := newThrottle(engagement.RoE{})
	if th.sem != nil {
		t.Fatal("no MaxConcurrent should mean a nil (unlimited) semaphore")
	}
	for i := 0; i < 50; i++ {
		rel, err := th.acquire(context.Background(), "h")
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
}
