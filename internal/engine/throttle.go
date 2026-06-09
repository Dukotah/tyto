package engine

import (
	"context"
	"math"
	"sync"

	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"

	"github.com/dukotah/tyto/internal/engagement"
)

// throttle enforces the RoE pacing knobs in the executor: a per-target token
// bucket (MaxRPS) and a global concurrency cap (MaxConcurrent). It lives in the
// engine, not the guard, so the guard stays pure and I/O-free. Both waits honor
// the cancellable context, so Ctrl-C / deadline aborts in-flight pacing.
type throttle struct {
	rps       rate.Limit
	burst     int
	mu        sync.Mutex
	perTarget map[string]*rate.Limiter
	sem       *semaphore.Weighted // nil ⇒ unlimited concurrency
}

func newThrottle(r engagement.RoE) *throttle {
	rps, burst := rate.Inf, 1
	if r.MaxRPS > 0 {
		rps = rate.Limit(r.MaxRPS)
		if b := int(math.Ceil(r.MaxRPS)); b > 1 {
			burst = b
		}
	}
	t := &throttle{rps: rps, burst: burst, perTarget: make(map[string]*rate.Limiter)}
	if r.MaxConcurrent > 0 {
		t.sem = semaphore.NewWeighted(int64(r.MaxConcurrent))
	}
	return t
}

// limiterFor returns the (lazily created) per-target rate limiter.
func (t *throttle) limiterFor(target string) *rate.Limiter {
	t.mu.Lock()
	defer t.mu.Unlock()
	l, ok := t.perTarget[target]
	if !ok {
		l = rate.NewLimiter(t.rps, t.burst)
		t.perTarget[target] = l
	}
	return l
}

// acquire blocks until a global concurrency slot is free AND the per-target rate
// permits one more request, or ctx is cancelled. The returned release frees the
// concurrency slot and is always safe to call (even after an error).
func (t *throttle) acquire(ctx context.Context, target string) (func(), error) {
	noop := func() {}
	if t.sem != nil {
		if err := t.sem.Acquire(ctx, 1); err != nil {
			return noop, err
		}
	}
	release := func() {
		if t.sem != nil {
			t.sem.Release(1)
		}
	}
	if err := t.limiterFor(target).Wait(ctx); err != nil {
		release() // don't leak the slot if the rate wait is cancelled
		return noop, err
	}
	return release, nil
}
