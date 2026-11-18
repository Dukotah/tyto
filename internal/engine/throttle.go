package engine

import (
	"context"
	"math"
	"strings"
	"sync"

	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"

	"github.com/dukotah/tyto/internal/engagement"
)

// Noise-governor tuning. The governor adds an ADAPTIVE backoff on top of the
// static RoE pacing: when a target shows trouble (rate-limiting / instability) it
// raises that target's "pressure", which slows its limiter; a clean result decays
// the pressure back toward calm. These are deliberately conservative — the
// governor only ever slows us down, never speeds past the RoE ceiling.
const (
	// governorMaxPressure caps how far a single target can be backed off.
	governorMaxPressure = 5
	// governorTroubleCeiling (req/s) is the rate a target is capped to the moment
	// ANY pressure is present — even if the static RoE left it unthrottled (Inf).
	governorTroubleCeiling rate.Limit = 1
	// governorFloor (req/s) is the slowest the governor will ever go: ~1 request
	// every 10s, so a struggling-but-live target is still probed, just gently.
	governorFloor rate.Limit = 0.1
)

// throttle enforces the RoE pacing knobs in the executor: a per-target token
// bucket (MaxRPS) and a global concurrency cap (MaxConcurrent). It also hosts the
// noise governor, which adapts the per-target rate to trouble signals observed in
// tool results. It lives in the engine, not the guard, so the guard stays pure and
// I/O-free. Both waits honor the cancellable context, so Ctrl-C / deadline aborts
// in-flight pacing.
type throttle struct {
	rps       rate.Limit
	burst     int
	mu        sync.Mutex
	perTarget map[string]*targetState
	sem       *semaphore.Weighted // nil ⇒ unlimited concurrency
}

// targetState is one target's limiter plus its governor pressure. pressure 0 is
// calm: the limiter runs at exactly the static RoE rate, so a target that never
// shows trouble behaves identically to the pre-governor throttle.
type targetState struct {
	limiter  *rate.Limiter
	pressure int
}

func newThrottle(r engagement.RoE) *throttle {
	rps, burst := rate.Inf, 1
	if r.MaxRPS > 0 {
		rps = rate.Limit(r.MaxRPS)
		if b := int(math.Ceil(r.MaxRPS)); b > 1 {
			burst = b
		}
	}
	t := &throttle{rps: rps, burst: burst, perTarget: make(map[string]*targetState)}
	if r.MaxConcurrent > 0 {
		t.sem = semaphore.NewWeighted(int64(r.MaxConcurrent))
	}
	return t
}

// stateFor returns the (lazily created) per-target state. Callers hold t.mu.
func (t *throttle) stateFor(target string) *targetState {
	ts, ok := t.perTarget[target]
	if !ok {
		ts = &targetState{limiter: rate.NewLimiter(t.rps, t.burst)}
		t.perTarget[target] = ts
	}
	return ts
}

// limiterFor returns the (lazily created) per-target rate limiter.
func (t *throttle) limiterFor(target string) *rate.Limiter {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stateFor(target).limiter
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

// observe feeds one tool result to the noise governor. A trouble signal raises the
// target's pressure (slowing its limiter); a clean result decays it one step back
// toward calm. With no trouble ever seen, pressure stays 0 and the limiter keeps
// the static RoE rate — so a quiet run is byte-for-byte the old behaviour.
func (t *throttle) observe(target, output, errText string) {
	troubled := troubleSignal(output, errText)
	t.mu.Lock()
	defer t.mu.Unlock()
	ts := t.stateFor(target)
	switch {
	case troubled && ts.pressure < governorMaxPressure:
		ts.pressure++
	case !troubled && ts.pressure > 0:
		ts.pressure-- // relax gradually as the target recovers
	default:
		return // no change ⇒ don't touch the limiter
	}
	t.applyPressure(ts)
}

// applyPressure sets a target's limiter to match its current pressure. Callers
// hold t.mu. At pressure 0 the limiter is restored to the exact static RoE rate.
func (t *throttle) applyPressure(ts *targetState) {
	if ts.pressure <= 0 {
		ts.limiter.SetLimit(t.rps)
		ts.limiter.SetBurst(t.burst)
		return
	}
	// Under pressure: cap at the conservative trouble ceiling (even if the static
	// rate was Inf) and halve per additional step, down to the floor. Burst drops to
	// 1 so a backed-off target can't be hit in a clump.
	ts.limiter.SetLimit(governedLimit(t.rps, ts.pressure))
	ts.limiter.SetBurst(1)
}

// governedLimit computes a target's effective rate for a given pressure. Pressure
// 0 returns the static base unchanged (today's behaviour); any pressure caps at
// governorTroubleCeiling and halves per further step, floored at governorFloor.
func governedLimit(base rate.Limit, pressure int) rate.Limit {
	if pressure <= 0 {
		return base
	}
	ceil := base
	if ceil == rate.Inf || ceil > governorTroubleCeiling {
		ceil = governorTroubleCeiling
	}
	eff := ceil / rate.Limit(int64(1)<<(pressure-1))
	if eff < governorFloor {
		eff = governorFloor
	}
	return eff
}

// troubleSignal reports whether a tool result shows the target is rate-limiting us
// or is unstable, so the governor should back off. Result carries no structured
// status code, so this is a conservative string heuristic over the tool's output
// and error text: over-matching only slows us (safe), under-matching is the risk,
// so the common forms of 429/503 and connection resets are all covered.
func troubleSignal(output, errText string) bool {
	hay := strings.ToLower(output + "\n" + errText)
	signals := []string{
		"429", "too many requests", "rate limit", "rate-limit", "retry-after",
		"503", "service unavailable", "server overloaded",
		"connection reset", "reset by peer", "connection refused",
		"i/o timeout", "broken pipe", "econnreset",
	}
	for _, s := range signals {
		if strings.Contains(hay, s) {
			return true
		}
	}
	return false
}
