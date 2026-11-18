package engine

import (
	"context"
	"testing"
)

func TestEstimateTokens(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"a", 1},
		{"abcd", 1},     // 4 chars / 4
		{"abcde", 2},    // ceil(5/4)
		{"abcdefgh", 2}, // 8 / 4
	}
	for _, tc := range tests {
		if got := estimateTokens(tc.in); got != tc.want {
			t.Errorf("estimateTokens(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestBudgetTokensExhausted(t *testing.T) {
	// Unlimited by default: any usage is fine when no ceiling is set.
	b := &budget{estimate: estimateTokens}
	b.tokens = 1_000_000
	if b.tokensExhausted() {
		t.Fatal("a zero token ceiling must mean unlimited")
	}
	// With a ceiling, exhaustion triggers at or above it.
	b = &budget{maxTokens: 10, estimate: estimateTokens}
	if b.tokensExhausted() {
		t.Fatal("fresh budget should not be exhausted")
	}
	b.addText("0123456789012345678901234567890123456789") // 40 chars -> 10 tokens
	if !b.tokensExhausted() {
		t.Fatalf("budget should be exhausted at the ceiling (tokens=%d)", b.tokens)
	}
}

func TestEstimatorIsSwappable(t *testing.T) {
	// A custom estimator that charges a flat 100 tokens per fragment blows a small
	// ceiling in one cycle, proving Options.EstimateTokens is honored.
	client := &countingClient{}
	var events []Event
	e, _ := termEngine(t, client, Options{
		MaxCycles:      5,
		MaxTokens:      50,
		EstimateTokens: func(string) int { return 100 },
		OnEvent:        func(ev Event) { events = append(events, ev) },
	})
	if err := e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Cycle 1 runs (prompt+response each cost 100 under the custom estimator), so by
	// cycle 2 the budget is spent and the run stops.
	if client.calls != 1 {
		t.Fatalf("custom estimator should halt after 1 planning turn, got %d", client.calls)
	}
	if !hasTerminalReason(events, reasonTokenBudget) {
		t.Fatalf("want a budget event with reason %q; events=%v", reasonTokenBudget, events)
	}
}

func TestTokenBudgetTerminates(t *testing.T) {
	client := &countingClient{}
	var events []Event
	// A tiny ceiling (1) is blown by the first cycle's real prompt, so the run stops
	// cleanly at the top of cycle 2 with the token-budget terminal reason.
	e, _ := termEngine(t, client, Options{
		MaxCycles: 10,
		MaxTokens: 1,
		OnEvent:   func(ev Event) { events = append(events, ev) },
	})
	if err := e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 {
		t.Fatalf("token budget should halt after 1 planning turn, got %d", client.calls)
	}
	if !hasTerminalReason(events, reasonTokenBudget) {
		t.Fatalf("want terminal reason %q on a done/budget event; events=%v", reasonTokenBudget, events)
	}
}

func TestCycleBudgetTerminates(t *testing.T) {
	client := &countingClient{}
	var events []Event
	// No-progress limit set above MaxCycles so it can't fire first; the loop then
	// runs to its cycle ceiling and halts with the cycle-budget terminal reason.
	e, _ := termEngine(t, client, Options{
		MaxCycles:            3,
		NoProgressCycleLimit: 99,
		OnEvent:              func(ev Event) { events = append(events, ev) },
	})
	if err := e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.calls != 3 {
		t.Fatalf("want exactly MaxCycles=3 planning turns, got %d", client.calls)
	}
	if !hasTerminalReason(events, reasonCycleBudget) {
		t.Fatalf("want terminal reason %q; events=%v", reasonCycleBudget, events)
	}
}

// hasTerminalReason reports whether any emitted event carries the given terminal
// reason (budget events, and the final done event, both set Event.Reason).
func hasTerminalReason(events []Event, reason string) bool {
	for _, ev := range events {
		if ev.Reason == reason {
			return true
		}
	}
	return false
}
