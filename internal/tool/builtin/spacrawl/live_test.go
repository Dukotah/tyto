package spacrawl

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dukotah/tyto/internal/action"
)

// TestLiveRender is an opt-in live smoke test: it drives the REAL chromedp
// renderer against a live URL to confirm a browser actually launches and renders
// in this environment (the unit tests use a fake renderer). It is skipped unless
// TYTO_LIVE=1 so normal/CI runs never touch the network or require a browser.
//
//	TYTO_LIVE=1 go test ./internal/tool/builtin/spacrawl/ -run TestLiveRender -v
func TestLiveRender(t *testing.T) {
	if os.Getenv("TYTO_LIVE") != "1" {
		t.Skip("set TYTO_LIVE=1 to run the live headless-browser smoke test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tool := New()
	res, err := tool.Execute(ctx, action.Action{
		Target: "https://example.com/",
		Params: map[string]string{"max_pages": "1", "max_depth": "0"},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Fatalf("Execute did not succeed: %q", res.Output)
	}
	// Graceful-degrade (no browser) emits an info finding mentioning the browser is
	// unavailable. A genuine render should NOT say that.
	for _, f := range res.Findings {
		if containsAny(f.Title+" "+f.Description, "headless browser unavailable", "browser unavailable") {
			t.Fatalf("browser did not launch — got graceful-degrade: %q / %q", f.Title, f.Description)
		}
	}
	t.Logf("live render OK: %d finding(s), %d asset(s), output=%q", len(res.Findings), len(res.Assets), res.Output)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
