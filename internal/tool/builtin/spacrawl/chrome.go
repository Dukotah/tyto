package spacrawl

import (
	"context"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// chromeRenderer is the production renderer: it drives a headless Chrome via
// chromedp to navigate, wait for the body, let the SPA settle, and return the
// rendered document HTML. If Chrome cannot be launched (no Chromium binary in the
// environment) chromedp.Run returns an error, which propagates up to Execute and
// triggers the graceful-degrade info finding — the browser is never started at
// construction time, only here on demand.
type chromeRenderer struct{}

func (chromeRenderer) render(ctx context.Context, u string, settle time.Duration, cookie string) (string, error) {
	// A fresh allocator+context per page keeps one wedged tab from poisoning the
	// rest of the crawl. The parent ctx already carries the per-page timeout, so a
	// stuck browser is bounded.
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx,
		append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-sandbox", true),
		)...)
	defer cancelAlloc()

	bctx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	var dom string
	actions := []chromedp.Action{}
	// Carry the engagement session into the render so authenticated SPA areas
	// load logged-in (not the public shell). Setting the Cookie as an extra HTTP
	// header authenticates the navigation AND the SPA's subsequent XHR/fetch calls
	// for same-origin requests, without parsing per-domain cookie attributes.
	if cookie != "" {
		actions = append(actions,
			network.Enable(),
			network.SetExtraHTTPHeaders(network.Headers{"Cookie": cookie}),
		)
	}
	actions = append(actions,
		chromedp.Navigate(u),
		// Wait for the document body, then a settle delay so client-side routing /
		// XHR-driven content has rendered into the DOM before we snapshot it.
		chromedp.WaitReady("body"),
		chromedp.Sleep(settle),
		chromedp.OuterHTML("html", &dom, chromedp.ByQuery),
	)
	if err := chromedp.Run(bctx, actions...); err != nil {
		return "", err
	}
	return dom, nil
}
