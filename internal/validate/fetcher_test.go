package validate

import "testing"

// TestCookieFor_HostAwareSelection proves the fetcher picks the per-host session
// cookie when one exists for the URL's host, falls back to the single Cookie
// otherwise, and strips the port when matching.
func TestCookieFor_HostAwareSelection(t *testing.T) {
	h := &HTTPFetcher{
		Cookie:  "fallback=1",
		Cookies: map[string]string{"app.test": "sid=app", "api.test": "sid=api"},
	}
	cases := []struct {
		url, want string
	}{
		{"https://app.test/dashboard", "sid=app"},         // host match
		{"http://api.test:8080/v1/users?id=1", "sid=api"}, // host match, port stripped
		{"https://other.test/x", "fallback=1"},            // no host entry -> fallback
		{"http://APP.TEST/x", "sid=app"},                  // case-insensitive host
	}
	for _, c := range cases {
		if got := h.cookieFor(c.url); got != c.want {
			t.Errorf("cookieFor(%q) = %q, want %q", c.url, got, c.want)
		}
	}

	// No host map at all -> always the fallback Cookie.
	h2 := &HTTPFetcher{Cookie: "only=1"}
	if got := h2.cookieFor("https://app.test/"); got != "only=1" {
		t.Errorf("cookieFor with no Cookies map = %q, want %q", got, "only=1")
	}
}
