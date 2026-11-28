package tool

import "net/http"

// TransportWrapper is an optional capability of HTTP-based tools: it lets the
// caller layer a RoundTripper under the tool's own HTTP client. It is the single
// seam for cross-cutting request behavior — the engagement traffic marker today,
// evidence capture next — so tools never need to know about either.
type TransportWrapper interface {
	WrapTransport(wrap func(http.RoundTripper) http.RoundTripper)
}

// MarkTraffic stamps header: value on every HTTP request the registry's native
// tools send to an in-scope destination, and returns how many tools were wired.
//
// The marker exists for the defenders: it lets a SOC separate authorized test
// traffic from a real attack with one filter. inScope is consulted per request
// (including redirect hops) so the engagement id is never disclosed to a third
// party the target happens to redirect to. A header the tool set itself is left
// alone. Shell-out tools (nmap, nuclei, sqlmap, …) build their own requests and
// are NOT covered — the attack timeline is the attribution record for those.
func MarkTraffic(reg *Registry, header, value string, inScope func(*http.Request) bool) int {
	n := 0
	for _, t := range reg.All() {
		w, ok := t.(TransportWrapper)
		if !ok {
			continue
		}
		w.WrapTransport(func(next http.RoundTripper) http.RoundTripper {
			return &markingTransport{next: next, header: header, value: value, inScope: inScope}
		})
		n++
	}
	return n
}

type markingTransport struct {
	next          http.RoundTripper
	header, value string
	inScope       func(*http.Request) bool
}

func (m *markingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	next := m.next
	if next == nil {
		next = http.DefaultTransport
	}
	if req.Header.Get(m.header) != "" || (m.inScope != nil && !m.inScope(req)) {
		return next.RoundTrip(req)
	}
	// A RoundTripper must not modify the caller's request: mark a shallow copy.
	marked := req.Clone(req.Context())
	marked.Header.Set(m.header, m.value)
	return next.RoundTrip(marked)
}
