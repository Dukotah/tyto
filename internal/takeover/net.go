package takeover

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// NetResolver is the production Resolver: a thin wrapper over *net.Resolver. It
// is never exercised in unit tests (those inject a fake), so it stays minimal.
type NetResolver struct {
	Resolver *net.Resolver
}

// NewNetResolver returns a NetResolver backed by the system default resolver.
func NewNetResolver() *NetResolver { return &NetResolver{Resolver: net.DefaultResolver} }

func (n *NetResolver) resolver() *net.Resolver {
	if n.Resolver != nil {
		return n.Resolver
	}
	return net.DefaultResolver
}

// LookupCNAME resolves the canonical name for host, normalized.
func (n *NetResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	c, err := n.resolver().LookupCNAME(ctx, host)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.ToLower(c), "."), nil
}

// LookupHost resolves host's addresses. A net.DNSError with IsNotFound set is
// returned verbatim so IsNotFound (which honors net.DNSError) recognizes the
// NXDOMAIN unclaimed signal.
func (n *NetResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return n.resolver().LookupHost(ctx, host)
}

// ensure NetResolver satisfies Resolver at compile time.
var _ Resolver = (*NetResolver)(nil)

// HTTPFetcher is the production Fetcher: a thin *http.Client wrapper. It tries
// HTTPS first then falls back to HTTP, because takeover fingerprints are served
// on either scheme depending on whether the provider terminates TLS. Tests use
// a fake Fetcher instead.
type HTTPFetcher struct {
	Client    *http.Client
	UserAgent string
}

// fetchMaxBody bounds the response body read per fetch.
const fetchMaxBody = 256 << 10

// NewHTTPFetcher returns an HTTPFetcher with a bounded-timeout client that does
// not follow redirects (a redirect off the provider host would lose the
// unclaimed fingerprint).
func NewHTTPFetcher() *HTTPFetcher {
	return &HTTPFetcher{
		Client: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		UserAgent: "tyto-takeover",
	}
}

func (h *HTTPFetcher) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	h.Client = &http.Client{Timeout: 8 * time.Second}
	return h.Client
}

// Fetch GETs the host, trying https:// then http://, returning the first
// successful response's status and (bounded) body.
func (h *HTTPFetcher) Fetch(ctx context.Context, host string) (int, string, error) {
	var lastErr error
	for _, scheme := range []string{"https://", "http://"} {
		status, body, err := h.do(ctx, scheme+host)
		if err == nil {
			return status, body, nil
		}
		lastErr = err
	}
	return 0, "", lastErr
}

func (h *HTTPFetcher) do(ctx context.Context, rawURL string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", err
	}
	if h.UserAgent != "" {
		req.Header.Set("User-Agent", h.UserAgent)
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, fetchMaxBody))
	return resp.StatusCode, string(body), nil
}

// ensure HTTPFetcher satisfies Fetcher at compile time.
var _ Fetcher = (*HTTPFetcher)(nil)
