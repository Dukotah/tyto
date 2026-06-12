package validate

import (
	"context"
	"io"
	"net/http"
	"time"
)

// maxBody caps the response body the re-verifiers read per fetch.
const maxBody = 512 << 10

// HTTPFetcher is the production Fetcher: a thin wrapper over *http.Client that
// the engine wires into a Validator. Tests use a fake Fetcher instead, so this
// type is never exercised without a network and is kept deliberately minimal.
type HTTPFetcher struct {
	Client    *http.Client
	UserAgent string
	// Cookie is replayed on every re-verification request so an established
	// session is preserved (re-proof must run with the same auth the scan had).
	Cookie string
}

// NewHTTPFetcher returns an HTTPFetcher with a bounded-timeout client.
func NewHTTPFetcher() *HTTPFetcher {
	return &HTTPFetcher{
		Client:    &http.Client{Timeout: defaultTimeout},
		UserAgent: "tyto-validate",
	}
}

// Fetch performs a GET and returns the response view the re-verifiers need.
func (h *HTTPFetcher) Fetch(ctx context.Context, rawURL string) (Response, error) {
	if h.Client == nil {
		h.Client = &http.Client{Timeout: defaultTimeout}
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Response{}, err
	}
	if h.UserAgent != "" {
		req.Header.Set("User-Agent", h.UserAgent)
	}
	if h.Cookie != "" {
		req.Header.Set("Cookie", h.Cookie)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return Response{
		Status: resp.StatusCode,
		Header: resp.Header,
		Body:   string(body),
	}, nil
}

// ensure HTTPFetcher satisfies Fetcher at compile time.
var _ Fetcher = (*HTTPFetcher)(nil)

// ensure time import is used (defaultTimeout typed as time.Duration).
var _ = time.Second
