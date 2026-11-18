package evidence

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
)

// maxBodyBytes caps how much of each request/response body is captured, matching
// the 64 KiB read cap tyto's HTTP tools already use. Bodies longer than this are
// truncated and the record's *Truncated flag is set.
const maxBodyBytes = 64 << 10

// redactedValue replaces the value of a sensitive header.
const redactedValue = "[REDACTED]"

// sensitiveHeaders are headers whose values carry credentials or tokens and are
// redacted at capture time. Keys are in http.Header canonical form.
var sensitiveHeaders = map[string]bool{
	"Authorization":        true,
	"Proxy-Authorization":  true,
	"Cookie":               true,
	"Set-Cookie":           true,
	"X-Api-Key":            true,
	"Api-Key":              true,
	"X-Auth-Token":         true,
	"X-Amz-Security-Token": true,
}

// RoundTripper wraps a base http.RoundTripper and records every request/response
// pair it carries into a Store, with bodies capped and secrets redacted. It lets
// tyto's HTTP tools capture the exact traffic behind a finding without any tool
// knowing the storage details: the engine injects a client whose Transport is a
// RoundTripper, and the tool just makes ordinary requests.
//
// Correlating captured traffic with the finding a tool produces is done out of
// band through a Capture carried on the request context (see WithCapture): each
// recorded evidence ID is appended to the Capture in scope, and the caller
// associates that set with the finding's ID afterward. The RoundTripper itself
// never sees a finding.
//
// Usage (engine side, later — not wired up here):
//
//	store := evidence.NewMemStore()
//	client := evidence.WrapClient(httpTool.Client(), store) // Transport now records
//
//	cap := &evidence.Capture{}
//	ctx := evidence.WithCapture(ctx, cap)
//	res, _ := tool.Execute(ctx, action) // tool's requests use client; traffic captured
//	for _, f := range res.Findings {
//	        store.Associate(f.ID, cap.IDs()...) // bind proof to the finding by ID
//	}
//
// A persistent Store can be substituted without touching tools or this type.
type RoundTripper struct {
	// Base is the underlying transport. If nil, http.DefaultTransport is used.
	Base http.RoundTripper
	// Store receives every captured Record. Required.
	Store Store
}

// RoundTrip records the request, delegates to the base transport, records the
// response, and returns it unchanged. Recording never alters the request or
// response bodies seen by the caller. A transport error is returned as-is and
// nothing is recorded (there is no response pair to capture).
func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBody, reqTrunc := drainBody(&req.Body, req.GetBody)

	base := rt.Base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	respBody, respTrunc := captureResponseBody(resp)

	rec := Record{
		Method:            req.Method,
		URL:               req.URL.String(),
		Status:            resp.StatusCode,
		RequestHeaders:    redactHeaders(req.Header),
		RequestBody:       reqBody,
		RequestTruncated:  reqTrunc,
		ResponseHeaders:   redactHeaders(resp.Header),
		ResponseBody:      respBody,
		ResponseTruncated: respTrunc,
	}
	if rt.Store != nil {
		id := rt.Store.Put(rec)
		if c := CaptureFrom(req.Context()); c != nil {
			c.add(id)
		}
	}
	return resp, nil
}

// WrapClient returns a copy of c whose Transport records into store. The original
// client is not modified; its Timeout, CheckRedirect, Jar, and the existing
// Transport (used as the base) are preserved. A nil c yields a new client.
func WrapClient(c *http.Client, store Store) *http.Client {
	if c == nil {
		return &http.Client{Transport: &RoundTripper{Store: store}}
	}
	clone := *c
	clone.Transport = &RoundTripper{Base: c.Transport, Store: store}
	return &clone
}

// Capture collects the evidence IDs recorded during a scoped sequence of requests
// (typically one tool's Execute). It is safe for concurrent use. Put a Capture on
// a request context with WithCapture; the RoundTripper appends to it.
type Capture struct {
	mu  sync.Mutex
	ids []string
}

func (c *Capture) add(id string) {
	c.mu.Lock()
	c.ids = append(c.ids, id)
	c.mu.Unlock()
}

// IDs returns a copy of the evidence IDs captured so far, in capture order.
func (c *Capture) IDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.ids...)
}

type captureKey struct{}

// WithCapture returns a context that carries c, so requests made with it have
// their captured evidence IDs appended to c.
func WithCapture(ctx context.Context, c *Capture) context.Context {
	return context.WithValue(ctx, captureKey{}, c)
}

// CaptureFrom returns the Capture carried by ctx, or nil if none is set.
func CaptureFrom(ctx context.Context) *Capture {
	c, _ := ctx.Value(captureKey{}).(*Capture)
	return c
}

// drainBody reads up to maxBodyBytes from a request body, then restores the body
// so the caller can still send it. It uses getBody (set by net/http for most
// requests) to obtain a fresh copy when available; otherwise it buffers and
// replaces the body. A nil body captures as empty.
func drainBody(body *io.ReadCloser, getBody func() (io.ReadCloser, error)) (string, bool) {
	if body == nil || *body == nil {
		return "", false
	}
	if getBody != nil {
		rc, err := getBody()
		if err == nil && rc != nil {
			defer rc.Close()
			return readCapped(rc)
		}
	}
	buf, err := io.ReadAll(*body)
	(*body).Close()
	if err != nil {
		*body = io.NopCloser(bytes.NewReader(buf))
		return "", false
	}
	*body = io.NopCloser(bytes.NewReader(buf))
	return cap64(buf)
}

// captureResponseBody reads up to maxBodyBytes of the response body and replaces
// resp.Body with a reader over the full bytes, so the caller reads it intact.
func captureResponseBody(resp *http.Response) (string, bool) {
	if resp == nil || resp.Body == nil {
		return "", false
	}
	buf, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(buf))
	if err != nil {
		return "", false
	}
	return cap64(buf)
}

// readCapped reads an entire stream and returns it capped to maxBodyBytes.
func readCapped(r io.Reader) (string, bool) {
	buf, _ := io.ReadAll(r)
	return cap64(buf)
}

// cap64 returns buf as a string, truncated to maxBodyBytes, with a flag reporting
// whether truncation occurred.
func cap64(buf []byte) (string, bool) {
	if len(buf) > maxBodyBytes {
		return string(buf[:maxBodyBytes]), true
	}
	return string(buf), false
}

// redactHeaders returns a copy of h with sensitive header values replaced. The
// input header is never mutated.
func redactHeaders(h http.Header) http.Header {
	if len(h) == 0 {
		return nil
	}
	out := make(http.Header, len(h))
	for k, vs := range h {
		if sensitiveHeaders[http.CanonicalHeaderKey(k)] {
			out[k] = []string{redactedValue}
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}
