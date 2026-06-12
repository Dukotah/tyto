package oob

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Collaborator is the long-lived OOB listener and token store. It is safe for
// concurrent use: the HTTP and DNS listener goroutines call Record while injection
// tools call Register and Poll. The RWMutex guards interactions + hits; listeners
// holds the net handles between Start and Close.
type Collaborator struct {
	cfg Config

	mu           sync.RWMutex
	counter      uint64                 // monotonic token source (see mintToken)
	interactions map[string]Interaction // token -> issued probe
	hits         map[string][]Hit       // token -> recorded callbacks

	// listeners, guarded by lmu so Start/Close don't race the goroutines.
	lmu    sync.Mutex
	httpLn net.Listener
	dnsLn  net.PacketConn
	srv    *http.Server
	cancel context.CancelFunc
}

// New returns a Collaborator with Config defaults applied. Tokens come from an
// internal monotonic counter (see mintToken) — New does NOT seed from the wall
// clock or rand, so token values are reproducible across runs and unit-testable.
// The returned collaborator is not listening until Start is called.
func New(cfg Config) *Collaborator {
	return &Collaborator{
		cfg:          cfg.withDefaults(),
		interactions: make(map[string]Interaction),
		hits:         make(map[string][]Hit),
	}
}

// Config returns the effective (defaults-applied) configuration.
func (c *Collaborator) Config() Config { return c.cfg }

// Register mints a fresh token, builds its callback Domain and URL, stores the
// Interaction, and returns a copy for the injection tool to embed in a payload.
// class is the vuln class ("ssrf" | "blind-xss" | "cmd-injection" | "sqli-oob"),
// target the URL/host under test, param the injected parameter name (may be "").
func (c *Collaborator) Register(class, target, param string) *Interaction {
	c.mu.Lock()
	token := mintToken(c.counter)
	c.counter++
	domain := domainFor(c.cfg, token)
	it := Interaction{
		Token:   token,
		Domain:  domain,
		URL:     urlFor(c.cfg, token, domain),
		Class:   class,
		Target:  target,
		Param:   param,
		Created: time.Now().UTC(),
	}
	c.interactions[token] = it
	c.mu.Unlock()
	out := it
	return &out
}

// Record stores an inbound callback. Listeners and tests both call this. Hits for
// an unknown token are dropped — only callbacks we can correlate to an issued
// probe are evidence; recording stray traffic would only invite spoofed noise.
func (c *Collaborator) Record(h Hit) {
	if h.At.IsZero() {
		h.At = time.Now().UTC()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.interactions[h.Token]; !ok {
		return
	}
	c.hits[h.Token] = append(c.hits[h.Token], h)
}

// Poll returns the callbacks recorded for one token (nil if none yet). The slice
// is a copy, safe to read without holding the lock.
func (c *Collaborator) Poll(token string) []Hit {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h := c.hits[token]
	if len(h) == 0 {
		return nil
	}
	out := make([]Hit, len(h))
	copy(out, h)
	return out
}

// Hits returns a flat copy of every recorded callback across all tokens.
func (c *Collaborator) Hits() []Hit {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []Hit
	for _, hs := range c.hits {
		out = append(out, hs...)
	}
	return out
}

// Interactions returns a copy of every issued probe.
func (c *Collaborator) Interactions() []Interaction {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Interaction, 0, len(c.interactions))
	for _, it := range c.interactions {
		out = append(out, it)
	}
	return out
}

// Lookup returns the Interaction for a token, if it was issued by this instance.
func (c *Collaborator) Lookup(token string) (Interaction, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	it, ok := c.interactions[token]
	return it, ok
}

// MatchToken pulls a known token out of an arbitrary hostname or path. A callback
// carries its token as a host label ("<token>.oob.example.com") or a path segment
// ("/x/<token>"), so we split on both dots and slashes and return the first
// segment that is a live token. Returns ("", false) when none matches.
func (c *Collaborator) MatchToken(s string) (string, bool) {
	s = strings.ToLower(s)
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '.' || r == '/'
	}) {
		if _, ok := c.interactions[seg]; ok {
			return seg, true
		}
	}
	return "", false
}

// Start binds the HTTP (TCP) and DNS (UDP) listeners and serves both in the
// background. It returns the FIRST bind error encountered, leaving nothing
// running so the caller can degrade to "OOB unavailable" rather than half-up.
func (c *Collaborator) Start(ctx context.Context) error {
	c.lmu.Lock()
	defer c.lmu.Unlock()
	if c.httpLn != nil || c.dnsLn != nil {
		return fmt.Errorf("oob: already started")
	}

	httpLn, err := net.Listen("tcp", c.cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("oob: http listen %s: %w", c.cfg.HTTPAddr, err)
	}
	dnsLn, err := net.ListenPacket("udp", c.cfg.DNSAddr)
	if err != nil {
		_ = httpLn.Close()
		return fmt.Errorf("oob: dns listen %s: %w", c.cfg.DNSAddr, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	c.httpLn = httpLn
	c.dnsLn = dnsLn
	c.cancel = cancel
	c.srv = &http.Server{
		Handler:           http.HandlerFunc(c.handleHTTP),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { _ = c.serveHTTP(ctx, httpLn) }()
	go func() { _ = c.serveDNS(ctx, dnsLn) }()
	return nil
}

// Close stops both listeners. Safe to call on a never-started collaborator and
// idempotent on repeat.
func (c *Collaborator) Close() error {
	c.lmu.Lock()
	defer c.lmu.Unlock()
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	var firstErr error
	if c.srv != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := c.srv.Shutdown(shutCtx); err != nil {
			firstErr = err
		}
		cancel()
		c.srv = nil
		c.httpLn = nil // Shutdown closed it
	}
	if c.dnsLn != nil {
		if err := c.dnsLn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.dnsLn = nil
	}
	return firstErr
}

// serveHTTP serves the HTTP callback endpoint until ctx is cancelled. It is the
// inline HTTP half of the listener; the DNS half lives in dns.go (serveDNS).
func (c *Collaborator) serveHTTP(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = c.srv.Shutdown(shutCtx)
	}()
	err := c.srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// handleHTTP records any request that carries a known token in its Host subdomain
// (left-most label) or its URL path, then answers a tiny neutral 200 so the
// calling backend doesn't error. The Detail string is quarantined evidence.
func (c *Collaborator) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Prefer the left-most Host label; fall back to scanning host+path for a token
	// (covers proxies that rewrite the path or drop the subdomain).
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	token := ""
	if label, _, ok := strings.Cut(host, "."); ok {
		c.mu.RLock()
		_, known := c.interactions[label]
		c.mu.RUnlock()
		if known {
			token = label
		}
	}
	if token == "" {
		if t, ok := c.MatchToken(host + "/" + r.URL.Path); ok {
			token = t
		}
	}
	if token != "" {
		ua := r.Header.Get("User-Agent")
		c.Record(Hit{
			Token:      token,
			Proto:      ProtoHTTP,
			RemoteAddr: r.RemoteAddr,
			Detail:     fmt.Sprintf("%s %s UA=%s", r.Method, r.URL.RequestURI(), ua),
			At:         time.Now().UTC(),
		})
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
