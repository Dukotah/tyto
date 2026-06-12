package oob

// This file is the LEGACY env-driven convenience layer. The package's core types
// (Collaborator, Interaction, Hit, Config, New) now live in collaborator.go /
// interaction.go, which own those identifiers. To avoid duplicate-symbol
// collisions while preserving the handy process-wide, environment-configured
// listener, Collector is now a thin wrapper around Collaborator and Default()
// builds one from TYTO_OOB_* env vars.

import (
	"context"
	"os"
	"strings"
	"sync"
)

// Collector is a process-wide convenience wrapper over a Collaborator. Prefer
// constructing a Collaborator with New(Config) directly; Collector exists for the
// env-driven Default() singleton below.
type Collector struct {
	*Collaborator
	cancel context.CancelFunc
}

// newCollectorFromEnv builds a Collector from TYTO_OOB_BASE (callback base domain)
// and the listen addresses, applying Config defaults. listenHTTP/listenDNS empty
// means "use the Config defaults".
func newCollectorFromEnv() *Collector {
	base := strings.TrimSpace(os.Getenv("TYTO_OOB_BASE"))
	base = strings.TrimPrefix(base, "http://")
	base = strings.TrimPrefix(base, "https://")
	base = strings.Trim(base, "/")
	cfg := Config{
		BaseDomain: base, // "" → New fills the documented default
		HTTPAddr:   os.Getenv("TYTO_OOB_HTTP"),
		DNSAddr:    os.Getenv("TYTO_OOB_DNS"),
	}
	return &Collector{Collaborator: New(cfg)}
}

// Start binds and serves both listeners using a background context, returning the
// first bind error so callers can degrade to "OOB unavailable".
func (c *Collector) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	if err := c.Collaborator.Start(ctx); err != nil {
		cancel()
		return err
	}
	return nil
}

// Close stops the listeners.
func (c *Collector) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	return c.Collaborator.Close()
}

var (
	defaultOnce sync.Once
	defaultCol  *Collector
)

// Default returns the process-wide collector, starting its listeners once on first
// use from the TYTO_OOB_* environment. If a listener can't bind, the collector is
// still returned (callers degrade to "OOB unavailable") rather than erroring.
func Default() *Collector {
	defaultOnce.Do(func() {
		defaultCol = newCollectorFromEnv()
		_ = defaultCol.Start()
	})
	return defaultCol
}
