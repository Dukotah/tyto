package main

import (
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/tool"
	"github.com/dukotah/tyto/internal/tool/builtin/corscheck"
	"github.com/dukotah/tyto/internal/tool/builtin/dnsenum"
	"github.com/dukotah/tyto/internal/tool/builtin/ftpcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/httpmethods"
	"github.com/dukotah/tyto/internal/tool/builtin/httpprobe"
	"github.com/dukotah/tyto/internal/tool/builtin/portscan"
	"github.com/dukotah/tyto/internal/tool/builtin/redircheck"
	"github.com/dukotah/tyto/internal/tool/builtin/sshcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/tlscheck"
	"github.com/dukotah/tyto/internal/tool/builtin/webcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/webcrawl"
	"github.com/dukotah/tyto/internal/tool/builtin/webdiscover"
	"github.com/dukotah/tyto/internal/tool/builtin/webinject"
)

// defaultRegistry wires the built-in tool adapters.
func defaultRegistry() *tool.Registry {
	r := tool.NewRegistry()
	r.MustRegister(portscan.New())
	r.MustRegister(httpprobe.New())
	r.MustRegister(webcheck.New())
	r.MustRegister(webdiscover.New())
	r.MustRegister(tlscheck.New())
	r.MustRegister(webcrawl.New())
	r.MustRegister(webinject.New())
	r.MustRegister(corscheck.New())
	r.MustRegister(redircheck.New())
	r.MustRegister(httpmethods.New())
	r.MustRegister(dnsenum.New())
	r.MustRegister(sshcheck.New())
	r.MustRegister(ftpcheck.New())
	return r
}

// toolSnapshot builds the immutable, read-only authority the Scope Guard gates
// on: each tool's authoritative category + risk ceiling, with no access to
// Execute. The guard never trusts model-supplied risk/category.
func toolSnapshot(r *tool.Registry) map[string]guard.ToolMeta {
	m := make(map[string]guard.ToolMeta)
	for _, t := range r.All() {
		m[t.Name()] = guard.ToolMeta{Category: t.Category(), MaxRisk: t.MaxRisk()}
	}
	return m
}
