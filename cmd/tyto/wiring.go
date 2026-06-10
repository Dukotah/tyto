package main

import (
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/tool"
	"github.com/dukotah/tyto/internal/tool/builtin/cmdexec"
	"github.com/dukotah/tyto/internal/tool/builtin/corscheck"
	"github.com/dukotah/tyto/internal/tool/builtin/cvematch"
	"github.com/dukotah/tyto/internal/tool/builtin/defaultcreds"
	"github.com/dukotah/tyto/internal/tool/builtin/dirfuzz"
	"github.com/dukotah/tyto/internal/tool/builtin/dnsenum"
	"github.com/dukotah/tyto/internal/tool/builtin/emailsec"
	"github.com/dukotah/tyto/internal/tool/builtin/exploitdb"
	"github.com/dukotah/tyto/internal/tool/builtin/ffufadapter"
	"github.com/dukotah/tyto/internal/tool/builtin/ftpcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/httpmethods"
	"github.com/dukotah/tyto/internal/tool/builtin/httpprobe"
	"github.com/dukotah/tyto/internal/tool/builtin/jwtcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/login"
	"github.com/dukotah/tyto/internal/tool/builtin/niktoadapter"
	"github.com/dukotah/tyto/internal/tool/builtin/nmapscan"
	"github.com/dukotah/tyto/internal/tool/builtin/nucleiscan"
	"github.com/dukotah/tyto/internal/tool/builtin/portscan"
	"github.com/dukotah/tyto/internal/tool/builtin/redircheck"
	"github.com/dukotah/tyto/internal/tool/builtin/secretscan"
	"github.com/dukotah/tyto/internal/tool/builtin/smbenum"
	"github.com/dukotah/tyto/internal/tool/builtin/sqliexploit"
	"github.com/dukotah/tyto/internal/tool/builtin/sqlmapadapter"
	"github.com/dukotah/tyto/internal/tool/builtin/sshcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/ssti"
	"github.com/dukotah/tyto/internal/tool/builtin/subtakeover"
	"github.com/dukotah/tyto/internal/tool/builtin/templatescan"
	"github.com/dukotah/tyto/internal/tool/builtin/tlscheck"
	"github.com/dukotah/tyto/internal/tool/builtin/wafdetect"
	"github.com/dukotah/tyto/internal/tool/builtin/webcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/webcrawl"
	"github.com/dukotah/tyto/internal/tool/builtin/webdiscover"
	"github.com/dukotah/tyto/internal/tool/builtin/webinject"
	"github.com/dukotah/tyto/internal/tool/builtin/whatweb"
	"github.com/dukotah/tyto/internal/tool/builtin/wpscanadapter"
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
	r.MustRegister(emailsec.New())
	r.MustRegister(secretscan.New())
	r.MustRegister(wafdetect.New())
	r.MustRegister(subtakeover.New())
	r.MustRegister(templatescan.New())
	r.MustRegister(jwtcheck.New())
	r.MustRegister(cvematch.New())
	r.MustRegister(dirfuzz.New())
	r.MustRegister(ssti.New())
	// Exploitation tier (exploit-category, RiskHigh) — the Scope Guard only lets
	// these run with a verified authorization grant for the target.
	r.MustRegister(cmdexec.New())
	r.MustRegister(sqliexploit.New())
	r.MustRegister(defaultcreds.New())
	r.MustRegister(login.New())
	r.MustRegister(smbenum.New())
	r.MustRegister(exploitdb.New())
	// Kali shell-out adapters (runtime-detected; degrade gracefully if absent).
	r.MustRegister(nmapscan.New())
	r.MustRegister(nucleiscan.New())
	r.MustRegister(ffufadapter.New())
	r.MustRegister(niktoadapter.New())
	r.MustRegister(whatweb.New())
	r.MustRegister(wpscanadapter.New())
	r.MustRegister(sqlmapadapter.New())
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
