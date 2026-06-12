package main

import (
	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/tool"
	"github.com/dukotah/tyto/internal/tool/builtin/accesscontrol"
	"github.com/dukotah/tyto/internal/tool/builtin/apidocs"
	"github.com/dukotah/tyto/internal/tool/builtin/cmdexec"
	"github.com/dukotah/tyto/internal/tool/builtin/cookieaudit"
	"github.com/dukotah/tyto/internal/tool/builtin/corscheck"
	"github.com/dukotah/tyto/internal/tool/builtin/cvematch"
	"github.com/dukotah/tyto/internal/tool/builtin/defaultcreds"
	"github.com/dukotah/tyto/internal/tool/builtin/dirfuzz"
	"github.com/dukotah/tyto/internal/tool/builtin/dnsenum"
	"github.com/dukotah/tyto/internal/tool/builtin/dotgit"
	"github.com/dukotah/tyto/internal/tool/builtin/emailsec"
	"github.com/dukotah/tyto/internal/tool/builtin/exploitdb"
	"github.com/dukotah/tyto/internal/tool/builtin/ffufadapter"
	"github.com/dukotah/tyto/internal/tool/builtin/ftpcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/gobuster"
	"github.com/dukotah/tyto/internal/tool/builtin/graphqlcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/hostheader"
	"github.com/dukotah/tyto/internal/tool/builtin/httpmethods"
	"github.com/dukotah/tyto/internal/tool/builtin/httpprobe"
	"github.com/dukotah/tyto/internal/tool/builtin/hydra"
	"github.com/dukotah/tyto/internal/tool/builtin/jsmine"
	"github.com/dukotah/tyto/internal/tool/builtin/jwtcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/kali"
	"github.com/dukotah/tyto/internal/tool/builtin/kerberoast"
	"github.com/dukotah/tyto/internal/tool/builtin/ldapenum"
	"github.com/dukotah/tyto/internal/tool/builtin/login"
	"github.com/dukotah/tyto/internal/tool/builtin/metasploit"
	"github.com/dukotah/tyto/internal/tool/builtin/netsweep"
	"github.com/dukotah/tyto/internal/tool/builtin/niktoadapter"
	"github.com/dukotah/tyto/internal/tool/builtin/nmapscan"
	"github.com/dukotah/tyto/internal/tool/builtin/nucleiscan"
	"github.com/dukotah/tyto/internal/tool/builtin/oobcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/portscan"
	"github.com/dukotah/tyto/internal/tool/builtin/redircheck"
	"github.com/dukotah/tyto/internal/tool/builtin/secretscan"
	"github.com/dukotah/tyto/internal/tool/builtin/shell"
	"github.com/dukotah/tyto/internal/tool/builtin/smbenum"
	"github.com/dukotah/tyto/internal/tool/builtin/spacrawl"
	"github.com/dukotah/tyto/internal/tool/builtin/sqliexploit"
	"github.com/dukotah/tyto/internal/tool/builtin/sqlmapadapter"
	"github.com/dukotah/tyto/internal/tool/builtin/sshcheck"
	"github.com/dukotah/tyto/internal/tool/builtin/ssti"
	"github.com/dukotah/tyto/internal/tool/builtin/subfinder"
	"github.com/dukotah/tyto/internal/tool/builtin/subtakeover"
	"github.com/dukotah/tyto/internal/tool/builtin/templatescan"
	"github.com/dukotah/tyto/internal/tool/builtin/testssladapter"
	"github.com/dukotah/tyto/internal/tool/builtin/tlscheck"
	"github.com/dukotah/tyto/internal/tool/builtin/trivyscan"
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
	// Host discovery across a CIDR → live `host` assets, the missing first step that
	// lets a bare range target ("10.0.0.0/24") drive per-host enumeration.
	r.MustRegister(netsweep.New())
	r.MustRegister(httpprobe.New())
	r.MustRegister(webcheck.New())
	r.MustRegister(webdiscover.New())
	r.MustRegister(tlscheck.New())
	r.MustRegister(webcrawl.New())
	r.MustRegister(jsmine.New())
	r.MustRegister(dotgit.New())
	r.MustRegister(cookieaudit.New())
	r.MustRegister(graphqlcheck.New())
	r.MustRegister(apidocs.New())
	r.MustRegister(webinject.New())
	r.MustRegister(corscheck.New())
	r.MustRegister(redircheck.New())
	r.MustRegister(httpmethods.New())
	// Host-header injection (cache/reset poisoning) — reflection-detection only.
	r.MustRegister(hostheader.New())
	// Broken-access-control / IDOR — GET-only differential (authed-vs-anon +
	// object-id mutation), refute-by-default. RiskMedium (may read another object).
	r.MustRegister(accesscontrol.New())
	r.MustRegister(dnsenum.New())
	r.MustRegister(sshcheck.New())
	r.MustRegister(ftpcheck.New())
	r.MustRegister(emailsec.New())
	r.MustRegister(secretscan.New())
	r.MustRegister(wafdetect.New())
	r.MustRegister(subtakeover.New())
	r.MustRegister(templatescan.New())
	// Headless-browser SPA crawler: renders JS apps to surface links/forms/XHR
	// endpoints the static crawlers miss. Graceful-degrades (honest info finding)
	// where no Chromium binary is installed.
	r.MustRegister(spacrawl.New())
	// Trivy dependency/container/filesystem CVE scanner (shell-out, routed through
	// the Kali backend). Registered for on-demand image/repo/fs scans; no auto-fire
	// methodology node since web recon does not emit image/repo assets. Graceful-
	// degrades when trivy is not installed.
	r.MustRegister(trivyscan.New())
	r.MustRegister(jwtcheck.New())
	r.MustRegister(cvematch.New())
	r.MustRegister(dirfuzz.New())
	r.MustRegister(ssti.New())
	// Out-of-band collaborator probe: catches BLIND vulns (SSRF/RCE/OOB-SQLi/blind
	// XSS) that leave no in-band response change. Resolves the process-wide oob
	// listener lazily on first Execute, so registering/listing it binds no ports.
	r.MustRegister(oobcheck.New())
	// Exploitation tier (exploit-category, RiskHigh) — the Scope Guard only lets
	// these run with a verified authorization grant for the target.
	r.MustRegister(cmdexec.New())
	r.MustRegister(sqliexploit.New())
	r.MustRegister(defaultcreds.New())
	r.MustRegister(login.New())
	r.MustRegister(smbenum.New())
	// AD/identity tier (identity-category, RiskMedium; read-only enum + roasting).
	r.MustRegister(ldapenum.New())
	r.MustRegister(kerberoast.New())
	r.MustRegister(exploitdb.New())
	// Kali shell-out adapters (runtime-detected; degrade gracefully if absent).
	r.MustRegister(nmapscan.New())
	r.MustRegister(nucleiscan.New())
	r.MustRegister(ffufadapter.New())
	r.MustRegister(niktoadapter.New())
	r.MustRegister(whatweb.New())
	r.MustRegister(wpscanadapter.New())
	r.MustRegister(sqlmapadapter.New())
	r.MustRegister(subfinder.New())
	r.MustRegister(testssladapter.New())
	r.MustRegister(gobuster.New())
	r.MustRegister(hydra.New())
	r.MustRegister(metasploit.New())
	// The kali tool gives the planner the WHOLE Kali distro (any command), contained
	// to the Kali VM. Read-only commands run within the risk ceiling; any mutating
	// command is force-gated through dashboard approval (ApprovalGater) and is
	// classified RiskHigh by defaultClassifier. This is the supervised way to give
	// the agent free-form arsenal access without the host-RCE risk of `shell`.
	r.MustRegister(kali.New())
	// NOTE: the `shell` tool is deliberately NOT registered here. It runs an
	// arbitrary command (`bash -lc <cmd>`) on tyto's OWN host, not against the
	// engagement target — so exposing it to the autonomous planner is a
	// confused-deputy host-RCE: a hallucinated or prompt-injected action could run
	// host commands while the guard only ever validated the in-scope *target*. The
	// operator console constructs the shell tool DIRECTLY (console.runShell /
	// startOperator), gated by shell.IsReadOnly + explicit operator confirmation —
	// that path never goes through the planner. Keeping shell out of the registry
	// means even a hallucinated {tool:"shell"} proposal resolves to "unknown tool"
	// and is skipped. See TestShellNotPlannerSelectable.
	return r
}

// defaultClassifier is the guard.RiskClassifier installed on every guard: it
// raises an action's effective risk based on its params. Today only the shell
// tool participates (read-only toolbox inspection stays low; arbitrary commands
// become high → require authorization/approval). Every other tool returns the
// passive floor, a no-op that leaves the tool's own MaxRisk authoritative — so
// installing the classifier is behaviorally identical for the existing fleet.
func defaultClassifier() guard.RiskClassifier {
	return func(toolName string, params map[string]string) action.RiskLevel {
		if toolName == "shell" || toolName == "kali" {
			// Read-only commands stay low; any arbitrary/mutating command becomes
			// RiskHigh so the guard's risk ceiling + approval path both apply.
			return shell.Classify(params["command"])
		}
		return action.RiskPassive
	}
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
