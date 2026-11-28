// Package attack maps tyto's tools onto MITRE ATT&CK (Enterprise) techniques and
// onto the defender telemetry each one should produce. It is the bridge between
// what tyto DID (the audit log, keyed by tool) and what a blue team should have
// SEEN: the purple-team timeline, the detection-coverage score, and the ATT&CK
// Navigator layer are all derived from this table.
//
// The mapping is keyed by tool name rather than by methodology-catalog node
// because the audit trail records tools, and one tool backs many catalog nodes.
// It is deliberately conservative: a tool maps to the technique its traffic
// actually resembles on the wire, not to everything it could lead to.
package attack

import "sort"

// Technique is one ATT&CK (sub-)technique.
type Technique struct {
	ID     string `json:"id"`     // e.g. "T1595.002"
	Name   string `json:"name"`   // e.g. "Active Scanning: Vulnerability Scanning"
	Tactic string `json:"tactic"` // e.g. "Reconnaissance"
}

// Mapping is what a defender needs to know about one tool's activity.
type Mapping struct {
	Techniques []Technique `json:"techniques"`
	// Telemetry lists where the activity should be visible to a defender, most
	// specific first. Empty when OffTarget is true.
	Telemetry []string `json:"telemetry,omitempty"`
	// OffTarget is true when the tool never contacts client infrastructure
	// (offline lookups, third-party passive sources). Such activity cannot be
	// detected by the client's sensors, so it is excluded from coverage scoring.
	OffTarget bool `json:"off_target,omitempty"`
}

// Reusable technique definitions (ATT&CK Enterprise).
var (
	tScanIPBlocks   = Technique{"T1595.001", "Active Scanning: Scanning IP Blocks", "Reconnaissance"}
	tVulnScan       = Technique{"T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance"}
	tWordlistScan   = Technique{"T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance"}
	tHostSoftware   = Technique{"T1592.002", "Gather Victim Host Information: Software", "Reconnaissance"}
	tNetDNS         = Technique{"T1590.002", "Gather Victim Network Information: DNS", "Reconnaissance"}
	tNetSecAppl     = Technique{"T1590.006", "Gather Victim Network Information: Network Security Appliances", "Reconnaissance"}
	tVictimSites    = Technique{"T1594", "Search Victim-Owned Websites", "Reconnaissance"}
	tOpenTechDBs    = Technique{"T1596", "Search Open Technical Databases", "Reconnaissance"}
	tObtainExploits = Technique{"T1588.005", "Obtain Capabilities: Exploits", "Resource Development"}
	tObtainVulns    = Technique{"T1588.006", "Obtain Capabilities: Vulnerabilities", "Resource Development"}
	tHijackDomain   = Technique{"T1584.001", "Compromise Infrastructure: Domains", "Resource Development"}
	tExploitPublic  = Technique{"T1190", "Exploit Public-Facing Application", "Initial Access"}
	tValidAccounts  = Technique{"T1078", "Valid Accounts", "Initial Access"}
	tDefaultAccts   = Technique{"T1078.001", "Valid Accounts: Default Accounts", "Initial Access"}
	tCmdInterp      = Technique{"T1059", "Command and Scripting Interpreter", "Execution"}
	tPwGuessing     = Technique{"T1110.001", "Brute Force: Password Guessing", "Credential Access"}
	tKerberoast     = Technique{"T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "Credential Access"}
	tCredsInFiles   = Technique{"T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"}
	tForgeWebCreds  = Technique{"T1606", "Forge Web Credentials", "Credential Access"}
	tNetSvcDisc     = Technique{"T1046", "Network Service Discovery", "Discovery"}
	tRemoteSysDisc  = Technique{"T1018", "Remote System Discovery", "Discovery"}
	tDomainAcctDisc = Technique{"T1087.002", "Account Discovery: Domain Account", "Discovery"}
	tNetShareDisc   = Technique{"T1135", "Network Share Discovery", "Discovery"}
)

// Reusable telemetry hints.
const (
	telWebLogs     = "web server / reverse-proxy access logs"
	telWAF         = "WAF or API-gateway alerts"
	telIDS         = "network IDS/IPS alerts"
	telFlow        = "firewall / NetFlow connection logs"
	telAuthLogs    = "authentication logs (failed and successful logons)"
	telAppLogs     = "application error logs"
	telDNSLogs     = "authoritative DNS query logs"
	telDCLogs      = "domain-controller security event log"
	telEDR         = "host EDR / process-creation telemetry"
	telEgress      = "egress proxy / outbound DNS logs"
	telTLSLogs     = "TLS termination / load-balancer handshake logs"
	telServiceLogs = "service daemon logs"
)

func m(tel []string, ts ...Technique) Mapping { return Mapping{Techniques: ts, Telemetry: tel} }

func off(ts ...Technique) Mapping { return Mapping{Techniques: ts, OffTarget: true} }

var byTool = map[string]Mapping{
	// --- Network discovery ---
	"netsweep": m([]string{telIDS + " (host sweep across a range)", telFlow}, tScanIPBlocks, tRemoteSysDisc),
	"portscan": m([]string{telIDS + " (port-scan signature)", telFlow + " (one source, many ports)"}, tNetSvcDisc, tScanIPBlocks),
	"nmapscan": m([]string{telIDS + " (port-scan / nmap service-probe signature)", telFlow + " (one source, many ports)"}, tNetSvcDisc, tScanIPBlocks),

	// --- Passive / off-target intelligence ---
	"subfinder": off(tOpenTechDBs),
	"exploitdb": off(tObtainExploits),
	"emailsec":  off(tNetDNS),
	"trivyscan": off(tObtainVulns),

	// --- DNS ---
	"dnsenum":     m([]string{telDNSLogs + " (burst of subdomain lookups, many NXDOMAIN)"}, tNetDNS),
	"subtakeover": m([]string{telDNSLogs, telWebLogs}, tHijackDomain, tNetDNS),

	// --- Web fingerprinting & content discovery ---
	"httpprobe":   m([]string{telWebLogs}, tHostSoftware),
	"whatweb":     m([]string{telWebLogs + " (scanner user-agent)"}, tHostSoftware),
	"wafdetect":   m([]string{telWAF + " (deliberately malicious probe request)", telWebLogs}, tNetSecAppl),
	"webcrawl":    m([]string{telWebLogs + " (rapid sequential page fetches from one source)"}, tVictimSites),
	"spacrawl":    m([]string{telWebLogs + " (headless-browser crawl)"}, tVictimSites),
	"jsmine":      m([]string{telWebLogs + " (bulk JavaScript asset fetches)"}, tVictimSites, tCredsInFiles),
	"apidocs":     m([]string{telWebLogs + " (requests for swagger/openapi paths)"}, tVictimSites),
	"webdiscover": m([]string{telWebLogs + " (well-known path probes)"}, tWordlistScan),
	"dirfuzz":     m([]string{telWebLogs + " (burst of 404s from one source)", telWAF}, tWordlistScan),
	"ffuf":        m([]string{telWebLogs + " (burst of 404s from one source)", telWAF}, tWordlistScan),
	"gobuster":    m([]string{telWebLogs + " (burst of 404s from one source)", telWAF}, tWordlistScan),

	// --- Web vulnerability scanning (non-exploiting) ---
	"webcheck":     m([]string{telWebLogs}, tVulnScan),
	"cookieaudit":  m([]string{telWebLogs}, tVulnScan),
	"corscheck":    m([]string{telWebLogs + " (unusual Origin header values)"}, tVulnScan),
	"httpmethods":  m([]string{telWebLogs + " (OPTIONS/TRACE/PUT/DELETE requests)", telWAF}, tVulnScan),
	"hostheader":   m([]string{telWebLogs + " (Host / X-Forwarded-Host mismatch)", telWAF}, tVulnScan),
	"redircheck":   m([]string{telWebLogs + " (external URLs in redirect parameters)"}, tVulnScan),
	"graphqlcheck": m([]string{telWebLogs + " (introspection queries)", telAppLogs}, tVulnScan),
	"tlscheck":     m([]string{telTLSLogs + " (legacy protocol / cipher offers)"}, tVulnScan),
	"testssl":      m([]string{telTLSLogs + " (many handshakes with legacy protocols)", telIDS}, tVulnScan),
	"sshcheck":     m([]string{telServiceLogs + " (sshd: connection closed before auth)"}, tVulnScan),
	"ftpcheck":     m([]string{telServiceLogs + " (ftpd: anonymous login attempt)", telAuthLogs}, tVulnScan),
	"cvematch":     m([]string{telWebLogs}, tVulnScan, tObtainVulns),
	"templatescan": m([]string{telWebLogs + " (requests for sensitive files: .env, .git, backups)", telWAF}, tVulnScan),
	"nucleiscan":   m([]string{telWAF + " (nuclei signatures)", telWebLogs, telIDS}, tVulnScan),
	"nikto":        m([]string{telWAF + " (nikto signatures)", telWebLogs + " (scanner user-agent)", telIDS}, tVulnScan),
	"wpscan":       m([]string{telWebLogs + " (wp-json / plugin enumeration)", telWAF}, tVulnScan),
	"dotgit":       m([]string{telWebLogs + " (requests under /.git/)", telWAF}, tVulnScan, tCredsInFiles),
	"secretscan":   m([]string{telWebLogs}, tCredsInFiles),
	"jwtcheck":     m([]string{telAppLogs + " (token validation failures)", telWebLogs}, tForgeWebCreds),

	// --- Injection & exploitation ---
	"webinject":     m([]string{telWAF + " (SQLi / XSS / traversal signatures)", telAppLogs, telWebLogs}, tExploitPublic),
	"ssti":          m([]string{telWAF + " (template-expression payloads)", telAppLogs, telWebLogs}, tExploitPublic),
	"accesscontrol": m([]string{telWebLogs + " (same object IDs requested across sessions)", telAppLogs + " (authorization failures)"}, tExploitPublic),
	"oobcheck":      m([]string{telEgress + " (server-initiated callback to an unknown host)", telWAF, telWebLogs}, tExploitPublic),
	"sqliexploit":   m([]string{telWAF + " (SQLi signatures)", "database error / audit logs", telAppLogs}, tExploitPublic),
	"sqlmap":        m([]string{telWAF + " (sqlmap signatures)", "database error / audit logs", telWebLogs + " (scanner user-agent)"}, tExploitPublic),
	"cmdexec":       m([]string{telEDR + " (web server spawning a shell)", telWAF + " (command-injection signatures)", telAppLogs}, tExploitPublic, tCmdInterp),
	"metasploit":    m([]string{telIDS + " (exploit signatures)", telEDR, telAppLogs}, tExploitPublic),

	// --- Identity ---
	"login":        m([]string{telAuthLogs + " (successful logon from the test source)"}, tValidAccounts),
	"defaultcreds": m([]string{telAuthLogs + " (failed logons with vendor-default usernames)", telWAF}, tDefaultAccts, tPwGuessing),
	"hydra":        m([]string{telAuthLogs + " (burst of failed logons)", "account-lockout events", telIDS}, tPwGuessing),
	"smbenum":      m([]string{telDCLogs + " (anonymous / null-session logon, share enumeration)", telIDS}, tNetShareDisc, tDomainAcctDisc),
	"ldapenum":     m([]string{telDCLogs + " (high-volume LDAP queries from one account)", "LDAP query auditing"}, tDomainAcctDisc),
	"kerberoast":   m([]string{telDCLogs + " (Event 4769: service tickets requested with RC4 for many SPNs)"}, tKerberoast),
}

// ForTool returns the ATT&CK mapping for a tool. ok is false for tools with no
// fixed mapping — notably the free-form `kali` and `shell` tools, whose technique
// depends entirely on the command run.
func ForTool(tool string) (Mapping, bool) {
	mp, ok := byTool[tool]
	return mp, ok
}

// Unmapped lists the tools that intentionally have no fixed mapping, so a
// coverage test can tell "deliberately unmapped" from "forgotten".
func Unmapped() []string { return []string{"kali", "shell"} }

// Tools returns every mapped tool name, sorted.
func Tools() []string {
	out := make([]string, 0, len(byTool))
	for name := range byTool {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ExpectsReaction reports whether a tool's activity is the kind a preventive
// control (WAF, IPS, rate limiter, account lockout) would reasonably be expected
// to react to: exploitation, credential attacks, and high-volume scanning.
// Quiet single-request checks (header audits, TLS inspection) are excluded, so
// "ran and drew no reaction" is only reported where a reaction was plausible.
func ExpectsReaction(tool string) bool {
	mp, ok := byTool[tool]
	if !ok || mp.OffTarget {
		return false
	}
	for _, t := range mp.Techniques {
		switch t.ID {
		case tExploitPublic.ID, tCmdInterp.ID, tDefaultAccts.ID, tPwGuessing.ID, tKerberoast.ID,
			tWordlistScan.ID, tNetSvcDisc.ID, tScanIPBlocks.ID:
			return true
		}
	}
	return loudScanners[tool]
}

// loudScanners are vulnerability scanners that send large volumes of
// signature-matching requests even though they map to plain T1595.002.
var loudScanners = map[string]bool{"nucleiscan": true, "nikto": true, "wpscan": true, "templatescan": true}
