package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/sysinfo"
	"github.com/dukotah/tyto/pkg/version"
)

// doctor is tyto's onboarding diagnostic. A new operator runs `tyto doctor` and
// gets a plain-language account of what works right now, what's optional, and the
// exact command to fix each gap. It is strictly READ-ONLY: it probes PATH, pings
// the local Ollama daemon, and stats ~/.tyto — it never installs, pulls, writes,
// or touches a target. The scope guard and audit path are untouched; doctor knows
// nothing about engagements.

type checkStatus int

const (
	statusOK checkStatus = iota
	statusInfo
	statusWarn
	statusMissing
)

func (s checkStatus) label() string {
	switch s {
	case statusOK:
		return "ok  "
	case statusInfo:
		return "info"
	case statusWarn:
		return "warn"
	default:
		return "----"
	}
}

func (s checkStatus) glyph() string {
	switch s {
	case statusOK:
		return "[+]"
	case statusInfo:
		return "[i]"
	case statusWarn:
		return "[!]"
	default:
		return "[ ]"
	}
}

type check struct {
	name   string
	detail string
	fix    string // optional copy-paste remediation
	status checkStatus
}

type section struct {
	title  string
	checks []check
}

// doctorEnv is the set of host facts doctor evaluates. It is populated by gather()
// from the real environment, or by a test with fixed values, so evaluate() stays a
// pure function of its input.
type doctorEnv struct {
	version      string
	homeTytoPath string
	homeExists   bool

	ollamaBin    string          // path to the ollama binary, or "" if not on PATH
	ollamaURL    string          // base URL probed
	ollamaUp     bool            // daemon answered /api/tags
	pulledModels map[string]bool // model names reported by the daemon
	ramBytes     uint64          // detected physical RAM
	ramOK        bool            // RAM detection succeeded
	recommended  llm.ModelChoice // model doctor recommends for this box

	cveIndex bool // ~/.tyto/feeds/cve-index.db present
	nvdDir   bool // ~/.tyto/feeds/nvd present with feeds

	arsenal map[string]string // external tool name -> resolved path ("" = absent)
	wsl     bool              // a WSL distro is available (Windows Kali backend)
}

// arsenalItem describes one optional external tool and what it unlocks. The order
// here is the order doctor prints them in.
type arsenalItem struct {
	// probe is the list of acceptable binary names; the first found satisfies it.
	probe   []string
	unlocks string
}

var arsenalCatalog = []struct {
	key  string
	item arsenalItem
}{
	{"nmap", arsenalItem{[]string{"nmap"}, "deeper port/service scan (builtin portscan works without it)"}},
	{"nuclei", arsenalItem{[]string{"nuclei"}, "full Nuclei engine + community templates (builtin templatescan works without it)"}},
	{"searchsploit", arsenalItem{[]string{"searchsploit"}, "Exploit-DB lookup (exploitdb tool)"}},
	{"sqlmap", arsenalItem{[]string{"sqlmap"}, "advanced SQLi (builtin sqliexploit covers error/UNION)"}},
	{"ffuf/gobuster", arsenalItem{[]string{"ffuf", "gobuster"}, "content/dir fuzzing (builtin dirfuzz works without it)"}},
	{"subfinder", arsenalItem{[]string{"subfinder"}, "passive subdomain enumeration"}},
	{"netexec", arsenalItem{[]string{"nxc", "netexec", "crackmapexec"}, "AD/identity tier (smbenum, ldapenum, kerberoast)"}},
	{"hydra", arsenalItem{[]string{"hydra"}, "online credential attacks (approval-gated)"}},
}

func newDoctorCmd() *cobra.Command {
	var ollamaURL string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check your environment and report exactly what's ready and what to fix",
		Long: "doctor inspects your machine and reports, in plain language, what tyto\n" +
			"can do right now and what each optional piece unlocks. It is read-only:\n" +
			"it installs nothing, pulls nothing, and never touches a target.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			env := gather(cmd.Context(), ollamaURL)
			renderDoctor(cmd.OutOrStdout(), evaluate(env))
			return nil
		},
	}
	cmd.Flags().StringVar(&ollamaURL, "ollama-url", "http://localhost:11434", "ollama base URL to probe")
	return cmd
}

// gather probes the real environment. Every probe is best-effort and non-fatal: a
// failure becomes a WARN/MISSING check, never an error.
func gather(ctx context.Context, ollamaURL string) doctorEnv {
	env := doctorEnv{
		version:      "tyto " + version.Version,
		homeTytoPath: homeTyto(),
		ollamaURL:    ollamaURL,
		pulledModels: map[string]bool{},
		arsenal:      map[string]string{},
	}

	if fi, err := os.Stat(env.homeTytoPath); err == nil && fi.IsDir() {
		env.homeExists = true
	}

	env.ollamaBin, _ = exec.LookPath("ollama")
	env.ollamaUp, env.pulledModels = probeOllama(ctx, ollamaURL)

	ram, derr := sysinfo.TotalRAMBytes()
	env.ramBytes, env.ramOK = ram, derr == nil
	env.recommended = llm.DefaultModel(ram, derr == nil)

	if fi, err := os.Stat(filepath.Join(env.homeTytoPath, "feeds", "cve-index.db")); err == nil && !fi.IsDir() {
		env.cveIndex = true
	}
	if entries, err := os.ReadDir(filepath.Join(env.homeTytoPath, "feeds", "nvd")); err == nil && len(entries) > 0 {
		env.nvdDir = true
	}

	for _, a := range arsenalCatalog {
		for _, bin := range a.item.probe {
			if p, err := exec.LookPath(bin); err == nil && p != "" {
				env.arsenal[a.key] = p
				break
			}
		}
	}

	env.wsl = probeWSL(ctx)
	return env
}

// probeOllama returns whether the daemon answered and the set of model names it
// reports as locally available.
func probeOllama(ctx context.Context, baseURL string) (bool, map[string]bool) {
	models := map[string]bool{}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/api/tags", nil)
	if err != nil {
		return false, models
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, models
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, models
	}
	var body struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return true, models // daemon is up, we just couldn't parse the list
	}
	for _, m := range body.Models {
		models[m.Name] = true
	}
	return true, models
}

// probeWSL reports whether at least one WSL distro is registered (the Windows path
// to a Kali execution backend). Non-Windows hosts simply won't have `wsl`.
func probeWSL(ctx context.Context) bool {
	if _, err := exec.LookPath("wsl"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "wsl", "-l", "-q").Output()
	if err != nil {
		return false
	}
	// WSL emits UTF-16; strip NULs so a distro name is detectable either way.
	return strings.TrimSpace(strings.ReplaceAll(string(out), "\x00", "")) != ""
}

// modelPulled reports whether a model matching want is already available. Match is
// tolerant of the implicit ":latest" tag Ollama applies.
func modelPulled(pulled map[string]bool, want string) bool {
	if pulled[want] {
		return true
	}
	base := want
	if i := strings.IndexByte(want, ':'); i >= 0 {
		base = want[:i]
	}
	for name := range pulled {
		if name == want || name == base+":latest" || name == base {
			return true
		}
	}
	return false
}

// evaluate turns host facts into the report. Pure: no I/O, no globals touched.
func evaluate(env doctorEnv) []section {
	var secs []section

	// --- core ---
	core := section{title: "Core"}
	core.checks = append(core.checks, check{
		name: "tyto binary", detail: env.version, status: statusOK,
	})
	if env.homeExists {
		core.checks = append(core.checks, check{
			name: "data dir", detail: env.homeTytoPath + " present", status: statusOK,
		})
	} else {
		core.checks = append(core.checks, check{
			name: "data dir", detail: env.homeTytoPath + " not created yet (optional; only offline feeds live here)",
			status: statusInfo,
		})
	}
	core.checks = append(core.checks, check{
		name: "detection templates", detail: "embedded pure-Go pack available (no download required)", status: statusOK,
	})
	secs = append(secs, core)

	// --- planner ---
	planner := section{title: "AI planner (local)"}
	switch {
	case env.ollamaBin == "":
		planner.checks = append(planner.checks, check{
			name: "ollama", detail: "not found on PATH", status: statusMissing,
			fix: "install from https://ollama.com — or skip it (see below)",
		})
	default:
		planner.checks = append(planner.checks, check{
			name: "ollama", detail: env.ollamaBin, status: statusOK,
		})
	}

	ramLine := "RAM detection unavailable on this platform"
	if env.ramOK {
		ramLine = fmt.Sprintf("%.1f GB detected", float64(env.ramBytes)/(1<<30))
	}
	planner.checks = append(planner.checks, check{name: "host RAM", detail: ramLine, status: statusInfo})

	switch {
	case !env.ollamaUp:
		planner.checks = append(planner.checks, check{
			name: "ollama daemon", detail: "not reachable at " + env.ollamaURL, status: statusMissing,
			fix: "start it with: ollama serve",
		})
		planner.checks = append(planner.checks, check{
			name: "recommended model", detail: env.recommended.String(), status: statusInfo,
			fix: "once ollama is running: ollama pull " + env.recommended.Model,
		})
	case modelPulled(env.pulledModels, env.recommended.Model):
		planner.checks = append(planner.checks, check{
			name: "ollama daemon", detail: "reachable at " + env.ollamaURL, status: statusOK,
		})
		planner.checks = append(planner.checks, check{
			name: "recommended model", detail: env.recommended.Model + " pulled", status: statusOK,
		})
	default:
		planner.checks = append(planner.checks, check{
			name: "ollama daemon", detail: "reachable at " + env.ollamaURL, status: statusOK,
		})
		st := statusMissing
		detail := env.recommended.String() + " — not pulled"
		if len(env.pulledModels) > 0 {
			// Some other model is present; the planner can still run, just not the
			// size doctor would pick for this box.
			st = statusWarn
			detail = env.recommended.String() + " not pulled; " + fmt.Sprintf("%d other model(s) available", len(env.pulledModels))
		}
		planner.checks = append(planner.checks, check{
			name: "recommended model", detail: detail, status: st,
			fix: "ollama pull " + env.recommended.Model,
		})
	}
	secs = append(secs, planner)

	// --- offline enrichment ---
	data := section{title: "Offline data (optional — enriches findings)"}
	if env.cveIndex {
		data.checks = append(data.checks, check{name: "CVE index", detail: "built — cvematch is instant", status: statusOK})
	} else if env.nvdDir {
		data.checks = append(data.checks, check{
			name: "CVE index", detail: "NVD feeds present but not indexed", status: statusWarn,
			fix: "tyto feeds index",
		})
	} else {
		data.checks = append(data.checks, check{
			name: "CVE index", detail: "no local NVD feeds (cvematch falls back to version heuristics)", status: statusInfo,
			fix: "place NVD JSON feeds in " + filepath.Join(env.homeTytoPath, "feeds", "nvd") + ", then: tyto feeds index",
		})
	}
	secs = append(secs, data)

	// --- optional arsenal ---
	ars := section{title: "Optional external arsenal (shelled out, never bundled)"}
	for _, a := range arsenalCatalog {
		if p := env.arsenal[a.key]; p != "" {
			ars.checks = append(ars.checks, check{name: a.key, detail: p, status: statusOK})
		} else {
			ars.checks = append(ars.checks, check{name: a.key, detail: a.item.unlocks, status: statusInfo})
		}
	}
	if env.wsl {
		ars.checks = append(ars.checks, check{name: "wsl (kali backend)", detail: "WSL distro available", status: statusOK})
	}
	secs = append(secs, ars)

	return secs
}

func renderDoctor(w io.Writer, secs []section) {
	fmt.Fprintln(w, "tyto doctor — environment check")
	fmt.Fprintln(w, strings.Repeat("=", 48))

	var localAIReady, ollamaUp bool
	for _, s := range secs {
		fmt.Fprintf(w, "\n%s\n", s.title)
		for _, c := range s.checks {
			fmt.Fprintf(w, "  %s %-22s %s\n", c.status.glyph(), c.name, c.detail)
			if c.fix != "" && c.status != statusOK {
				fmt.Fprintf(w, "      ↳ %s\n", c.fix)
			}
			if s.title == "AI planner (local)" {
				if c.name == "ollama daemon" && c.status == statusOK {
					ollamaUp = true
				}
				if c.name == "recommended model" && c.status == statusOK {
					localAIReady = true
				}
			}
		}
	}

	fmt.Fprintf(w, "\n%s\n", strings.Repeat("-", 48))
	fmt.Fprintln(w, "What you can do right now:")
	fmt.Fprintln(w, "  • Dry-run (no model, no actions, nothing to install):")
	fmt.Fprintln(w, "      tyto run --engagement configs/engagement.example.yaml --dry-run")
	fmt.Fprintln(w, "  • Full scripted demo against your own machine (no model):")
	fmt.Fprintln(w, "      tyto run --engagement configs/localhost.engagement.yaml --planner scripted \\")
	fmt.Fprintln(w, "          --report-format md --report-out report.md")
	if localAIReady && ollamaUp {
		fmt.Fprintln(w, "  • Autonomous local-AI engagement (planner ready):")
		fmt.Fprintln(w, "      tyto run --engagement configs/localhost.engagement.yaml")
	} else {
		fmt.Fprintln(w, "  • No Ollama? Drive tyto with a frontier model over MCP instead:")
		fmt.Fprintln(w, "      tyto mcp --engagement configs/localhost.engagement.yaml")
	}
	fmt.Fprintln(w, "\nEverything optional above is exactly that — the core ship line runs without it.")
}

// arsenalKeys is exported for tests to assert the catalog stays in sync.
func arsenalKeys() []string {
	keys := make([]string, 0, len(arsenalCatalog))
	for _, a := range arsenalCatalog {
		keys = append(keys, a.key)
	}
	sort.Strings(keys)
	return keys
}
