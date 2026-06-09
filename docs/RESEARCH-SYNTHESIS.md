# Research Synthesis

Digest of a 16-facet research sweep (June 2026) that grounds
[ROADMAP.md](ROADMAP.md). Each facet was researched with live web search against
the project's hard constraints (fully local · free · no API key · single static Go
binary · deterministic Scope Guard). Raw findings + full source lists per facet are
in [`.research/`](../.research/) (one JSON file per facet).

All 16 facets completed. One agent (the Go-platform facet) hit a tool-parser bug
that mangled the *formatting* of its output but lost **no content**; its findings
are intact in `.research/aa8fe56cd07352e90.json`.

---

## Recommended stack at a glance

Every pick below is fully local, free, no-API-key, and license-safe for the stated
integration boundary.

| Layer | Recommended pick | License | Integration | Facet |
|---|---|---|---|---|
| LLM runtime | **Ollama** (default), llama.cpp server as air-gap escape hatch | MIT | embed Go client; code to OpenAI-compat `/v1` so it's swappable | local-runtimes |
| Model (brain) | **Qwen3-14B Q4_K_M** default; 8B floor; 4B for stripped laptop; 30B-A3B/32B for 24GB+ | Apache-2.0 | model string via Ollama | local-models, hardware-cost |
| Structured output | Ollama `format`=JSON-Schema → GBNF; **validate-repair-retry** in Go | MIT/Apache/BSD | `santhosh-tekuri/jsonschema` + `invopop/jsonschema` | tool-calling-go |
| Agent loop | **Plan-and-execute** + bounded re-plan; compaction; **dual-LLM quarantine**; conditional critic | — | extend `internal/engine` | agent-arch |
| Methodology | **External Pentesting Task Tree** (ATT&CK ~30 nodes) + PTES phases + WSTG, `go:embed` | CC/MIT data | new `internal/methodology` | methodology |
| Port scan | native connect scanner + **naabu** (CONNECT) + **fingerprintx** | MIT/Apache | embed Go libs | scanning-tools |
| Recon | **ProjectDiscovery**: subfinder→dnsx→httpx→katana | MIT | embed Go libs | recon-tools |
| Vuln detect | **Nuclei v3** + vendored templates; Trivy/OSV; **FKIE NVD feed** | MIT/Apache | embed nuclei lib; shell Trivy | vuln-scanning |
| Web testing | nuclei + katana (embedded); **ZAP** sidecar; ffuf/sqlmap/arjun shell-out | MIT/Apache + GPL(shell) | per-mode risk gating | web-testing |
| Memory / RAG | **SQLite** (`ncruces`, no-CGO) + **sqlite-vec** + **nomic-embed-text** | PD/MIT/Apache | embed; one `.db` per engagement | memory-rag |
| Safety hardening | `x/time/rate` + semaphore; **default-deny egress proxy**; **bubblewrap**/gVisor; **hash-chained audit** | BSD/LGPL/Apache | native + detect external | safety-scope |
| Exploitation | **Metasploit** (msfrpcd RPC); **Sliver** (gRPC); searchsploit — all gated, default OFF | BSD/GPLv3(shell) | shell/RPC, never linked | exploitation |
| Platform | **cobra** CLI + **Bubble Tea** TUI; `go-plugin`; koanf; slog; GoReleaser | Apache/MIT/MPL | embed | go-platform |
| Reporting | **SARIF** (`go-sarif`) + **dual CVSS v3.1/v4.0** (`go-cvss`) + **Typst** PDF; DefectDojo push | MIT/Apache/BSD | embed | reporting |

**The recurring technical lever:** grammar-constrained decoding (`format`/GBNF) +
deterministic scaffolding (the task tree + Scope Guard) is what makes a *small local
model* reliable enough to compete. Every facet pointed back to it.

---

## Cross-cutting decisions that need YOUR call

These surfaced in multiple facets as `open_questions`. They shape architecture, so
decide them early.

1. **✅ RESOLVED — the name → `tyto`.** "Strix" collided with a popular Apache-2.0
   AI-pentest tool (`usestrix/strix`, PyPI `strix-agent`, docs.strix.ai, Aug 2025)
   in the same category + audience. Renamed to **tyto** (barn-owl genus — keeps the
   owl lineage, no known collision). Module `github.com/dukotah/tyto`, binary `tyto`.
2. **✅ RESOLVED — positioning → powerful all-in-one platform.** Build the full
   capability surface (recon → scan → vuln → web → exploit → report), not a subset.
   Autonomy is a **configurable spectrum**: full autonomy *within scope* when
   authorized, human-in-the-loop gating for the highest-risk actions by default. The
   honest constraint (local models solve only 0–33% of privesc challenges vs ~75%
   human) is met by **heavy deterministic scaffolding** — the methodology task tree,
   grammar-constrained output, a curated CVE/TTP KB, tight orchestration — *to reach*
   that power, not to cap it. The Scope Guard + audit are the moat that makes an
   all-in-one offensive engine legally and defensibly runnable.
3. **Minimum hardware floor.** Determines the *default* model (8GB→Qwen3-8B,
   16GB→14B, 24GB+→30B-A3B/32B, CPU→4B). Needed to pick "the" default.
4. **Single-binary purity vs. capability.** Pure-Go core works on bare Windows;
   higher-signal tools (nmap, ZAP/JVM, massdns, Chrome-headless, Metasploit) pull
   external deps. Recommended: **pure-Go core, external tools as optional,
   runtime-detected, gracefully-degrading adapters.**
5. **Will tyto ship commercially / closed-source?** If yes, the license boundary is
   a hard rule: embed only MIT/Apache/BSD/MPL; **shell-out** nmap (NPSL), ZAP-adjacent
   GPL tools, sqlmap/Arjun (AGPL), Metasploit, OpenVAS. If purely personal, the
   constraints relax (but bundling nmap data still needs care).
6. **Ship a bundled model, or orchestrate whatever the operator pulls?** Bundling →
   Apache-2.0 (Qwen3/Mistral) is effectively mandatory; operator-supplied → you can
   also support Llama/Hermes/uncensored variants as opt-in.
7. **Primary OS for "hardened mode."** OS-level egress + sandbox (bubblewrap/gVisor/
   nftables) are Linux-only. On Windows the guarantee is weaker — decide whether full
   scope-enforcement is a Linux-only hardened mode.

---

## The honest caveats (don't over-promise)
- **Local-model reasoning gap is real and measured** — compensate with deterministic
  tooling, the task tree, RAG of CVEs/TTPs, and tight orchestration; don't rely on
  raw model reasoning for kill-chains.
- **"Scope Guard" is only a differentiator if it's truly deterministic + unbypassable.**
  Competitors already market "guardrails" (soft LLM/heuristic). Protect the
  hard-coded, non-AI, audited distinction.
- **One layer is theater.** An app-layer guard alone can't guarantee in-scope
  behavior (buggy tool, SSRF redirect, DNS rebinding). Scope must *also* be enforced
  at the OS network boundary before claiming "cannot go out of scope."
- **Stale vuln data is worse than none** — it gives false assurance. The `tyto feeds`
  bundler is load-bearing for the air-gapped story.
- **Validate findings with a real PoC before reporting** — an LLM-imagined vuln
  destroys trust instantly.

---

## Per-facet digest

Format: **facet** — one-line recommendation. (Full detail + sources in the matching
`.research/*.json`.)

1. **local-models** — Qwen3 family (Apache-2.0) as the brain; avoid Llama (license
   AUP trap for offensive use); reasoning models (R1 distills) only as planners, not
   in the tool-calling loop.
2. **local-runtimes** — Ollama default (official Go client, MIT, GBNF structured
   output); code to the OpenAI-compatible interface so the runtime is swappable;
   llama.cpp server for air-gap/power users; never bundle proprietary LM Studio.
3. **hardware-cost** — Qwen3-14B Q4_K_M is the sweet spot; Q4_K_M shows no accuracy
   loss; one planning call is seconds on GPU; grammar-constrained decoding lets you
   drop to smaller models safely.
4. **tool-calling-go** — official Ollama Go client + `Format`=schema for guaranteed
   structure; native tool-calling for selection; mandatory validate-repair-retry;
   avoid langchaingo as the core abstraction.
5. **agent-arch** — plan-and-execute with bounded re-plan beats ReAct/ToT for a small
   local model; compact to structured state; **CaMeL dual-LLM** to neutralize
   prompt-injection from tool output; conditional (not always-on) critic.
6. **methodology** — encode methodology as a machine-readable **external task tree**
   (ATT&CK-derived) the Go engine owns; feed the model only the current frontier;
   guard prunes before the model sees options. The single biggest reasoning uplift.
7. **scanning-tools** — naabu (CONNECT, pure-Go) + fingerprintx; nmap is the gold
   standard but **NPSL-licensed → shell-out only, never bundle**; skip masscan/
   rustscan for typical scope.
8. **recon-tools** — embed the PD suite (subfinder/dnsx/httpx/katana); "offline" ≠
   "air-gapped" for passive OSINT — gate it; CT is already covered by subfinder's
   crtsh source.
9. **vuln-scanning** — embed Nuclei v3 + vendored templates; Trivy/OSV for deps; FKIE
   NVD mirror for offline CPE→CVE; `tyto feeds` bundler for freshness; OpenVAS only
   as an optional heavy "deep scan" adapter.
10. **web-testing** — nuclei + katana embedded; ZAP as the Burp-class sidecar daemon;
    ffuf/sqlmap/arjun shell-out; **per-mode** risk gating; dalfox v3 is Rust now
    (shell-out), jaeles is dead (use nuclei).
11. **exploitation** — build LAST, default OFF, human-approval + sandbox; Metasploit
    (msfrpcd RPC) + Sliver (gRPC) + offline searchsploit; **break the lethal
    trifecta**; never let the model auto-exploit.
12. **safety-scope** — enforce the already-declared MaxRPS/MaxConcurrent; add
    default-deny egress proxy + bubblewrap sandbox (two-layer scope); upgrade the
    audit log to a SHA-256 hash chain that fails closed.
13. **memory-rag** — one SQLite file per engagement (`ncruces`, no-CGO) doing
    relational + graph-via-edges + audit + `sqlite-vec` vectors; embeddings via the
    existing Ollama (`nomic-embed-text`); defer Neo4j/Graphiti.
14. **reporting** — SARIF primary (lossy for dynamic findings → keep a richer native
    JSON as source of truth) + dual CVSS v3.1/v4.0 + Typst PDF (embedded WASM or
    CLI); DefectDojo (BSD) as the integration hub.
15. **competition** — no one ships the offline + single-binary + deterministic-guard
    combo; wedge is trust/compliance/air-gap; renamed to **tyto** (resolved the
    `usestrix/strix` collision); aim for a powerful all-in-one capability surface;
    validate findings with a real PoC before reporting.
16. **go-platform** — cobra CLI + Charm/Bubble Tea TUI (passive view); reject Go
    native `plugin` (no Windows); use `hashicorp/go-plugin` gRPC for third-party
    extensions; koanf config; slog; GoReleaser static builds; gocron/self-update opt-in.
