# Tyto — Roadmap

Research-backed plan. ✅ done · 🚧 in progress · ⬜ planned.

> **Project renamed `strix` → `tyto`** (June 2026). "Strix" collided with an
> existing Apache-2.0 AI-pentest tool (`usestrix/strix`, same category + audience).
> `tyto` keeps the owl lineage (genus of the barn owl — a silent, precise nocturnal
> hunter; fitting for an offline/air-gapped tool) with no known collision.
>
> This roadmap is grounded in a 16-facet research sweep (June 2026). The raw,
> per-facet findings (with sources) live in [`.research/`](../.research/) and are
> digested in [RESEARCH-SYNTHESIS.md](RESEARCH-SYNTHESIS.md). Where a phase names a
> specific library/model, the rationale and license analysis are in that digest.

## Guiding constraints (weigh every choice against these)
1. **Fully local / offline** — runs air-gapped on the operator's own machine.
2. **Free** — no paid services or subscriptions.
3. **No API keys** — no cloud LLM or paid SaaS in the core path.
4. **Single static Go binary** preferred (`CGO_ENABLED=0`). May shell out to or
   embed OSS tools, but the *core* must build and run pure-Go on Windows.
5. **License hygiene** — embed only MIT/Apache/BSD/MPL code. GPL/AGPL/NPSL tools
   (nmap, ZAP, sqlmap, Metasploit, SSLyze…) are *shelled out as separate
   processes*, never linked into the binary.
6. The **deterministic Scope Guard stays the sole, model-unbypassable gate.**
   Everything the AI proposes is pruned/validated by deterministic Go before it runs.

## The vision & wedge
**Tyto is a powerful, complete, all-in-one offensive-security platform** — recon,
scanning, fingerprinting, vuln detection, web testing, exploitation, and
client-ready reporting, all driven by a local-model brain in **one static binary**.
The ambition is to match the capability surface of the big dogs
(Nmap + Nessus + Burp + ProjectDiscovery + Metasploit), not a subset.

No competitor ships **a single static Go binary, fully offline, no API key, with a
hard-coded model-unbypassable Scope Guard + tamper-evident audit.** The cloud
leaders (XBOW, Burp AI) are closed/online/expensive; the OSS field (CAI, PentAGI,
PentestGPT, usestrix/strix) is Python/Docker, cloud-LLM-first, and treats scope as
soft prompt text or Docker sandboxing.

**The Scope Guard + audit are what make that power usable, not a cap on it.** They
are the moat: they turn a dangerous all-in-one offensive engine into something an
operator can legally, defensibly, and repeatedly run — the thing the cloud leaders
structurally cannot offer (air-gap, no data egress, provable boundaries). Autonomy
is a **configurable spectrum**: full autonomy *within scope* when the engagement
authorizes it, human-in-the-loop gating for the highest-risk actions by default.
Reality check, not a limit on ambition: local models reason worse than frontier
cloud models, so tyto reaches "powerful" by **leaning hard on deterministic
scaffolding** — the methodology task tree, grammar-constrained output, a curated
CVE/TTP knowledge base, and tight tool orchestration — rather than hoping the model
free-solves a kill chain.

---

## Phase 0 — Foundation (scaffold) — ✅ DONE
- ✅ Repo, license, CI, lint, build
- ✅ Engagement / scope / rules-of-engagement model
- ✅ Scope Guard with unit tests (the safety core)
- ✅ Tool plugin interface + registry
- ✅ LLM interface + Ollama client + mock
- ✅ Engine loop skeleton with `--dry-run`
- ✅ State store + findings model
- ✅ Audit log
- ✅ CLI surface (`engagement validate`, `run`, `tools`, `version`)

---

## Phase 1 — Make the brain reliable & the guard *real* — ⬜
*Highest leverage, lowest effort. Do this before adding any new tools — it is the
difference between "hope the model behaves" and "the model cannot misbehave."*

- ⬜ **Schema-constrained decoding.** Upgrade `internal/planner/llm/ollama.go` from
  `Format:"json"` (a hint) to passing the action **JSON Schema** in Ollama's
  `format` field → compiled to a GBNF grammar → invalid JSON is impossible at the
  token level. Keep the lenient parser only as a fallback.
- ⬜ **Validate → repair → retry loop** between planner output and the guard:
  `santhosh-tekuri/jsonschema` to validate, `invopop/jsonschema` (or
  `google/jsonschema-go`) to generate the schema from Go structs, 1–2 repair
  retries, then **fail closed** (audited error, never execute a half-parsed action).
- ⬜ **Default model → Qwen3** (Apache-2.0). Replace the `llama3.1` default; add
  hardware detection that auto-selects a tier: `≤8GB → qwen3:8b`, `16GB →
  qwen3:14b`, `24GB+ → qwen3:30b-a3b / qwen3:32b`, CPU-only → `qwen3:4b` + heavy
  scaffolding. **Do not default to Llama** (license trap for an offensive product).
- ⬜ **Close the re-plan loop.** Feed tool results back into `planner.Plan()` each
  cycle; add **no-progress / duplicate-action detection** on top of `MaxCycles` so
  a local model can't loop forever.
- ⬜ **Enforce the RoE knobs that already exist.** Wire `MaxRPS` (`x/time/rate`,
  per-target) and `MaxConcurrent` (`x/sync/semaphore`) into the engine. Shipping
  config that does nothing is worse than omitting it.
- ⬜ **Tamper-evident audit log.** Hash-chain entries (`prevHash`,
  `entryHash=SHA256(...)`), print/anchor the head hash, and **stop swallowing write
  errors** — a failed audit write must fail-closed.
- ⬜ **CLI → cobra.** Replace the `os.Args` switch with `spf13/cobra` subcommands
  (sets up completion, global flags, and incremental growth).
- ✅ **Name resolved → `tyto`.** Renamed from `strix` (collided with `usestrix/strix`,
  Apache-2.0, Aug 2025, same category + audience). Module is now
  `github.com/dukotah/tyto`; binary is `tyto`.

## Phase 2 — Real recon/scan + a methodology-driven planner — ⬜
- ⬜ **Embed the scan layer (pure-Go):** harden the native TCP-connect scanner
  (worker pool, port ranges, banner grab), then embed `naabu` (CONNECT mode,
  `CGO_ENABLED=0`) and `praetorian-inc/fingerprintx` for service identification.
- ⬜ **Embed the recon pipeline (ProjectDiscovery, all MIT Go libs):**
  `subfinder → dnsx → httpx → katana` (standard/non-headless crawl). Tag passive
  OSINT vs active so the guard governs outbound-OSINT vs air-gapped profiles.
- ⬜ **Methodology brain — the differentiator.** Implement an **external Pentesting
  Task Tree** the deterministic engine owns: a PTES phase backbone + an
  ATT&CK-derived (~30-node) technique catalog + OWASP WSTG for web, shipped as
  `go:embed` JSON. Each cycle the guard prunes the technique frontier *before* the
  model sees it; the model only **selects + parameterizes** one node. (Proven to
  lift an 8B local model 13.5% → 71.8% subtask completion.)
- ⬜ **Persist state to SQLite** (`ncruces/go-sqlite3`, no-CGO WASM) — one
  `engagement.db` per job; resumable engagements.
- ⬜ **Quarantine untrusted tool output** (dual-LLM / CaMeL pattern): raw banners /
  HTTP bodies never enter the planner prompt; a quarantined extraction step emits
  typed findings the planner reasons over. (Prompt-injection defense.)

## Phase 3 — Vuln detection + client-ready reporting — ⬜
*This is where tyto starts to compete with Nessus/Burp on detection breadth.*
- ⬜ **Embed Nuclei v3** (`nuclei/v3/lib`) with a **vendored nuclei-templates**
  snapshot and `DisableUpdateCheck()` — 10k+ checks, fully offline.
- ⬜ **Dependency / version CVEs:** Trivy or OSV-Scanner (offline DB) + the **FKIE
  `nvd-json-data-feeds`** mirror for CPE→CVE matching (legacy NVD feeds are dead).
- ⬜ **`tyto feeds` command** — one operator-run bundler (templates + trivy-db +
  OSV `all.zip` + FKIE NVD) so air-gapped boxes never go silently stale.
- ⬜ **Reporting:** SARIF 2.1.0 export (`owenrumney/go-sarif`) + **dual CVSS v3.1 &
  v4.0** scoring (`pandatix/go-cvss`) + a **Typst** PDF report (embedded WASM via
  `typst-go-wasm`, or the Typst CLI). Optional DefectDojo push.
- ⬜ **Semantic recall:** `sqlite-vec` + `nomic-embed-text` (via the existing Ollama
  daemon) so the planner retrieves top-K relevant findings instead of dumping all
  state into every prompt.
- ⬜ **Validate-before-report:** confirm exploitability with a real check before a
  finding is reported (the design choice that gave XBOW its credibility).

## Phase 4 — Web depth + OS-level "hardened mode" — ⬜
- ⬜ **Web active scanning:** OWASP ZAP as a managed **sidecar daemon**
  (`zap-api-go`); shell-out adapters for `ffuf`, `sqlmap` (detect-only by default),
  `arjun`. **Per-mode** risk gating (nuclei passive vs intrusive; ZAP passive vs
  active; sqlmap detect vs exploit) — destructive modes default-deny.
- ⬜ **Two-layer scope enforcement (Linux hardened mode):** a **default-deny egress
  proxy** keyed to the engagement scope (`iron-proxy`, or a native SNI/DNS allowlist
  for single-binary purity) + **bubblewrap** sandbox per shelled-out tool, with
  `gVisor` for high-risk tools. Until OS-level egress exists, do **not** market
  "cannot go out of scope." Degrade gracefully + warn loudly on Windows.
- ⬜ **Kill-switch** wired through `ctx` (SIGINT + watched abort-file + per-engagement
  deadline) that cancels in-flight rate-limiter waits, semaphores, and child
  processes — not just scheduling.
- ⬜ **TUI console** (Bubble Tea v2) as a *passive* live view of the
  plan→guard→execute loop; the engine/guard stay headless.

## Phase 5 — Exploitation (opt-in, hard-gated) + product polish — ⬜
*Highest risk, built last, default OFF. The AI may PROPOSE; a deterministic gate +
human sign-off APPROVES. Break the "lethal trifecta" (untrusted input + exploit
capability + egress).*
- ⬜ **Offline exploit lookup:** `searchsploit` / Exploit-DB (low-risk, reference
  only — surface to operator, never auto-run).
- ⬜ **Exploitation backends, gated:** Metasploit via `msfrpcd` RPC; Sliver C2 via
  gRPC-over-mTLS. Require an authorization artifact in the engagement record + an
  explicit high-risk RoE flag + interactive human approval + sandboxed execution.
- ⬜ **Plugin SDK:** `hashicorp/go-plugin` (gRPC) for third-party tool adapters —
  process-isolated so a plugin can't crash tyto or bypass the in-process guard.
- ⬜ **Release engineering:** GoReleaser signed, reproducible `CGO_ENABLED=0` builds
  for all OS/arch; `koanf` config; `slog` (separate from the audit log); optional
  `gocron` scheduler for a long-running daemon (every tick re-passes the guard).

---

## Non-goals
- A botnet, worm, or anything self-propagating.
- Anything that runs without an acknowledged, in-scope engagement.
- Detection-evasion whose only purpose is to defeat defenders on systems you
  weren't authorized to touch.
- Embedding GPL/AGPL/NPSL code into the binary (shell-out only).
- Over-promising full-autonomy parity with cloud tools — the local-model reasoning
  gap is real; tyto wins on trust, scope enforcement, and offline operation.
