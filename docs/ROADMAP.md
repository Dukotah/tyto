# Tyto — Roadmap

Research-backed, review-hardened plan. ✅ done · 🚧 in progress · ⬜ planned.

> **Project renamed `strix` → `tyto`** (June 2026). "Strix" collided with an
> existing Apache-2.0 AI-pentest tool (`usestrix/strix`, same category + audience).
> `tyto` keeps the owl lineage (genus of the barn owl — a silent, precise nocturnal
> hunter; fitting for an offline/air-gapped tool) with no known collision.
>
> This roadmap is grounded in a 16-facet research sweep and then **stress-tested by a
> 9-dimension adversarial review** (June 2026): every finding was independently
> verified against live sources and the actual repo. 53 confirmed/partial findings
> are folded in below. Raw findings live in [`.research/`](../.research/); the digest
> is [RESEARCH-SYNTHESIS.md](RESEARCH-SYNTHESIS.md).

## Guiding constraints (weigh every choice against these)
1. **Fully local / offline** — runs air-gapped on the operator's own machine.
   **Air-gapped is the *default* profile** (no outbound OSINT) — opt in to passive
   OSINT explicitly. This also removes the egress leg of the "lethal trifecta" until
   the OS-level egress proxy (Phase 4) ships.
2. **Free** — no paid services or subscriptions.
3. **No API keys to third parties.** (Local secrets like ZAP's own `api.key` or an
   operator-set Ollama URL are fine; nothing phones home or needs a cloud key.)
4. **Single static Go binary** preferred (`CGO_ENABLED=0`) **for the external/web
   core**. External OSS tools MAY be shelled out; the AD/identity and exploitation
   tiers are explicitly *optional, runtime-detected adapters*, not single-binary-pure.
5. **License hygiene** — embed only MIT/Apache/BSD/MPL code. GPL/AGPL/NPSL tools
   (nmap, ZAP, sqlmap, Metasploit, Sliver, hydra, Responder, ligolo-ng…) are
   *shelled out as separate processes*, never linked into the binary.
6. **The deterministic Scope Guard is the sole, model-unbypassable gate** — and it
   gates on **authoritative, deterministic** inputs (tool-registry risk/category +
   param classifier), **never on strings the model supplies**. Unknown tool or
   unknown category ⇒ **deny** (fail closed).

## The vision & wedge
**Tyto's north star is a powerful, complete, all-in-one offensive-security platform**
— recon, scanning, fingerprinting, vuln detection, web testing, internal/AD,
exploitation, and client-ready reporting, driven by a local-model brain in **one
binary** (with optional adapters for the heavy tiers). It aims to match the
capability *surface* (tools/features) of the big dogs (Nmap + Nessus + Burp +
ProjectDiscovery + Metasploit) — **breadth of capability, with multi-step
exploitation operator-gated by default, not full autonomous kill-chaining** (a known
open problem for local models).

No competitor ships **a single static Go binary, fully offline, no API key, with a
hard-coded model-unbypassable Scope Guard + tamper-evident audit.** The cloud
leaders (XBOW, Burp AI) are closed/online/expensive; the OSS field (CAI, PentAGI,
PentestGPT, usestrix/strix) is Python/Docker, cloud-LLM-first, and treats scope as
soft prompt text or Docker sandboxing.

**The Scope Guard + tamper-evident audit are the moat — what makes that power legally
and defensibly runnable, not a cap on it.** Autonomy is a **configurable spectrum**:
full autonomy *within scope* when authorized, human-in-the-loop gating for the
highest-risk actions by default. Honesty discipline (applied throughout): tyto only
*claims* a guarantee once the mechanism that delivers it ships. The local-model
reasoning gap is real, so tyto reaches "powerful" by **leaning hard on deterministic
scaffolding** (the methodology task tree, grammar-constrained output, a curated
CVE/TTP knowledge base, tight orchestration) — measurably effective (the structured
attack-tree work lifted an 8B local model 13.5%→71.8% subtask completion *and* let it
fully solve 4/10 HackTheBox machines vs 0 for the baseline) — not by hoping the model
free-solves a kill chain.

---

## 🚢 v0.1 Ship Line (the smallest credible, useful product) — ✅ MVP REACHED
> **Status (June 2026): the v0.1 MVP runs end to end.** scan (`portscan`) →
> fingerprint (`httpprobe`) → safe web vuln checks (`webcheck`) → validated,
> grouped Markdown/JSON report, every action under the deterministic Scope Guard
> + Ed25519 authorization gate, recorded in the tamper-evident hash-chained
> fail-closed audit log. Proven by an end-to-end test against a live local HTTP
> server (`internal/engine/mvp_test.go`) and runnable offline via
> `configs/localhost.engagement.yaml`. **Substitution vs the cut below:** a
> built-in `webcheck` (safe header/version/listing checks) stands in for embedded
> Nuclei, which — with vendored templates, SARIF, and SQLite-resume — is the v0.2
> increment.

> **v0.2 in progress** (branch `v0.2`): methodology task-tree (`internal/methodology`
> — the planner now selects from an embedded, asset-pruned technique catalog;
> `tyto methodology` lists it), SARIF 2.1.0 export (`--report-format sarif`),
> resumable engagements (`--resume`), CVSS v3.1 scoring (`internal/cvss`, wired
> into the report), and a **15-tool** built-in surface covering recon, hygiene,
> and **active** web-app testing: portscan, httpprobe, webcheck, webdiscover,
> tlscheck, webcrawl, **webinject** (XSS + SQLi error/boolean + path traversal +
> command injection, CVSS-scored), corscheck, redircheck, httpmethods, dnsenum,
> sshcheck, ftpcheck, emailsec, secretscan. Verified live: the crawl→inject chain
> finds real HIGH XSS and SQLi. Many of these tools were built in parallel via
> subagents and integrated centrally. Still ahead for v0.2: embedded Nuclei +
> vendored templates (the CVE-breadth lever), a relational SQLite store, and a
> Typst/maroto PDF report.

**The all-in-one is the north star, NOT the v1 deliverable.** Draw a line and ship the
differentiator first (which is mostly Phase-1 work anyway). **v0.1 =**

> *An offline, scope-enforced, AI-orchestrated **recon → scan → Nuclei → validated
> report** tool with a real deterministic Scope Guard and a tamper-evident,
> hash-chained, fail-closed audit log.*

- **Contents:** all of **Phase 1** + the recon/scan + methodology task-tree of
  **Phase 2** + **Nuclei v3** (vendored templates, offline) + validate-before-report
  + a Markdown/native-JSON report (the existing `internal/report` scaffold; SARIF +
  Typst PDF are a v0.1 stretch / v0.2 — do **not** gate the ship on the PDF pipeline).
- **Explicitly post-1.0:** all web-active tooling (ZAP/ffuf/sqlmap), internal/AD,
  exploitation, credential attacks, pivoting. Build these only if real users validate
  v0.1.
- *(Even-smaller cut if velocity matters: Phase 1 guard + naabu/native scan + Nuclei +
  Markdown report, with the methodology tree + SQLite-resume as the v0.2 increment.)*

---

## Phase 0 — Foundation (scaffold) — ✅ DONE
Engagement/scope/RoE model · Scope Guard (scope/risk/category/time) + tests · tool
registry · LLM interface (Ollama + mock) · engine loop w/ `--dry-run` · state store +
findings · audit log · CLI (`engagement validate`, `run`, `tools`, `version`).

> ⚠️ Phase 0 is a *scaffold*. The guard, audit, and engine have known gaps that
> Phase 1 closes (below). Until then, docs must not describe rate-limits, audit
> tamper-evidence, or authorization enforcement as *implemented*.

## Phase 1 — Make the brain reliable & the guard *real* (the correctness/safety core) — ✅
*Highest leverage, lowest effort, and the bulk of the v0.1 differentiator. This is
where "model-unbypassable guard" becomes true instead of aspirational.*

> **Status (June 2026): all Phase-1 items landed** on branch `phase-1` (14 commits
> since the scaffold; build/vet/test green, 19 test files). Delivered: typed
> taxonomy + authoritative guard gating (Phase 0 close-out), the quarantine
> invariant, typed-asset observe→re-plan loop, deterministic termination contract
> (dedup + no-progress halt + window deadline), tamper-evident hash-chained
> fail-closed audit log, Ed25519 authorization gate enforced in the guard (+
> `tyto authorize` helper), schema-constrained planning with validate→repair→fail
> closed, RAM-tier model auto-detection, RoE rate-limit/concurrency enforcement,
> a hermetic evaluation harness, and a cobra CLI. Two deliberate deviations:
> schema validation is in-package rather than via santhosh-tekuri/invopop (keeps
> the build dependency-free/offline); the live-model (GPU) eval tier is deferred
> behind the hermetic scorer. **Next: the Phase-2 recon/scan + methodology slice
> toward the v0.1 ship line.**

**Taxonomy & guard authority (do first — everything else imports these):**
- ⬜ **Freeze the canonical action taxonomy.** Convert `action.Category` from a free
  string to a **typed, closed Go enum** (mirroring the existing `RiskLevel` enum),
  tyto-native and mapped to **PTES phases** (ATT&CK tactic / kill-chain stage carried
  as *separate* metadata on technique nodes, never as the category vocabulary). This
  enum is the **single source** the JSON Schema, Scope Guard, Phase-2 methodology
  catalog, and Phase-3 report all import. Validate `RoE.Allowed/ForbiddenCategories`
  against it at load time (typo ⇒ fail closed). Add an orthogonal
  **blast-radius axis** (`none | reversible | destructive`) so C2/destructive modules
  gate distinctly from intrusive-but-safe scans.
- ⬜ **🔴 Guard gates on authoritative inputs, never model strings.** At engine
  construction, build a read-only `map[toolName]{Category, MaxRisk}` snapshot from the
  registry and inject it into `guard.New()` (keeps the guard pure — no Execute, no
  AI). In `Evaluate`: resolve the tool **first**, **deny unknown tools/categories**,
  then gate on `effectiveRisk = max(tool.MaxRisk, perParamRisk(params))` and
  `category = tool.Category()`. The model's self-declared `risk`/`category` are
  **advisory only, never trusted upward**; log under-declarations as a
  misbehaving-model signal. The per-param classifier **defaults UP** to the tool
  ceiling on unrecognized params (fail safe). *Regression anchor:* a test asserting a
  model declaring `risk=passive` on a `RiskMedium` tool is **denied** on a
  passive-ceiling engagement. Re-word `tool.go`: MaxRisk/Category are
  **authoritative**, not "advisory."
- ⬜ **🔴 Authorization gate, enforced in the guard** (move from Phase 5). Sign the
  canonicalized engagement (scope + max_risk + client) with **Ed25519** (stdlib
  `crypto/ed25519`, pure-Go); the **client supplies the public key out-of-band**,
  pinned in the engagement and recorded in the audit head. A `guard.RequireAuthorization`
  step **denies any RiskHigh or exploit-category action** unless a verified
  authorization covering that target+tier is present, and binds the signed scope hash
  into the audit chain (post-hoc widening becomes detectable). **Honest framing:** an
  offline single-user tool cannot make the gate *un-toggleable* by the machine owner;
  the real, marketable guarantee is **tamper-evident, scope-bound, attributable, and
  not silently self-modifiable** — not "impossible to toggle."
- ⬜ **Three-state guard verdict + approval record** (reserve the type now; UX later).
  `type Verdict int { Deny; Allow; RequireApproval }`; `engine.handle()` becomes a
  3-way switch where unknown/default **fails closed to Deny**. Define the per-action
  **Approval** audit entry (approver, timestamp, action ID, guard reason, y/N) and
  hash-chain it. Note `Authorization.AuthorizedBy` (engagement-level) ≠ per-action
  approver. Don't build the interactive prompt UX yet (Phase 4/5).

**Reliable structured planning:**
- ⬜ **Schema-constrained decoding.** Upgrade `internal/planner/llm/ollama.go` from
  `Format:"json"` (a hint) to passing the action **JSON Schema** in Ollama's `format`
  field → GBNF grammar → invalid JSON impossible at the token level. The schema
  enumerates the legal `Category` enum values.
- ⬜ **Validate → repair → retry**, then **fail closed**: `santhosh-tekuri/jsonschema`
  to validate, `invopop/jsonschema` (or `google/jsonschema-go`) to generate the schema
  from Go structs, 1–2 repair retries, audited error on exhaustion (never execute a
  half-parsed action). **Category parse failure fails closed** (unlike risk, do *not*
  silently default to passive).
- ⬜ **Default model → Qwen3** (Apache-2.0). Replace `llama3.1` in **both** places
  (`ollama.go` default + the `--model` flag default). **Headline default:
  `qwen3:14b` (16GB tier)** with auto-detection: `≤8GB → qwen3:8b`, `16GB →
  qwen3:14b`, `24GB+ → qwen3:30b-a3b/32b`. CPU-only `qwen3:4b` is offered but flagged
  **degraded** (heavy scaffolding required; GPU/Apple-Silicon strongly recommended).
  **Never default to Llama** (license/AUP trap for offensive use).

**Close the loop & bound it:**
- ⬜ **Close the observe→re-plan loop with *typed assets*.** Tool `Result` carries
  **Assets** (host/service/url + attrs) alongside Findings; `engine.handle` writes
  both (`state.AddAsset` next to `AddFinding`); portscan emits a host asset + a service
  asset per open port. The **task-tree frontier computes in Go from `State.Assets()`**
  (deterministic, guard-side), *not* by the model parsing asset lines out of the
  prompt. *Integration test:* a 2-hop chain — portscan discovers a service → next
  `Plan()` selects a service-specific technique for it.
- ⬜ **Termination contract** (deterministic, in the engine): canonical
  **action key** = `SHA256(tool ∥ normalized-target ∥ canonical-sorted-params)`;
  duplicate key ⇒ skip + audit `duplicate_action_skipped`. **Progress** = ≥1 new
  asset/finding or ≥1 novel completed action; after `NoProgressCycleLimit` (default 3)
  ⇒ halt + audit. Pull the **per-engagement deadline** (`context.WithDeadline` from
  RoE `TimeWindows`) forward from Phase 4. Flip `cycles>1` default **only after** the
  contract lands. Tests for each.
- ⬜ **Quarantine invariant (load-bearing trifecta defense — precondition for any
  untrusted-input tool).** Enforce that `state.Summary()` only ever emits **typed,
  validated fields** and **never** raw tool output / `Finding.Evidence` verbatim into
  the planner prompt. Land this *before/with* the first tool that ingests
  attacker-controllable bodies (Phase 2 httpx/katana/nuclei). The full CaMeL dual-LLM
  extraction can follow; the **invariant + test** is what must precede the capability.

**Accountability & enforcement:**
- ⬜ **Enforce the RoE knobs that already exist:** `MaxRPS` (`x/time/rate`, per-target)
  + `MaxConcurrent` (`x/sync/semaphore`), wired through the cancellable `ctx`.
- ⬜ **Tamper-evident audit log:** hash-chain (`prevHash`, `SHA256(...)`), print/anchor
  the head, **stop swallowing write errors** (fail closed). Redact secrets
  (store handle + hash/last-4, never plaintext) — a hard requirement once credentials
  exist (Phase 2).
- ⬜ **Fix URL scope matching:** replace naive `HasPrefix` (prefix-confusion lets
  `app.evil.com` match an in-scope `app.example.com` prefix) with proper
  scheme/host/path-segment matching.

**Plumbing & proof:**
- ⬜ **CLI → cobra** (subcommands, completion, global flags).
- ⬜ **Evaluation harness (starts here, runs forever).** *In hermetic CI* (mock LLM,
  no GPU): golden-file regression tests on planner output + a schema-validity/in-scope
  scorer. *Local/nightly `make eval`* (needs Ollama+GPU): score each model tier on
  schema-valid + in-scope next-action selection, grammar-constrained on/off — the
  numbers that justify the tier defaults and substantiate marketing claims. Extend
  with methodology-alignment once the task tree exists (Phase 2).
- ✅ **Name resolved → `tyto`** (module `github.com/dukotah/tyto`, binary `tyto`).

## Phase 2 — Real recon/scan, the methodology brain & the data model — 🚧
> **Status (June 2026):** methodology task-tree ✅ (`internal/methodology`, guard-pruned
> frontier); native recon/scan ✅ (`portscan`, `httpprobe`, `webcrawl`, `dnsenum` — native,
> not the naabu/ProjectDiscovery tools); finding dedup ✅ (light, by target+title);
> resumable engagements ✅ via a JSON state snapshot (`internal/store`). **Not done:** a
> relational SQLite store and the provisioned/recovered **credential data model**.
- ⬜ **Scan layer (pure-Go):** harden the native TCP-connect scanner (worker pool,
  ranges, banner grab) → embed `naabu` (CONNECT, `CGO_ENABLED=0`) +
  `praetorian-inc/fingerprintx`. *(Pin the ProjectDiscovery module tree together;
  CONNECT mode keeps it pure-Go on Windows.)*
- ⬜ **Recon pipeline (PD, MIT Go libs):** `subfinder → dnsx → httpx → katana`
  (standard/non-headless). **Air-gapped by default**; passive OSINT is opt-in and
  guard-tagged. **Discovered assets are TAINTED candidates** — they may populate state
  but can **never widen Scope**; every active tool re-passes the guard against the
  *original* authorized scope. Scope is **load-time-only/immutable** (no runtime
  `AddTarget`); any amendment goes through engagement reload + re-validation + audit,
  never the planner. *Test:* an out-of-scope host injected via a banner is never scanned.
- ⬜ **Methodology brain — the differentiator.** External **Pentesting Task Tree** the
  engine owns: PTES phase backbone + ATT&CK-derived (~30-node) technique catalog +
  OWASP WSTG, shipped as `go:embed` JSON. The guard prunes the technique frontier
  (computed in Go from the asset graph) **before** the model sees it; the model only
  **selects + parameterizes** one node.
- ⬜ **Credential / identity data model** (the schema blocker — land it before any
  authenticated tooling). Add a **provisioned-credential** type to the engagement
  model (scoped to specific targets, with a usage/risk ceiling the guard enforces) and
  a **recovered-credential** type (creds/hashes/tickets) to finding/state. Secrets are
  **redacted** in audit + never enter the planner prompt. Add an `identity`/`credential`
  Category + Credential finding type to the taxonomy.
- ⬜ **Finding dedup/correlation model** (cheap now, before SQLite churns the schema):
  deterministic `Fingerprint = hash(normalized-target + port + template/CVE id +
  location)`, plus `AssetID`/`Port`/`SourceID` keys; `AddFinding` becomes dedup-aware
  ("one logical issue = one finding with N evidence instances" — `Evidence` becomes a
  slice). Native exact-dedup + host→service→vuln grouping is a **core** Phase-3
  reporting requirement (not delegated to optional DefectDojo).
- ⬜ **Persist state to SQLite** (`ncruces/go-sqlite3`, no-CGO WASM) — one
  `engagement.db` per job; resumable engagements; provisioned + recovered creds persist
  here.
- ⬜ **Quarantine extraction** (builds on the Phase-1 invariant): raw banners/HTTP
  bodies run through a quarantined step that emits **typed assets AND findings**; the
  planner sees only those, never raw output.

## Phase 3 — Vuln detection + client-ready reporting — 🚧
> **Status (June 2026):** reporting is largely ✅ — SARIF 2.1.0, dual-axis CVSS v3.1
> (`internal/cvss`, scored into findings), HTML/print-to-PDF + Markdown + JSON, native
> dedup/grouping, and validate-before-report (validated/candidate split). Detection breadth ✅
> via a NATIVE template engine — `internal/templates` runs Nuclei-style YAML templates with an
> embedded, operator-extensible starter pack (`templatescan`), rather than embedding the heavy
> nuclei/v3 lib (keeps single-binary/offline). **Still not done:** a much larger template pack
> (or real nuclei-templates ingestion), dependency/version **CVE feeds** (Trivy / FKIE NVD), the
> `tyto feeds` bundler, and semantic recall.
*Where tyto starts competing with Nessus on detection breadth. (Burp-class web-active
testing is Phase 4 — don't claim it here.)*
- ⬜ **Embed Nuclei v3** (`nuclei/v3/lib`) + **vendored nuclei-templates** snapshot +
  `DisableUpdateCheck()` — 10k+ checks, fully offline.
- ⬜ **Dependency/version CVEs:** Trivy (primary; OS-pkg/container/IaC coverage) +
  **FKIE `nvd-json-data-feeds`** for offline CPE→CVE. *(OSV-Scanner is the weaker
  half of the pair — optional, source-repo lockfiles only.)*
- ⬜ **`tyto feeds` command** — one operator-run bundler (templates + trivy-db +
  FKIE NVD) with checksums, so air-gapped boxes never go silently stale.
- ⬜ **Reporting:** SARIF 2.1.0 export (`owenrumney/go-sarif/v3`) + **dual CVSS
  v3.1 & v4.0** (`pandatix/go-cvss`). **PDF:** Typst (embedded WASM `typst-go-wasm`)
  is the *target*, but it is young (v0.x, Go-1.25+, operator-supplied fonts) and a
  **single-maintainer** wrapper — keep **pure-Go `maroto/v2` as a real fallback** and
  ship the existing Markdown/native-JSON report as the default first. Native exact
  dedup + host→service→vuln grouping required. Optional DefectDojo push.
- ⬜ **Semantic recall** (enhancement, not the primary mechanism): `sqlite-vec` +
  `nomic-embed-text` (via Ollama) for top-K retrieval. *(sqlite-vec is pre-1.0 — keep
  deterministic fingerprint dedup as the trustworthy default; vector clustering is
  additive.)*
- ⬜ **Validate-before-report:** confirm exploitability with a real check before a
  finding is reported.

## Phase 4 — Web depth + OS-level "hardened mode" — 🚧
> **Status (June 2026):** web-active testing ✅ but built NATIVELY (own tools:
> `webcheck`/`webdiscover`/`webinject`/`corscheck`/`redircheck`/`httpmethods`/`tlscheck`/
> `secretscan`) rather than shelling out to ZAP/ffuf/sqlmap; an operational **web console**
> ✅ (`tyto serve` — beyond the planned passive TUI: drive + live-monitor runs in a browser).
> **Not done:** OS-level **hardened mode** (default-deny egress proxy + bubblewrap/gVisor) and
> the interactive per-action approval UX (we chose auto-run-within-authorized-scope instead).
- ⬜ **Web active scanning:** OWASP ZAP as a managed **sidecar daemon** (`zap-api-go`,
  local `api.key`); shell-out adapters for `ffuf`, **`sqlmap` (GPLv2,** detect-only by
  default**)**, `arjun`. **Per-mode** risk gating enforced by the guard's per-param
  classifier (nuclei passive vs intrusive; ZAP passive vs active; sqlmap detect vs
  exploit). Authenticated scanning uses the Phase-2 credential model.
- ⬜ **Two-layer scope enforcement (Linux hardened mode):** **default-deny egress
  proxy** keyed to scope (`iron-proxy`, or a native SNI/DNS allowlist) — validating the
  **resolved IP at connect time** against scope CIDRs (closes DNS-rebinding/TOCTOU) and
  honoring **out-of-scope precedence** — + **bubblewrap** per shelled-out tool,
  `gVisor` for high-risk. Until this ships, the in-scope guarantee is **app-layer-only
  / best-effort**; degrade + warn loudly on Windows.
- ⬜ **Full kill-switch** wired through `ctx` (SIGINT + watched abort-file + the
  Phase-1 deadline) that cancels in-flight rate-limiter waits, semaphores, **and child
  processes**.
- ⬜ **TUI console** (Bubble Tea v2) — *passive* live view; engine/guard stay headless.
- ⬜ **Interactive approval UX** for the Phase-1 `RequireApproval` verdict.

## Phase 5 — Internal / Identity (Active Directory) — ⬜
*The biggest capability gap for "all-in-one," and where offline/air-gapped value is
strongest. Read-only enumeration/graph (RiskMedium↓) can land earlier; intrusive
spray/relay/PtH defer behind the exploitation-grade gate. All shell-out/adapter tier.*
- ⬜ **AD/SMB/Kerberos enumeration:** **NetExec** (BSD-2, SMB/LDAP/WinRM/MSSQL) +
  **impacket** (Apache-class; GetUserSPNs/GetNPUsers/secretsdump) + **kerbrute** (MIT).
- ⬜ **AD graph:** ingest **BloodHound CE + SharpHound CE** (both **Apache-2.0** — embed
  the data model + shell out the collector) into the SQLite engagement DB as
  relational + edge tables; surface attack paths to the planner via the same top-K
  recall (no Neo4j).
- ⬜ Kerberoast/AS-REP-roast = RiskMedium; **spray/relay/pass-the-hash/ticket =
  RiskHigh**, gated like exploitation (authorization artifact + human approval +
  per-target rate-limit + lockout-awareness). *(Not pure-Go; documented optional tier.)*

## Phase 6 — Offensive depth (gated, post-1.0) — 🚧
> **Status (June 2026):** a NATIVE exploitation tier landed early — `cmdexec` (proves RCE by
> executing commands and capturing output) and `sqliexploit` (error-based SQLi data
> extraction). Both are exploit-category/RiskHigh and run ONLY with a verified Ed25519
> authorization grant for the target (auto-run within authorized scope). **Not done:** the
> heavy frameworks (Metasploit/Sliver), credential attacks (hydra/hashcat), and pivoting.
*Highest risk, build last, **default OFF**. The AI may PROPOSE; the deterministic
guard + human sign-off APPROVE. Break the lethal trifecta (untrusted input + exploit
capability + egress).*
- ⬜ **Offline exploit lookup:** `searchsploit`/Exploit-DB (reference only; bash+git, so
  a documented external dep, not single-binary). Surface to operator, never auto-run.
- ⬜ **Exploitation backends:** Metasploit (`msfrpcd` RPC) + Sliver (gRPC-over-mTLS) —
  GPLv3, shell/RPC only. Require auth artifact + high-risk RoE flag + interactive
  approval + sandboxed execution.
- ⬜ **Credential attacks** *(add a 17th research facet first to justify picks/licenses)*:
  online spray/brute via **hydra (AGPLv3, shell-out-only)** / NetExec; offline cracking
  via **hashcat (MIT)** / **john (GPLv2)**. `credential-attack` category, RiskHigh +
  forbidden by default, strict per-target rate-limit + lockout config + approval.
- ⬜ **Pivoting/proxying (optional, operator-initiated, never model-driven):**
  `chisel` (MIT, embeddable) or `ligolo-ng` (GPL-3.0, shell-out). **Hard prerequisite:**
  the guard must enforce in-scope on the *actual connect-time destination through the
  tunnel*, not the literal target string. *(If internal engagements fall outside tyto's
  wedge, move MITM/pivoting to Non-goals instead — make the boundary explicit.)*

## Phase 7 — Platform & release polish — ⬜
- ⬜ **Plugin SDK:** `hashicorp/go-plugin` (gRPC), process-isolated (a plugin can't
  crash tyto or bypass the in-process guard).
- ⬜ **Release engineering:** GoReleaser signed, reproducible `CGO_ENABLED=0` builds;
  `koanf` config; `slog` (separate from the audit log); optional `gocron` scheduler
  (every tick re-passes the guard + RoE window).

---

## Always-on workstreams (not a phase)
- **Evaluation:** the harness from Phase 1 grows every phase — no capability ships
  without a scorer/regression test. This is also the source of honest marketing numbers.
- **License & security hygiene:** maintain a NOTICE/attribution file; keep the
  embed-vs-shell-out boundary green in CI; never link GPL/AGPL/NPSL.
- **Honesty discipline:** never market a guarantee before its mechanism ships
  (authorization, OS-egress "cannot go out of scope," tamper-evidence).

## Open decisions (yours — see RESEARCH-SYNTHESIS.md)
Minimum supported hardware floor (drives *the* default model & whether CPU-only is
supported) · single-binary purity vs. the optional adapter tiers · commercial/closed
shipping (hardens the license boundary) · ship a bundled model? · OS target for
hardened mode (Linux-only egress/sandbox).

## Non-goals
- A botnet, worm, or anything self-propagating.
- Anything that runs without an acknowledged, in-scope, **authorized** engagement.
- **Model-driven** pivoting/exploitation (these are operator-initiated + gated).
- Detection-evasion whose only purpose is to defeat defenders on systems you weren't
  authorized to touch.
- Embedding GPL/AGPL/NPSL code into the binary (shell-out only).
- Over-promising full-autonomous kill-chaining — the local-model gap is real; tyto
  wins on capability breadth under provable scope control, trust, and offline operation.
