# tyto → v1.0: the road to a tool too good not to use

**North star:** an authorized-pentest operator that, pointed at an in-scope target
and driven by a frontier model over MCP, produces findings and a report at the
level of a **senior pentester / senior dev** — complete coverage, validated
findings, chained impact, and a client-ready deliverable — while staying provably
in scope and fully audited.

This is the authoritative, sequenced plan. The other roadmap docs are the granular
backlogs this one draws from:
- [ROADMAP-100.md](ROADMAP-100.md) — the 100-item capability backlog (A–J).
- [ROADMAP-V2.md](ROADMAP-V2.md) — the MCP-first pivot + capability track.
- [ROADMAP.md](ROADMAP.md) / [ROADMAP-FULL-PENTEST.md](ROADMAP-FULL-PENTEST.md) — original phases, kept for context.

> **For the next agent picking this up:** the latest work lives on branch
> **`pivot-mcp-first`** (stacked on `onboarding-doctor`, PR #1). `git fetch && git
> checkout pivot-mcp-first`, read this file, run `tyto doctor`, then take the top
> unchecked milestone. Build conventions: single Go binary, `CGO_ENABLED=0` core;
> external tools shelled out via `internal/tool/adapter` (graceful-degrade, never
> bundled); every new capability is a registered builtin so the **guard classifies
> it, the methodology ranks it, and coverage tracks it** — never a bare shell
> command. `go build ./... && go vet ./... && go test ./...` stays green. Add a
> technique node to `internal/methodology/catalog.json` for every new builtin.

---

## What "senior-level" means (the bar every milestone is measured against)

A senior operator is defined by six properties. tyto is v1.0 when it has all six,
proven on the benchmarks below — not before.

1. **Completeness** — doesn't miss whole vuln classes or whole phases. Walks a full
   methodology (external → web → internal → AD → post-ex) and *knows* what it didn't
   cover.
2. **Accuracy** — findings are validated, not guessed. Low false-positive rate; each
   finding carries evidence (request/response, screenshot, extracted data).
3. **Impact / chaining** — turns a foothold into real impact: recon → access →
   lateral → privilege escalation → domain/data. Not a disconnected finding list.
4. **Judgment** — stays in scope, respects RoE, avoids destructive actions, knows
   when to ask a human. Enforced by the guard, not hoped for.
5. **Deliverable** — a report a client pays for: exec summary, business impact,
   reproduction steps, remediation, CVSS, coverage statement.
6. **Trust** — everything it did (and was allowed to do) is provable from a
   tamper-evident audit. This is the moat and it never regresses.

---

## Tracks (every milestone advances one or more)

- **T1 Coverage** — breadth of what tyto can detect/do (web classes + internal/AD).
- **T2 Accuracy** — validation, evidence, confidence, dedup, false-positive kill.
- **T3 Reasoning** — how well the brain drives (methodology, chaining, auth, memory).
- **T4 Deliverable** — report quality + exports.
- **T5 Control** — human-in-the-loop (console + MCP), steering, approval.
- **T6 Trust** — guard/audit/RoE hardening, egress control.
- **T7 Proof** — benchmarks + regression that *prove* the bar is met.
- **T8 Adoption** — install/onboarding/docs so people actually run it.

Status legend: ✅ done · 🚧 in progress · ⬜ planned.

---

## Milestones

### M0 — Onboarding & MCP-first foundation ✅ (2026-11-20)
*T8, T3, T6.* The floor that makes everything else usable.
- ✅ `tyto doctor` — read-only environment diagnostic with exact fixes.
- ✅ Committed, runnable localhost demo; quickstart that actually works.
- ✅ `tyto_methodology` MCP tool — the governed, coverage-aware full-scope frontier
  is now visible to the driving brain (the keystone of the pivot).
- ✅ MCP action-coverage anchoring; `fix(mcp)` audit-category correctness.
- ✅ README/ROADMAP reframed to MCP-first "governed body any brain drives."

### M1 — Evidence & validation core 🚧 — *the single biggest credibility jump* (T2)
Senior findings are *proven*, not asserted. Without this, breadth just makes more
noise. This is the highest-leverage next milestone.
- ⬜ Recording HTTP(S) transport bound into every web tool (inject one client; today
  each builds its own) → each finding carries the real req/resp. Folds in
  ROADMAP-100 **C** evidence + ROADMAP-V2 #4 (package exists, needs the injection seam).
- ⬜ Headless-browser screenshot capture for visual findings (reuse `spacrawl`'s Chrome).
- ⬜ **Validation pass**: a finding is marked `validated` only when a confirming
  action succeeded (e.g. SQLi → extracted a value; XSS → fired in headless render;
  SSRF → OOB callback hit the collaborator). Unvalidated = `candidate`, reported
  separately. Folds ROADMAP-100 C40/C41/C46.
- ⬜ Confidence score + false-positive suppression; dedup/cluster findings across
  hosts (ROADMAP-100 F74/E66, G84).
- **Acceptance gate:** on OWASP Juice Shop, ≥90% of reported findings carry evidence
  and reproduce; false-positive rate measured and <10%.

### M2 — Web vuln-class completeness (T1)
Close the gaps so no common web class is unreachable. All pure-Go where feasible,
OOB-backed where needed (the collaborator already exists via `oobcheck`).
- ⬜ SSRF (param + header) paired with OOB; blind XSS via OOB; XXE on XML endpoints.
- ⬜ HTTP request smuggling (CL.TE/TE.CL); web-cache deception/poisoning.
- ⬜ Prototype pollution (client+server); mass-assignment / parameter pollution.
- ⬜ Insecure deserialization signatures; CSP weakness analyzer; CRLF injection.
- ⬜ GraphQL field-suggestion + batching abuse; JWT forgery (alg:none, weak-secret crack).
- Backlog source: ROADMAP-100 **B** (16–35) + **C**. Each = one builtin + catalog node.
- **Acceptance gate:** a curated set of PortSwigger Web Security Academy labs
  (one per class above) solved end-to-end under MCP drive.

### M3 — Native internal network & Active Directory offense (T1) — *the whole-works unlock*
Promote the internal/AD tiers from the `tyto_kali` escape hatch to first-class,
guard-classified, coverage-tracked builtins (adapter-backed, graceful-degrade).
This is what no OSS tool combines with web + governance.
- ⬜ **BloodHound-style AD collection + attack-path analysis** (collect via nxc/bloodhound-python; parse+reason over paths).
- ⬜ **NTLM relay / poisoning** detection + (gated) execution (responder/ntlmrelayx).
- ⬜ **Credential dumping** (secretsdump / DCSync) — gated.
- ⬜ **Lateral movement** (psexec/wmiexec/winrm via impacket/nxc) — gated, credential-driven.
- ⬜ **Privilege escalation** checks (winPEAS/linPEAS/GTFOBins/ADCS ESC-series) — read-only enum unattended, exploitation gated.
- ⬜ **Pivoting / SOCKS** (ligolo-ng/chisel) so deeper segments are reachable.
- ⟶ Requires M4's credential-aware frontier so these surface in the methodology.
- Backlog source: ROADMAP-100 **D** (49–58).
- **Acceptance gate:** tyto, driven over MCP, solves **GOAD (Game of Active
  Directory)** / GOAD-Light end-to-end to domain compromise, every step audited.

### M4 — Reasoning & chaining: drive like an operator (T3)
Make the brain string findings into impact and never lose the thread.
- ⬜ **Credential-aware & finding-aware methodology**: `Recommend` considers recovered
  creds and prior findings, not just assets — so post-ex/AD/lateral techniques enter
  the frontier once a foothold exists (unblocks M3 in the catalog).
- ⬜ **Chained-exploit synthesis**: a finding spawns the next recommended action
  (foothold → internal discovery → roast → path → DA). ROADMAP-100 C44.
- ⬜ **Durable todolist / hypothesis ledger** across MCP calls so multi-step chains
  are tracked and advanced only when prerequisites are met. ROADMAP-100 E62/F.
- ⬜ **Authenticated / multi-identity testing**: provisioned-credential login slots;
  IDOR/BOLA differ across two identities. ROADMAP-100 D + C39.
- **Acceptance gate:** on a multi-step app (e.g. HTB-style), tyto reaches an
  objective that requires chaining ≥3 findings, unprompted beyond the objective.

### M5 — Client-ready deliverable (T4)
The report is what gets paid for.
- ⬜ Exec summary + per-finding business impact, reproduction steps, remediation.
- ⬜ CVSS vector + score per finding; confidence column; **coverage statement**
  ("tested X/Y/Z; not covered: …" straight from the methodology coverage data).
- ⬜ Exports: SARIF (CI), PDF (client), single-finding HackerOne/Bugcrowd markdown.
- Backlog source: ROADMAP-100 **G** (79–86).
- **Acceptance gate:** a generated report passes a senior pentester's review rubric
  (completeness, accuracy, actionability) with no critical gaps.

### M6 — Control surface: watch, approve, steer (T5, T6)
With a powerful brain driving, the human console *is* the safety story.
- ⬜ **MCP ↔ console unification**: every MCP action streams to the `serve` live
  feed; gated actions block on a real human click (browser) or terminal approval —
  not the agent's own `approve=true`. (ROADMAP-V2 #0.)
- ⬜ Inline approve/deny + "steer" notes the brain sees on its next call.
- ⬜ Visual attack graph / run-history diff (ROADMAP-100 H).
- ⬜ **Egress control + tool-output redaction** in MCP mode (scrub creds/PII before
  they reach a cloud model) — restores part of the offline posture the pivot traded.
- ⬜ Scope TOCTOU close (grant `ScopeVersion`); kill switch; RoE depth. ROADMAP-100 I.
- **Acceptance gate:** a full engagement run where a human watched the live feed and
  approved every state-changing action from the browser, nothing self-approved.

### M7 — Proof & productionization (T7, T8)
Make "it's good" measurable and the tool a daily driver.
- ⬜ **Benchmark harness + regression suite**: GOAD, the PortSwigger/Juice-Shop set,
  an HTB-style chain — run in CI, scored, tracked over time. This is how we *prove*
  senior-level and prevent regressions. (Everyone claims #1 on a leaderboard; we
  publish a reproducible harness instead.)
- ⬜ Resumable engagements (SQLite) across crashes/machines; differential/retest runs.
- ⬜ One-command MCP setup for Claude Code; one-line installer + Homebrew tap
  (GoReleaser already ships archives); `tyto init` (provision `~/.tyto` + model).
- ⬜ Scheduled/recurring engagements (ROADMAP-100 J).
- **Acceptance gate (v1.0):** all six senior-level properties demonstrated on the
  benchmark suite, reproducibly, from a clean `go install` + `tyto doctor` setup.

---

## Suggested order (value-first)
**M1 (evidence/validation)** → **M4-credential-aware-frontier** (small, unblocks the
internal catalog) → **M3 (AD/internal, GOAD gate)** → **M2 (web completeness)** →
**M6 (console control)** → **M5 (report)** → **M7 (benchmarks + release)**.

Rationale: accuracy before breadth (M1 first, or breadth just adds noise); the tiny
credential-aware frontier change unblocks the biggest differentiator (M3); control
and reporting harden once the engine is capable; benchmarks last, to certify.

Each milestone ships independently and leaves tyto working and better than before.
