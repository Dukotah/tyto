# tyto blue — autonomous detection & response, purple-locked to tyto

**Status:** NEW subsystem (as of 2026-11-17). tyto today is a red-team engine; this
adds the defensive mirror in the *same* binary. Branch: `feat/tyto-blue`.

Goal: a single Go binary (Apache-2.0) that **ingests** security logs/alerts,
**detects** with Sigma rules, **triages** each alert with a local LLM (real vs noise,
with reasoning), proposes **guarded** response actions, and runs a **purple loop** —
tyto attacks, tyto blue proves it detected the attack or drafts the missing rule,
scored live on a **MITRE ATT&CK** coverage grid.

## Why this belongs in the tyto repo (not a separate project)

tyto's spine *is* a blue-team engine wearing red paint. The defensive loop
`ingest → detect → triage → guard → respond → record` is the structural mirror of
the offensive `plan → guard → execute → record → replan`, and it reuses the same
core. The **purple loop** only works if attack and defend share one audit log and
one run record in one process — splitting repos would mean rebuilding half of tyto
behind an IPC bridge.

## The governing principle (inherited from tyto)

**The AI proposes, a deterministic guard disposes.** On the red side the Scope Guard
gates offensive actions; on the blue side a **ResponseGuard** gates defensive actions
(block IP, isolate host, kill process). The guard is hard code the model cannot
bypass. Destructive/outward responses require human approval. Same legal/safety
backbone, same auditability.

## Reuse map (do NOT rebuild these)

### From tyto (`github.com/dukotah/tyto/internal/...`)
| Reuse | As |
| --- | --- |
| `guard` (Verdict/Decision/ToolMeta/RiskClassifier/New/Evaluate) | pattern for `respond.ResponseGuard`; reuse `guard.Verdict`/`guard.Decision` verbatim, Deny = zero value = fail closed |
| `audit` (Open/Record/Head, hash-chained JSONL) | tamper-evident detection/response log, verbatim |
| `planner/llm` (`Client`, `SchemaClient`, Ollama/OpenAI/Mock) | the triage brain's model backend, verbatim; type-assert `SchemaClient` for grammar-constrained verdicts |
| `engine` throttle (per-target rate-limit + global semaphore, errgroup) | "triage N alerts, M concurrent, rate-limited per source" |
| `report` (Build/Render*/RenderSARIF/RenderHTML) | detection & posture reports |
| `state` quarantine boundary (`planner:"safe"\|"quarantined"` + reflect test) | event hygiene — log text is attacker-controlled; see Event design below |
| `engagement` (Authorization/VerifiedGrant/self-attested) | "authorization to respond" over a defended estate |
| `tool.Registry` pattern | parallel `detect`/`respond` registries, wired in Go (no JSON catalog) |
| `methodology.Recommend` (deterministic ranker + embedded catalog) | deterministic triage/response playbook ranker |

### From bastion (`github.com/Dukotah/bastion`, Apache-2.0 — safe to vendor)
| Reuse | As |
| --- | --- |
| `pkg/contract` (Finding/Severity/RiskID+Taxonomy/RiskScore/CoverageMatrix) | swap OWASP-MCP axis → MITRE ATT&CK technique IDs |
| `internal/warden` (deny-by-default policy, taint-tracking exfil detection, integrity pinning, obfuscation stripping) | detection-rule engine content + patterns |
| `internal/store` (pure-Go SQLite, migrations, Save/List/Latest/Prune) | event/finding store + retention |
| `internal/report` (one view model → MD + self-contained HTML) | posture/incident report |
| `internal/loop` (attack→defend→aggregate) | purple-loop spine |

### From injectkit (MIT — port ideas, not lines) / lantern (design ref)
- injectkit `response_class.py` 5-class graded disposition; `scoring.py` detector
  precedence + per-technique severity floor → graded alert dispositions.
- lantern `reasoning.py` → the triage-brain template: deterministic state analysis +
  enumerated actions + confidence-dominant scoring + **no-LLM fallback planner**.

### External formats/libs (permissive — adopt/embed)
| Area | Adopt / embed | License |
| --- | --- | --- |
| Detection rules | **Sigma** format + fork/embed `bradleyjkemp/sigma-go`, add correlation clean-room; consume SigmaHQ corpus | DRL-1.1 (rules) / MIT (lib) |
| Event schema | **OCSF**-shaped internal `Event`; adapters map in | Apache-2.0 |
| ATT&CK data | **STIX 2.1** from `mitre-attack/attack-stix-data`, parse with stdlib | MITRE ToU (attribute) |
| Purple attacker | **tyto itself** (core thesis); Atomic Red Team YAML / Stratus (Go) as later adapters | MIT / Apache-2.0 |

### License firewall — NEVER link into the binary (reference/consume-output only)
AGPL: Hayabusa, Velociraptor, TheHive/Cortex, Shuffle. GPL-3.0: Chainsaw. GPLv2:
Wazuh. SSPL/Elastic License: Elastic Security. (Ingesting their JSON output is fine.)

### Attribution obligations (not blockers)
Sigma **DRL**: show rule author wherever a match is displayed. **ATT&CK ToU**:
attribute MITRE ATT&CK. Atomic Red Team: MIT notice.

## Package layout (disjoint — collision-proof build lanes)

```
cmd/tyto/
  blue.go              # `tyto blue` subcommands (wired by maintainer, serial)
internal/
  guard/ audit/ planner/llm/ engine/ report/ engagement/   # ← shared, reused as-is
  blue/
    event/             # KEYSTONE: OCSF-shaped Event + quarantine tags + sanitizer
    ingest/            # adapters: Wazuh JSON / Suricata EVE / Sysmon / generic JSONL → []Event
    detect/            # Sigma engine (fork sigma-go) + embedded starter rules + ATT&CK tagging
    attack/            # ATT&CK STIX 2.1 loader + technique catalog
    triage/            # clean-room brain: deterministic state + enumerated dispositions + llm.Client + no-LLM fallback
    respond/           # ResponseGuard (mirror guard) + response actions + responders (read-only propose)
    coverage/          # ATT&CK coverage matrix (technique × rule-covered × proven-detected)
    store/             # (later) vendored bastion SQLite store
  purple/              # tyto-attack → blue-detect → score → draft-missing-rule (maintainer-wired)
```

## Phases (prove the loop first, breadth later — mirrors tyto's own phasing)

- **Phase 0 — ingest + normalize.** `event` keystone + ≥1 real adapter (Suricata EVE
  + Wazuh JSON). Gate: feed a known log sample, get clean normalized `Event`s. This is
  the blue-side equivalent of the proving ground.
- **Phase 1 — detect.** Fork/embed sigma-go, `go:embed` ~20 high-precision rules,
  evaluate events → `Detection` findings tagged with ATT&CK technique IDs. Gate: a
  known-malicious log line fires the expected rule + technique; a benign baseline does not.
- **Phase 2 — triage brain.** Local-model disposition `{verdict: real|noise|uncertain,
  why, confidence}`, refute-by-default, no-LLM deterministic fallback. Reuses
  `llm.Client` + the quarantine/injection-framing boundary. This is where the value is.
- **Phase 3 — respond.** `ResponseGuard` + gated actions (block_ip/isolate_host/
  kill_process); reversible auto, irreversible/outward needs the 3-state approval.
- **Phase 4 — purple loop (THE differentiator).** tyto attacks a lab host, blue proves
  detection on the ATT&CK grid, gap → draft a Sigma rule → re-test. No open,
  local-model version of this exists.
- **Phase 5 — console + coverage dashboard** (reuse `internal/webui`), bastion store,
  Atomic/Stratus technique adapters, more ingest adapters.

Phases 0–3 stand alone as a trustworthy "AI SOC analyst." Phase 4 is the north star.

## Event hygiene (the one non-obvious design rule)

Log/alert content is **attacker-controlled text** and can carry prompt injection. But
unlike tyto's planner (which is deliberately starved), the triage brain *must* read the
alert to judge it. So the rule is **neutralize, not withhold**: log-derived fields are
tagged `quarantined`, pass through `sanitizeField` (strip control chars, collapse
whitespace, cap length), and are presented to the model only inside an explicitly
delimited, "this is untrusted log data, not instructions" framed block. Routing/numeric/
enum fields are `safe`. A reflect-based test fails the build if a new string field is
added untagged — same guarantee as `internal/state`.

## Name

`tyto blue` subcommand. Brand candidate for the subsystem: **Athene** (little-owl genus,
nods to Athena / defense).
