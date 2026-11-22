# LOOP-STATE — tyto capability loop

The loop's PICKUP-HERE. **Read this first every iteration; write it last.** It is how
iterations compound instead of re-deriving. The ranked backlog lives in
[`CAPABILITY-AUDIT.md`](CAPABILITY-AUDIT.md); this file is the live position.

---

## Loop doctrine (binding — this is what "a good iteration" means)

1. **Measure or it didn't happen.** A commit must move a benchmark number
   (`proving-ground/bench.py` → `scorecard.json`) OR be measurement/infra that enables
   one (new lab vuln + answer-key class, autonomy tier, etc.). No unmeasured "progress."
2. **Gates before commit.** `go build ./...`, `go vet ./...`, the test suite, and the
   benchmark must all pass. On red: fix or revert. Never commit broken.
3. **One task per iteration.** Take the single highest-value unblocked item from the
   backlog. Smallest task that moves a real number wins. Don't batch.
4. **Lab-only.** Benchmark/exploit work runs ONLY against tyto's own local lab targets
   (self-attested, 127.0.0.1). Never a real or external host. The Scope Guard enforces
   it; don't try to route around it.
5. **Branch, never main.** Commit to `feat/loop-capability`. No auto-merge to main, no
   deploy, no push beyond the feature branch.
6. **Honesty.** If the number didn't move, say so and revert. If a change only *looks*
   right, prove it with the benchmark before claiming it.
7. **Stop and wait for the human if:** blocked needing a decision / credentials / a real
   target, OR 3 iterations pass with no score movement, OR the target score is reached.

**Target score (v1):** coverage **≥ 13/15** and validated **≥ 13/15** on the Northwind
lab, then grow the lab (P6) and raise the bar. Industry-leading is a moving target; the
scorecard is how we chase it honestly.

---

## Current scorecard  (planner: scripted — deterministic, no model)

_Source: `proving-ground/scorecard.json`, 2026-11-21, stable across 3 runs._

| Metric | Value |
| --- | --- |
| **coverage** | **7 / 15 (46.7%)** |
| **validated** | **7 / 15 (46.7%)** |
| **chain_depth** | 3 / 3 (coarse single-host proxy) |
| raw findings | ~28 (±1 flake) |
| autonomous recall (ollama) | **unmeasured** — no local model in this env |

- **Found (7):** exposed-env · exposed-git · secrets-in-js · missing-sec-headers ·
  weak-cookie · stale-banner · robots-disclosure
- **Missed (8):** reflected-xss · sql-injection · open-redirect · exposed-backup ·
  permissive-cors · dangerous-methods · graphql-introspection · admin-creds-comment

---

## Backlog position (full detail in CAPABILITY-AUDIT.md)

| # | Task | Moves | Status |
| --- | --- | --- | --- |
| **P1** | Chain discovered params → injection tools | +3 (sqli, xss, redirect) | `[ ]` **← NEXT** |
| P2 | Invoke full web battery (cors/methods/graphql/cookie/apidocs) | +3 | `[ ]` |
| P3 | secretscan reads HTML comments | +1 (admin creds) | `[ ]` |
| P4 | Reliable `/backup/` detection (+ kill the flake) | +1 | `[ ]` |
| P5 | Stand up autonomy tier (ollama) of the benchmark | unlocks axis 5 | `[ ]` |
| P6 | Second lab host for real chain-depth | fixes axis 3 | `[ ]` |

**NEXT TASK:** P1 — make parameterized endpoints discovered by `webcrawl` seed the
injection tools (`webinject`/`ssti`/`sqliexploit`), then re-run the benchmark and
confirm sql-injection + reflected-xss + open-redirect move from missed → found.

---

## Iteration log (newest first)

_Template per entry: date · task · score before→after · committed? · notes._

- **2026-11-21 · scaffolding** · n/a → coverage 7/15, validated 7/15 · harness built &
  baseline locked (not yet committed — awaiting owner sign-off on what it measures).
  Also shipped, uncommitted on the working tree: structured guard `DenyCode` +
  actionable MCP denial feedback (3 files) and a latent `string(Category)` audit-log
  fix. Branch note: the denial-feedback work is orthogonal to blue and should land on
  its own branch off main.
