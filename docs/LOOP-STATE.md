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

## Current scorecard  (planner: scripted · runner: wsl)

_Source: `proving-ground/scorecard.json`, 2026-11-21._

| Metric | Value |
| --- | --- |
| **coverage** | **11 / 15 (73.3%)** |
| **validated** | **11 / 15 (73.3%)** |
| **chain_depth** | 3 / 3 (coarse single-host proxy) |
| raw findings | ~63 |
| autonomous recall (ollama) | **unmeasured** — no local model in this env |

- **Found (11):** reflected-xss · sql-injection · open-redirect · exposed-env ·
  exposed-git · exposed-backup · secrets-in-js · missing-sec-headers · weak-cookie ·
  stale-banner · robots-disclosure
- **Missed (4):** permissive-cors · dangerous-methods · graphql-introspection ·
  admin-creds-comment

### Environment notes (this machine)
- **Runner = WSL.** Smart App Control blocks freshly-built unsigned `.exe`s
  (WinError 4551), so the benchmark cross-compiles a Linux ELF and runs lab + tyto
  in WSL. `bench.py` does this automatically (`--runner auto`).
- **Tests** run the same way: `GOOS=linux go test -c -o .bench/<pkg>.test ./pkg`
  then execute the ELF in WSL. Native `go test` is SAC-blocked; WSL has no `go`.
- Baseline before P1 (same WSL runner): **8/15**. P1 added exactly +3.

---

## Backlog position (full detail in CAPABILITY-AUDIT.md)

| # | Task | Moves | Status |
| --- | --- | --- | --- |
| **P1** | Chain discovered params → injection tools | +3 (sqli, xss, redirect) | `[x]` **DONE** (8→11) |
| **P2** | Invoke full web battery (cors/methods/graphql/cookie/apidocs) | +3 | `[ ]` **← NEXT** |
| P3 | secretscan reads HTML comments | +1 (admin creds) | `[ ]` |
| P4 | Reliable `/backup/` detection (+ kill the flake) | +1 (done via WSL runner) | `[~]` |
| P5 | Stand up autonomy tier (ollama) of the benchmark | unlocks axis 5 | `[ ]` |
| P6 | Second lab host for real chain-depth | fixes axis 3 | `[ ]` |

**NEXT TASK:** P2 — the arsenal has `corscheck`, `httpmethods`, `graphqlcheck`,
`cookieaudit`, `apidocs` but the sweep never invokes them, so permissive-cors,
dangerous-methods, and graphql-introspection go undetected. Dispatch the full web
battery deterministically against `service` assets (mirror the P1 follow-up
pattern in `internal/engine/followup.go`, or extend the methodology), and make
`/api/graphql` discoverable. Target: +3 → 14/15.

---

## Iteration log (newest first)

_Template per entry: date · task · score before→after · committed? · notes._

- **2026-11-21 · P1 chain params→injection** · WSL 8/15 → **11/15** (+3: reflected-xss,
  sql-injection, open-redirect) · committed. `internal/engine/followup.go` deterministically
  dispatches injection tools (webinject/ssti/sqliexploit/redircheck) against discovered
  `endpoint` assets, planner-independent (hunt omits injection; a fixed planner targets
  only the base host). Also reworked `bench.py` to the WSL runner (SAC workaround) — this
  is why the baseline is now quoted as WSL 8/15, not the earlier native 7/15. Next: P2.
  ⚠️ Found a separate pre-existing bug (NOT in this branch): `internal/blue/coverage/
  coverage.go` on `feat/tyto-blue` is swallowed by the `coverage.*` .gitignore rule and was
  never committed → the pushed blue branch won't build. File backed up to scratchpad;
  needs a gitignore fix + commit on `feat/tyto-blue`. Flagged to owner.
- **2026-11-21 · scaffolding** · n/a → coverage 7/15 (native) · harness + audit + loop
  state built; structured guard `DenyCode` + actionable MCP denial feedback committed as
  the base (`cff93a3`), scaffolding (`426f72f`), both on `feat/loop-capability` off main.
