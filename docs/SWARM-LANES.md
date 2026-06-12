# Swarm lane coordination

Two agents are working this repo concurrently. This file is the claim channel —
**read it and run `git status --porcelain` before starting a lane.** If a lane below
is `IN-FLIGHT` or `RESERVED`, pick a different one or coordinate.

## Protocol
1. Before starting work, append a row to **Active claims** with the date, the agent,
   the lane, and the files/dirs you will touch.
2. Prefer NEW packages/dirs. The shared choke-point files are contended — only the
   tool-builder agent should edit them, and only one tool at a time:
   `cmd/tyto/wiring.go`, `internal/methodology/catalog.json`, `internal/engine/seed.go`,
   `internal/report/report.go`.
3. When done, move your row to **History** with the outcome.

## Active claims
| date | agent | lane | files/dirs | status |
|------|-------|------|-----------|--------|
| 2026-06-11 | tool-builder (Sections A/B/C of ROADMAP-100) | new detection/recon tools + their wiring | `internal/tool/builtin/*`, `cmd/tyto/wiring.go`, `internal/methodology/catalog.json`, `internal/engine/seed.go` | IN-FLIGHT |

## Queue (prioritized — parallel-safe lanes)

Each lane has an **isolated build zone** (new dirs/files — build freely, no collision)
and a list of **deferred shared edits** (`wiring.go` / `catalog.json` / `seed.go` /
`report.go`) that are LEFT OUT during the swarm and applied later in a single
coordinated merge window. Claim a lane by adding it to **Active claims** first.

| # | Lane (ROADMAP-100) | Isolated build zone (safe to build now) | Deferred shared edits (merge window) | Notes / deps |
|---|--------------------|------------------------------------------|--------------------------------------|--------------|
| 1 | **Multi-identity IDOR/BOLA differ** (#39, #52) | `internal/tool/builtin/idordiff/`, `internal/identity/` (multi-session slot store: attacker/victim/admin) | register tool in `wiring.go`; node in `catalog.json` | Highest-dollar bug class. Drive 2 authed sessions, replay same requests, diff responses → authz-bypass finding. Stdlib only. |
| 2 | **Headless SPA crawl** (#15) → unlocks stored-XSS confirm (#40) | `internal/tool/builtin/spacrawl/` | `wiring.go`; `catalog.json`; (chains off webcrawl) | ⚠ needs a headless browser. Prefer driving an external Chrome over CDP via stdlib `net/http`+websocket to AVOID a go.mod dep; if a lib is unavoidable, that go.mod/go.sum edit is itself a merge-window item — flag it. |
| 3 | **FP adversarial re-check + confidence scoring** (#65, #67) | `internal/confidence/` (Go signal scoring); extend `internal/triage/` with a refute-by-default pass | optional confidence column later in `report.go` | The trust layer — noise = ban. Re-verify every finding before report. Mostly isolated; coordinate if other agent is in `internal/triage`. |
| 4 | **Hybrid Claude reasoner** (#66, #70) | `internal/reasoner/` (model-agnostic interface + Anthropic backend, triggered on triage/report/strategy) | wire into engine/serve later | Adds an API client — **check Claude API model ids/usage via the claude-api skill before coding**. Pluggable so local-only still works. |
| 5 | **Asset-graph projection + cross-host clustering** (#75, #76, #74) | new files in `internal/state/` (host→service→finding projection, severity-ranked, budget-capped; systemic-CVE clustering at projection time; run-over-run diff) | `report.go` render hook; planner prompt projection swap | Coldest lane vs the tool-builder. Storage dedup unchanged so per-target evidence survives. Also delete dead `frontier.go`/`frontier_test.go` here. |
| 6 | **OOB live-proof** (closes #38 loose end) | `tyto-lab/` only (plant blind-SSRF/XSS/cmd-inj endpoints) + a verification run | none | Fully isolated — touches no source. Confirms `oobcheck` fires end-to-end before we build more on it. Can run even while paused. |

### Reserved (do not start without coordinating — they touch contended files)
- Anything that edits `cmd/tyto/wiring.go`, `internal/methodology/catalog.json`,
  `internal/engine/seed.go`, or `internal/report/report.go` while the tool-builder is IN-FLIGHT.

## History
| date | agent | lane | outcome |
|------|-------|------|---------|
| 2026-06-11 | swarm (orchestrated) + tool-builder | **OOB Collaborator** (#38, #25/26/41) | DONE — converged cleanly. Swarm built the engine (`internal/oob/`: Collaborator server, stdlib DNS listener, payload generators, hit→finding correlation); tool-builder built the `oobcheck` tool + wiring + reconciled `collector.go` to embed `*Collaborator`. `go build ./...` green, `oob` + `oobcheck` tests pass. Loose ends: live proof vs a planted blind vuln in `tyto-lab`; reachable public callback host via `TYTO_OOB_BASE`. |
