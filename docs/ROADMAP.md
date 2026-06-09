# Roadmap

Honest status. ✅ done · 🚧 in progress · ⬜ planned.

## Phase 0 — Foundation (this scaffold)
- ✅ Repo, license, CI, lint, build
- ✅ Engagement / scope / rules-of-engagement model
- ✅ Scope Guard with unit tests (the safety core)
- ✅ Tool plugin interface + registry
- ✅ LLM interface + Ollama client + mock
- ✅ Engine loop skeleton with `--dry-run`
- ✅ State store + findings model
- ✅ Audit log
- ✅ CLI surface (`engagement validate`, `run`, `tools`, `version`)

## Phase 1 — First real engagement
- ⬜ Built-in tools: TCP port scan, service/banner grab, TLS inspect
- ⬜ Passive recon tools (DNS, cert transparency) — risk-passive
- ⬜ Planner prompt v1 with structured JSON output + retry/repair
- ⬜ Real plan→act→observe→replan loop against a lab target
- ⬜ Markdown report generation

## Phase 2 — Depth
- ⬜ Web crawl + OWASP-style probes (gated to high risk + explicit RoE)
- ⬜ Findings dedup, asset graph, severity scoring (CVSS)
- ⬜ Knowledge base of techniques the planner can draw on (MITRE ATT&CK map)
- ⬜ Resumable engagements (persist state)

## Phase 3 — Compete
- ⬜ SARIF + client-ready PDF reports
- ⬜ Plugin SDK so others can ship tool adapters
- ⬜ Multi-model planner (local + optional stronger model for hard calls)
- ⬜ TUI dashboard for live engagement view
- ⬜ Signed, reproducible builds + release pipeline

## Non-goals
- A botnet, worm, or anything self-propagating.
- Anything that runs without an acknowledged, in-scope engagement.
- Detection-evasion features whose only purpose is to defeat defenders on
  systems you weren't authorized to touch.
