# tyto

**An AI-orchestrated platform for _authorized_ penetration testing.**

`tyto` is a security-testing engine driven by a **local language model** that
plans, adapts, and reasons about an engagement the way a human operator
would — choosing the approach based on *who hired you, what they own, and what
they told you you're allowed to touch*. Everything the model proposes is forced
through a deterministic **Scope Guard** that the model cannot override. The AI is
the strategist; the guard is the law.

> ⚠️ **tyto is for authorized testing only.** It will refuse to act against any
> target that is not explicitly in-scope for a loaded, acknowledged engagement.
> Using it against systems you do not own or have written permission to test is
> illegal. See [docs/ETHICS.md](docs/ETHICS.md).

> 🦉 **New:** drive tyto with a frontier model instead of the local planner —
> `tyto mcp` exposes the arsenal over the Model Context Protocol so an external
> agent (e.g. Claude Code / Opus) becomes the operator, with every call still
> routed through the same Scope Guard, approval gate and audit log. See
> [docs/MCP.md](docs/MCP.md). A landing page lives in [`site/`](site/index.html).

---

## Why this is different

The incumbents are tools. `tyto` is an **operator**.

| | Nmap / Nessus / Burp / Nuclei | tyto |
|---|---|---|
| Decides *what* to do next | You do | Local model, per engagement context |
| Adapts to findings mid-run | You do | Plan → act → observe → re-plan loop |
| Knows the client's rules | Lives in your head | First-class, machine-enforced |
| Stays in scope | Your discipline | Hard-coded guard, AI can't bypass |
| Runs offline / air-gapped | n/a | Yes — local model, no cloud calls |
| Output | Raw tool data | Findings + reasoning + report |

The wedge: **none of the big dogs have a brain that drives the whole engagement
within provable, auditable boundaries.** That's what we're building.

## The core loop

```
          ┌─────────────────────────────────────────────┐
          │  Engagement (scope, rules, objectives, auth)  │
          └───────────────────────┬─────────────────────┘
                                  │
              ┌───────────────────▼───────────────────┐
              │              Planner (AI)              │  local model
              │  "given state + rules, what next?"    │  via Ollama
              └───────────────────┬───────────────────┘
                                  │ proposes Action(s)
              ┌───────────────────▼───────────────────┐
              │            Scope Guard (hard)          │  deterministic
              │   in-scope? allowed technique? rate?   │  AI cannot override
              └───────────────────┬───────────────────┘
                       allow      │      deny → logged + fed back to planner
              ┌───────────────────▼───────────────────┐
              │          Execution Engine              │
              │     runs Tool adapters, rate-limited   │
              └───────────────────┬───────────────────┘
                                  │ Results / Findings
              ┌───────────────────▼───────────────────┐
              │       State (assets, findings)         │ ──► back to Planner
              └───────────────────────────────────────┘
                                  │
                          Report generator
```

Every decision and action is written to an append-only **audit log**.

## Architecture at a glance

| Package | Responsibility |
|---|---|
| `internal/engagement` | Engagement, scope, and rules-of-engagement model + loading |
| `internal/guard` | **Scope Guard** — deterministic allow/deny on every action |
| `internal/planner` | The AI brain: turns state + rules into proposed actions |
| `internal/planner/llm` | Pluggable LLM backend (Ollama today) |
| `internal/tool` | Tool-adapter plugin interface + registry (+ built-ins) |
| `internal/engine` | The orchestration loop tying it all together |
| `internal/state` | Knowledge store: assets, findings, timeline |
| `internal/report` | Findings → human report |
| `internal/audit` | Append-only audit log of decisions & actions |
| `cmd/tyto` | CLI entrypoint |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the deep dive and
[docs/ROADMAP.md](docs/ROADMAP.md) for what's built vs. planned.

## Status

🟢 **v0.1 MVP — working end to end.** The full ship line runs: **scan →
fingerprint → safe web checks → validated, client-ready report**, with every
action forced through the deterministic **Scope Guard** and recorded in a
**tamper-evident, hash-chained, fail-closed audit log**. Built-in tools:
`portscan`, `httpprobe` (HTTP fingerprint), `webcheck` (safe passive
vuln checks). Planning is grammar-constrained and validated (fails closed);
high-risk/exploit actions require a client **Ed25519 authorization**. Reports
export as grouped Markdown or JSON.

Next (v0.2): embedded Nuclei + vendored templates, SQLite-resumable engagements,
the methodology task-tree, and SARIF/PDF reports. See
[docs/ROADMAP.md](docs/ROADMAP.md).

## Quick start

```bash
# build
make build

# check your environment: what's ready, what's optional, and how to fix each gap
# (read-only — installs nothing, touches no targets)
./bin/tyto doctor

# validate an engagement file (no actions taken)
./bin/tyto engagement validate configs/engagement.example.yaml

# dry-run: the planner proposes, the guard rules, nothing executes (needs no model)
./bin/tyto run --engagement configs/engagement.example.yaml --dry-run

# full run against your OWN machine, no Ollama required — the "scripted" planner
# drives portscan -> httpprobe -> webcheck over the in-scope targets:
python -m http.server 8080 &   # give the web checks something to hit
./bin/tyto run --engagement configs/localhost.engagement.yaml --planner scripted \
    --report-format md --report-out report.md

# with a local model driving the plan instead of the demo script:
ollama pull qwen3:14b      # or let tyto auto-pick a size from your RAM
./bin/tyto run --engagement configs/localhost.engagement.yaml   # planner=ollama
```

`tyto authorize keygen` / `tyto authorize sign` produce the client Ed25519
authorization needed for high-risk or exploit-category actions.

## License

Apache-2.0. See [LICENSE](LICENSE).
