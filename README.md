# tyto

**The governed operator for _authorized_ penetration testing — bring your own AI brain.**

`tyto` is the **body**, not the brain. A capable AI model — Claude / Opus and
other frontier agents over the **Model Context Protocol (`tyto mcp`)** — drives a
real engagement: planning, adapting to findings, and reasoning about *who hired
you, what they own, and what you're allowed to touch*. Every action the model
proposes is forced through a deterministic **Scope Guard** the model cannot
override, waits for human approval where it matters, and lands in a
tamper-evident **audit log**. The AI is the strategist; **tyto is the law, the
hands, and the record.**

> ⚠️ **tyto is for authorized testing only.** It will refuse to act against any
> target that is not explicitly in-scope for a loaded, acknowledged engagement.
> Using it against systems you do not own or have written permission to test is
> illegal. See [docs/ETHICS.md](docs/ETHICS.md).

---

## Why this is different

The incumbents are tools. The AI-pentest startups are a model you rent. `tyto` is
the **governed operator any brain plugs into** — and it owns the one thing a model
can't: provable, auditable boundaries.

| | Nmap / Nessus / Burp | XBOW / Burp AI (rented model) | tyto |
|---|---|---|---|
| Decides *what* to do next | You do | Their model | **Your** model, over MCP |
| Swap/upgrade the brain | n/a | No — locked in | Yes — model-agnostic |
| Knows the client's rules | In your head | Soft prompt | First-class, machine-enforced |
| Stays in scope | Your discipline | Soft prompt / sandbox | **Hard guard the AI can't bypass** |
| Human-in-the-loop approval | n/a | Limited | Gated actions wait for you |
| Tamper-evident audit | No | Closed | Hash-chained, fail-closed |
| Output | Raw tool data | Findings | Findings + reasoning + report |

The wedge: **the model was never the moat.** Frontier models change every few
months and you don't own them. What tyto owns — the Scope Guard, the audit, the
methodology, the approval console — is what makes *any* powerful brain legally and
defensibly runnable. That's the durable asset.

## The core loop

```
          ┌─────────────────────────────────────────────┐
          │  Engagement (scope, rules, objectives, auth)  │
          └───────────────────────┬─────────────────────┘
                                  │
              ┌───────────────────▼───────────────────┐
              │          AI brain (the operator)       │  frontier model
              │  "given state + rules, what next?"    │  via MCP (default)
              │                                        │  · local model = experimental
              └───────────────────┬───────────────────┘
                                  │ proposes Action(s)
              ┌───────────────────▼───────────────────┐
              │            Scope Guard (hard)          │  deterministic
              │   in-scope? allowed technique? rate?   │  AI cannot override
              └───────────────────┬───────────────────┘
                       allow      │      deny / require-approval
                                  │        ↳ human approves in console or client
              ┌───────────────────▼───────────────────┐
              │          Execution Engine              │
              │     runs Tool adapters, rate-limited   │
              └───────────────────┬───────────────────┘
                                  │ Results / Findings
              ┌───────────────────▼───────────────────┐
              │       State (assets, findings)         │ ──► back to the brain
              └───────────────────────────────────────┘
                                  │
                          Report generator
```

Every decision, action, approval, and result is written to an append-only,
hash-chained **audit log**.

## Architecture at a glance

| Package | Responsibility |
|---|---|
| `internal/engagement` | Engagement, scope, and rules-of-engagement model + loading |
| `internal/guard` | **Scope Guard** — deterministic allow/deny on every action |
| `cmd/tyto` (`mcp`) | **MCP server** — exposes the arsenal so a frontier model becomes the operator |
| `cmd/tyto` (`serve`) | **Web console** — watch the live feed and approve/deny gated actions |
| `internal/planner` | Optional built-in planner (experimental local-model path) |
| `internal/planner/llm` | Pluggable LLM backend (Ollama, OpenAI-compatible) |
| `internal/tool` | Tool-adapter plugin interface + registry (+ built-ins) |
| `internal/engine` | The orchestration loop tying it all together |
| `internal/state` | Knowledge store: assets, findings, timeline |
| `internal/report` | Findings → human report |
| `internal/audit` | Append-only audit log of decisions & actions |
| `cmd/tyto` | CLI entrypoint |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the deep dive and
[docs/ROADMAP.md](docs/ROADMAP.md) for what's built vs. planned.

## Two ways to drive it

- **MCP (default).** `tyto mcp` serves the arsenal to a frontier agent (Claude
  Code / Opus). The model is the operator; every call still passes the Scope
  Guard, approval gate, and audit log. This is the accurate path and the one we
  build for.
- **Web console.** `tyto serve` is the cockpit — watch the live feed and
  approve/deny gated actions in the browser while the brain drives.
- **Local model (experimental).** `tyto run --planner ollama` keeps a built-in
  local-model planner for air-gapped / sensitive engagements. A local model small
  enough for consumer hardware is a weaker strategist; it leans hard on tyto's
  deterministic scaffolding. Supported, not the headline.

## Status

🟢 **Working end to end.** The full ship line runs — **scan → fingerprint → safe
web checks → validated, client-ready report** — with every action forced through
the deterministic **Scope Guard** and recorded in a **tamper-evident, hash-chained,
fail-closed audit log**. High-risk/exploit actions require human approval (and/or a
client **Ed25519 authorization**). Reports export as grouped Markdown or JSON.

**Pivot in progress (MCP-first).** tyto is being reframed as the governed body any
AI brain drives. The full plan to a senior-pentester-level v1.0 — milestones,
acceptance gates, and benchmarks (GOAD, PortSwigger, Juice Shop) — is in
**[docs/ROADMAP-V1.md](docs/ROADMAP-V1.md)**. See also
[docs/ROADMAP-V2.md](docs/ROADMAP-V2.md) for the MCP-first capability track.

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
