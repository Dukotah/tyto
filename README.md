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

🚧 **Pre-alpha — architecture scaffold.** The skeleton, interfaces, Scope Guard,
and the plan→guard→execute loop are in place. Real tool adapters and the full
planner are next. This is the foundation, not the finished product.

## Quick start (once Go + Ollama are installed)

```bash
# 1. pull a local model
ollama pull llama3.1

# 2. build
make build

# 3. validate an engagement file (no actions taken)
./bin/tyto engagement validate configs/engagement.example.yaml

# 4. dry-run: the planner proposes, the guard rules, nothing executes
./bin/tyto run --engagement configs/engagement.example.yaml --dry-run
```

## License

Apache-2.0. See [LICENSE](LICENSE).
