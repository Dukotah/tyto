# Architecture

`tyto` is built around one idea: **separate strategy from authority.**

- The **Planner** (an AI) decides *what should happen next*.
- The **Scope Guard** (deterministic code) decides *whether it's allowed*.

The model is creative and fallible. The guard is dumb and incorruptible. By
keeping them apart, we get adaptive testing without ever trusting the model to
respect the client's boundaries. The guard is the part you can put in a contract.

> **Status:** this describes the *target* architecture. The Phase-0 scaffold has
> known gaps that **Phase 1 closes** (see [ROADMAP.md](ROADMAP.md)): the guard
> currently reads the model's self-declared risk/category (Phase 1 makes these
> tool-authoritative), does **not** yet enforce rate limits, and the audit log is
> plain append-only JSONL (Phase 1 adds the hash chain + fail-closed). Treat the
> guarantees below as the destination, not today's state.

## Data flow

```
engagement.yaml ──► engagement.Load ──► Engagement{ Scope, RoE, Objectives }
                                              │
                                              ▼
   ┌────────────────────────── engine.Run loop ──────────────────────────┐
   │                                                                       │
   │   state ──► planner.Plan(engagement, state) ──► []action.Action      │
   │                                                       │               │
   │                                  guard.Evaluate(action, engagement)   │
   │                                          │            │               │
   │                                       DENY          ALLOW             │
   │                                          │            │               │
   │                                   audit + feedback   tool.Execute     │
   │                                                       │               │
   │                                              action.Result ──► state  │
   │                                                                       │
   └───────────────────────────────────────────────────────────────────  ┘
                                   │
                            report.Generate
```

## Packages

### `internal/engagement`
The contract with the client, as data.

- `Engagement` — id, client, objectives, scope, rules of engagement, the
  authorization record (who approved, when, signature/reference).
- `Scope` — in-scope and out-of-scope targets (CIDRs, domains, URL prefixes).
  Out-of-scope always wins over in-scope.
- `RoE` (rules of engagement) — allowed risk ceiling, allowed/forbidden tool
  categories, time windows, global rate limits, intensity caps.

Loading validates the file and **refuses** anything missing an authorization
record. No auth, no run.

### `internal/guard` — the Scope Guard
A pure function: `Evaluate(action, engagement) Decision`. No I/O, no AI, fully
unit-testable. It is the single chokepoint every action passes through. It checks,
in order:

1. Target is in scope (and not explicitly out-of-scope). *(URL matching becomes
   scheme/host/path-segment aware in Phase 1, replacing naive prefix matching.)*
2. Action risk is at or below the ceiling — gated on the **tool-authoritative** risk
   (`max(tool.MaxRisk, perParamRisk)`), **not** the model's self-declared value (Phase 1).
3. The tool's category is permitted by the RoE — gated on the tool's authoritative
   category from a closed taxonomy; **unknown tool/category ⇒ deny** (Phase 1).
4. Time window is respected; **rate/concurrency limits are enforced** (Phase 1) and
   a high-risk/exploit action additionally requires a **verified authorization** (Phase 1).

A `Decision` is `Allow`, `Deny{reason}`, or `RequireApproval{reason}` (the three-state
verdict added in Phase 1, so the human gate lives *inside* the deterministic boundary).
Denials are logged **and** fed back to the planner so it can choose a different approach
— the model learns the walls by hitting them, but can never pass through.

### `internal/planner` + `internal/planner/llm`
The brain. `Plan(ctx, engagement, state) ([]action.Action, error)` builds a
prompt from the engagement context and current findings, asks the local model
for the next step(s) as structured JSON, and parses them into actions.

`llm.Client` is an interface so the backend is swappable. `llm.Ollama` talks to a
local Ollama server over HTTP — no data leaves the machine. A `llm.Mock` is used
in tests and `--dry-run`.

### `internal/tool`
The plugin surface. A `Tool` declares its name, category, and the maximum risk it
can reach, and implements `Execute(ctx, action) (Result, error)`. The `Registry`
maps tool names to implementations. Built-ins live under `internal/tool/builtin/`.

Tools are the *only* things that touch a target. They never decide whether they
may — the guard already did.

### `internal/engine`
The orchestration loop: plan → guard → execute → record → repeat, until an
objective is met, a budget is exhausted, or the operator stops. Owns concurrency,
rate limiting, and `--dry-run` (plan + guard, never execute).

### `internal/state`
The engagement's memory: discovered assets, findings (with severity + evidence),
and a timeline. It's what turns a sequence of tool runs into an adaptive
engagement — the planner reads it every cycle.

### `internal/report`
Turns findings into a report (Markdown first; JSON/SARIF later).

### `internal/audit`
Append-only JSONL log of every decision and action — the accountability record.
This is what you hand the client to prove you stayed in scope. *(Phase 1 makes it
**tamper-evident** — SHA-256 hash-chained, head anchored, fail-closed on write error,
with secret redaction — so the record is provably un-altered, not just append-only.)*

## Design rules

1. **The guard is never optional and never AI.** Every path to a tool goes
   through it.
2. **Tools don't make policy.** They execute; they don't judge.
3. **Local-first.** No required cloud dependency; the model runs on the operator's
   machine.
4. **Everything is auditable.** If it happened, it's in the audit log.
