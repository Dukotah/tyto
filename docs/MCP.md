# MCP server — drive tyto with an external agent (Claude Code / Opus)

`tyto mcp` exposes the arsenal over the **Model Context Protocol** (stdio
JSON-RPC 2.0) so an external agent becomes the operator: it plans, adapts, and
chains tools natively, while tyto stays the **body**. Every tool call is routed
through the **same deterministic Scope Guard, approval gate, and audit log** the
autonomous engine uses — so "full access" never means "bypass scope." The guard
is the law; the agent cannot override it.

This is the supervised way to put a frontier model in the operator's seat
instead of the local planner, when offline operation isn't required.

---

## Why

The built-in planner is bounded by whatever **local** model you can run. The MCP
server replaces that brain with the agent on the other end of the protocol
(e.g. Claude Code driven by Opus), without weakening any safety invariant:

- unknown tool → **DENY** (fail closed)
- out-of-scope target → **DENY**
- risk / category / time / authorization over the ceiling → **DENY**
- a `RequireApproval` verdict, or a tool's `ApprovalGater` (the `kali`
  arbitrary-command tool for any non-read-only command) → **BLOCKED** until a
  human authorizes, relayed as `approve: true`; the guard re-checks scope/risk
  on the approved run
- every decision, action and result is written to the tamper-evident audit log

## Run it

```bash
tyto mcp --engagement path/to/engagement.yaml [--exec <backend>] [--audit <path>]
```

- `--engagement` (required) — the engagement YAML. Its scope and rules of
  engagement are what the guard enforces for the whole session.
- `--exec` — where shell-out tools run: empty = host (auto-detects a Kali WSL
  distro on Windows), or `wsl:<distro>`. Same resolution as `tyto run`.
- `--audit` — audit log path (default `<engagement-id>.mcp.audit.jsonl`).

stdout carries **only** protocol frames; all human/log output goes to stderr, so
the channel is never corrupted.

## Wire it into Claude Code

```bash
claude mcp add tyto -- /path/to/tyto mcp --engagement /path/to/engagement.yaml
```

Then restart the session; the `tyto_*` tools load and the agent can drive an
engagement. Point it at a different engagement by removing and re-adding with a
new `--engagement`.

> Build note (WSL): `go` may only be on the Windows side. Cross-compile a Linux
> binary (`GOOS=linux GOARCH=amd64`) and run it from the native filesystem — a
> binary on a `/mnt/c` DrvFs mount fails to exec. See [WSL-KALI.md](WSL-KALI.md).

## The six tools

| Tool | Purpose |
|---|---|
| `tyto_scope` | Show the engagement: client, in-scope targets, risk ceiling, allowed/forbidden categories, authorization mode. Read first — it's the boundary every action is checked against. |
| `tyto_list_tools` | List the arsenal with each tool's category + risk ceiling, and whether it forces human approval. |
| `tyto_execute` | Run one registered tool against an in-scope target. Passes the guard, then returns output + findings + assets + credentials. Gated actions return `BLOCKED` until re-called with `approve: true`. |
| `tyto_kali` | Run an **arbitrary** command in the Kali backend — the full distro, for anything the built-in tools don't cover. Read-only commands run within the ceiling; any state-changing command is forced through human approval. Contained to the Kali VM, never tyto's own host. |
| `tyto_findings` | Dump accumulated assets, findings (with severity) and recovered credentials (redacted). The agent's persistent memory across the run. |
| `tyto_report` | Render the markdown penetration-test report from everything discovered so far. |

### `tyto_execute` arguments

```json
{ "tool": "nmapscan", "target": "10.0.0.5", "params": {"ports": "1-1000"},
  "rationale": "service enumeration", "approve": false }
```

`tool` and `target` are required. `params` is a string→string map of
tool-specific options. `rationale` is recorded in the audit log and report.
`approve: true` authorizes an action the guard gated for approval (human
sign-off relayed). Risk and category are taken from the **authoritative** tool
metadata; the agent's self-declared values never gate.

### Human kill-switch

Two independent gates stand between the agent and a dangerous action:

1. **tyto's guard** — deterministic scope/risk/category/time/authorization,
   fails closed, cannot be argued with.
2. **The host's tool-permission prompt** — Claude Code asks the human before the
   agent may call `tyto_kali` (and any other tool the human gates), which is how
   a human sign-off reaches an approval-gated action.

## Execution path (identical to the engine)

Each `tyto_execute` / `tyto_kali` call walks the same order as the engine's
admit → execute → commit:

```
resolve tool  →  guard.Evaluate  →  [approval gate]  →  tool.Execute
                      │                   │                  │
                   fail closed       BLOCKED unless      fold findings/assets/
                   on DENY           approve:true        creds into state
                      └─────────────── audit.Record every step ──────────────┘
```

## Example session

```
tyto_scope                              → read the boundary
tyto_list_tools                         → see the arsenal
tyto_execute {dnsenum, example.com}     → recon, folds assets into state
tyto_execute {httpprobe, http://…}      → fingerprint
tyto_execute {nucleiscan, http://…}     → scan
tyto_kali {target, "nmap -sV …"}        → arbitrary tool (approval-gated)
tyto_findings                           → review accumulated knowledge
tyto_report                             → client-style markdown report
```

## Safety & scope

The MCP server changes **who** plans, not **what is permitted**. It refuses to
act against any target not explicitly in-scope for the loaded engagement, exactly
like the rest of tyto. See [ETHICS.md](ETHICS.md). Authorized testing only.
