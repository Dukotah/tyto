# Operating tyto with an external agent (operator runbook)

How to run a real, authorized engagement with a frontier model (e.g. Claude Code /
Opus) in the operator seat over MCP — in a way that keeps the work **scoped,
attested, auditable**, and that minimizes false interruptions from the agent host's
own safety systems.

This is hygiene, not evasion. The same practices that keep the agent host from
falsely flagging authorized work are the ones that make an engagement defensible to
a client and a court: execution inside a guarded process, authorization on file,
and loot kept in the audit trail instead of the open chat.

---

## 1. The one rule: execute through tyto, never inline

The operator (the model) is the **brain**. tyto's headless Kali is the **hands**.

- **DO** run every action as a `tyto_execute` / `tyto_kali` MCP call. It routes
  through `guard.Evaluate` -> approval gate -> `audit.Record` and runs inside
  tyto's process.
- **DO NOT** let the operator run offensive commands through its own generic shell
  (e.g. Claude Code's `Bash` tool) and narrate them inline. That (a) bypasses the
  Scope Guard entirely, (b) puts raw payloads in the open conversation stream, and
  (c) is the shape agent-host classifiers are tuned to interrupt.

If a command isn't going through a `tyto_*` tool, it isn't a tyto action and it has
no guard, no scope check, and no audit entry.

## 2. Keep payloads and loot out of the chat

Raw exploit strings, credential dumps, captured shells/tokens, reverse-shell
one-liners — these live in tyto's `tyto_findings` store and the `tyto_report`
output, which the operator *references*, not echoes.

The chat should read like *"ran sqliexploit against the scoped login form; tyto
recorded 1 confirmed finding (high)"* — not a paste of the payload or the dumped
rows.

## 3. Authorization is loaded first, every time

No engagement file loaded = no authorized scope = the guard denies everything of
consequence. Before any action:

1. Point the MCP server at the engagement for *this* job (see §5).
2. Confirm scope with `tyto_scope` as the first call of the session.
3. Only then plan and act.

Use `engagement.template.yaml` as the starting point for each new client.

## 4. The guard's prompts are features, not obstacles

- An out-of-scope target or over-ceiling risk is **DENY** — full stop. Don't try to
  route around it; change the engagement (with authorization) or don't do it.
- A mutating `kali` command is **BLOCKED until re-called with `approve: true`**,
  which surfaces as the agent host's own tool-permission prompt. That prompt is the
  per-action human kill switch and part of the audit story. Lean on it.

## 5. Session setup (per machine, once) + per-job engagement swap

Register the server at **user scope** so it persists across working directories
(local scope is tied to the directory it was added in, which is a common "it
disappeared" trap):

```bash
# one time, per machine — points at a SAFE DEFAULT (recon/scan, medium ceiling)
claude mcp add tyto -s user -- ~/.local/bin/tyto mcp \
  --engagement /ABS/PATH/TO/safe-default.engagement.yaml
```

To run a specific job, swap the engagement (its ceiling is what unlocks exploit
tools + mutating Kali) and restart the agent host so it reloads the tool set:

```bash
claude mcp remove tyto -s user
claude mcp add tyto -s user -- ~/.local/bin/tyto mcp \
  --engagement /ABS/PATH/TO/<this-job>.engagement.yaml
# then restart Claude Code / reconnect MCP — tools load at startup
```

Note (WSL): the agent host loads a server's tools at startup, so a freshly added
server's `tyto_*` tools do **not** appear mid-session — restart or reconnect.

## 6. Where real work runs

The agent-host sandbox usually has limited egress — external targets may resolve
but never connect. Run tyto on a host with real network egress (your own machine or
a VPS) for live external targets; loopback/self-hosted labs always work.

## 7. MCP tool surface

| tool            | what it does                                               |
|-----------------|------------------------------------------------------------|
| `tyto_scope`    | report the loaded engagement's scope, ceiling, categories  |
| `tyto_list_tools` | list the registered arsenal                              |
| `tyto_execute`  | run any registered tool (guard-gated, audited)             |
| `tyto_kali`     | run an arbitrary Kali command (mutating = approval-gated)  |
| `tyto_findings` | persistent findings memory                                 |
| `tyto_report`   | generate the client-style report from recorded findings    |

Every one routes through the same guard/approval/audit path as the built-in engine.
Full access never means bypass scope.
