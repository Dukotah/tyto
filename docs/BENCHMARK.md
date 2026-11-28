# Benchmark

`tyto bench` answers one question with numbers instead of opinion: **did that
change make tyto — or the model driving it — better at finding real
vulnerabilities?**

It has two parts: a deliberately vulnerable lab with a known answer key, and a
scorer that grades any run against it.

## The lab

`internal/bench/lab` is a small web application ("Northwind Billing Portal")
built into the tyto binary. It binds loopback only and executes nothing: the
command- and template-injection endpoints are simulations.

It plants **21 vulnerabilities** in three tiers:

| Tier | Count | What it takes | Examples |
|---|---|---|---|
| surface | 13 | one passive or low-risk check | missing headers, exposed `.env` / `.git`, secrets in a JS bundle, GraphQL introspection, weak JWT secret |
| injection | 5 | an active payload on the right parameter | reflected XSS, SQL injection, open redirect, template injection, command injection |
| chain | 3 | more than one step, or reading between the lines | a debug endpoint listed only in `robots.txt`; invoices readable by id; credentials in an HTML comment that log in as admin and unlock a customer export |

and **6 decoys** — endpoints that look like the vulnerable ones but are
implemented correctly (`/safe/search` encodes output, `/safe/item` parses an
integer, `/.env.example` holds placeholders, …). Reporting a decoy is a false
positive. Without decoys, a tool that flags everything would score perfectly.

## What is measured

| Metric | Meaning |
|---|---|
| Found | planted vulnerabilities the run reported, overall and per tier |
| Proven | of those, how many are backed by a finding a tool directly observed, rather than inferred or asserted by the operator |
| False positives | decoys reported as vulnerable |
| Precision | found ÷ (found + decoys hit) |
| Actions, actions per find, duration | what it cost, from the audit log |
| Unscored findings | non-informational findings that match neither a planted item nor a decoy — review these by hand |

The scorer reads two ordinary tyto artifacts: the JSON report (what was claimed)
and the audit log (what it took). A finding is credited by matching its text —
title, target, description, evidence, repro — against the answer key, so a
tool's terse title and an agent's prose are scored the same way.

## Reference runs

```bash
make bench
# or
tyto bench run --planner oracle   --out ceiling.json
tyto bench run --planner scripted --out floor.json --cycles 6
```

`bench run` starts the lab on a free loopback port, runs a full engagement, and
prints a scorecard.

- **`oracle` — the tool ceiling.** Every relevant built-in tool, aimed at exactly
  the right URL. Whatever it misses is a **tool gap**: no planner can find it
  with today's tools.
- **`scripted` — the floor.** The fixed no-model demo script, which only ever
  tests the base URL.

Current baseline (answer key v1):

| Run | Found | surface | injection | chain | False positives |
|---|---|---|---|---|---|
| scripted (floor) | 6 of 21 | 6 of 13 | 0 of 5 | 0 of 3 | 0 |
| oracle (ceiling) | 18 of 21 | 12 of 13 | 5 of 5 | 1 of 3 | 0 |

The three items the oracle misses have no tool that reports them: the
credentials in the HTML comment, the debug endpoint, and the admin takeover
chain. Only an operator that reasons about what it sees can score those — which
is what makes them the measure of the model rather than of the tools.

**Reading a model's score.** Between floor and ceiling is how much of the tools'
potential its planning realizes. Above the ceiling is reasoning the tools cannot
do. False positives are claims it could not back up.

## Benchmarking a model

### A local or OpenAI-compatible model as the planner

```bash
tyto bench run --planner ollama --model qwen3:14b --out qwen14.json
tyto bench run --planner openai --model my-model --llm-base-url http://localhost:1234/v1 --out mine.json
```

The in-engine planner can only select tools; it cannot record its own
conclusions. Its best possible score is therefore the oracle ceiling.

### An external agent over MCP (e.g. Claude Code)

This is the configuration that can exceed the ceiling, because the agent can
chain steps and record what it works out.

```bash
# 1. Serve the lab and write its engagement file.
tyto bench lab --addr 127.0.0.1:8080 --engagement-out /tmp/bench/lab.yaml

# 2. In an EMPTY working directory, register tyto with the agent.
cd /tmp/bench
claude mcp add tyto -- /path/to/tyto mcp --engagement /tmp/bench/lab.yaml \
    --audit /tmp/bench/audit.jsonl --report-out /tmp/bench/report.json

# 3. Start the agent and give it proving-ground/bench-operator-prompt.md verbatim.

# 4. When it stops, score the run.
tyto bench score --report /tmp/bench/report.json --audit /tmp/bench/audit.jsonl \
    --label opus-mcp --out opus-mcp.json
```

Delete `audit.jsonl` and `report.json` between runs; the audit log appends.

Rules for a result you can trust:

- **Keep the answer key away from the agent.** Run it from an empty directory,
  not from a checkout of this repository — `internal/bench/lab` is the answer
  key, and an agent that can read it is not being measured.
- **Use the same prompt every time.** `proving-ground/bench-operator-prompt.md`
  is the fixed one. Changing the prompt is itself an experiment; label it.
- **Run it more than once.** Model runs vary. Do at least three per
  configuration and compare the middle result, not the best.
- **Change one thing at a time** — the model, the prompt, or the tooling.

## Comparing

```bash
tyto bench compare before.json after.json
```

prints the metric deltas and, more usefully, the items that changed: newly
found, regressed, and newly proven. Results carry the answer-key version, and
`compare` warns when two results used different keys.

## A regression gate

`go test ./cmd/tyto -run TestBench` runs the oracle and scripted configurations
hermetically. It fails if a built-in tool stops finding its planted
vulnerability or starts reporting a decoy — so a tool can no longer silently
stop working. (It already caught two: see the history of
`internal/tool/builtin/ssti` and `login`.)

## Limits

- **One small web app.** The lab has no network services, Active Directory,
  cloud, or multi-host movement. A good score here does not mean a good score on
  a real estate; it means the web path works. Treat it as a floor on capability,
  not a certificate.
- **Text matching.** Credit is assigned by pattern-matching finding text. An
  agent that describes a real finding in unusual words can be under-credited;
  check "Unscored findings" before concluding it missed something.
- **Known answers leak.** Once a model has been tuned against this lab, its
  score stops meaning much. Bump `lab.Version` and change the planted items when
  that happens.
- **Chain findings are asserted, not proven.** Operator-recorded findings are
  credited as found but not proven, because no tool re-verified them.

## Extending the lab

Add the endpoint to `internal/bench/lab/lab.go`, its entry to `planted` (or
`decoys`) in `answers.go`, an oracle step if a tool should find it, a case in
`TestLabBehavesAsDocumented`, and bump `lab.Version`.
