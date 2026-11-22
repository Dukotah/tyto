# tyto Capability Audit

**What this is.** The living source of truth for how capable tyto is as an AI
penetration-testing tool, scored against a concrete rubric, with a ranked gap
backlog. The capability loop reads this and `LOOP-STATE.md`, moves the benchmark
number, and updates both. Last full pass: **2026-11-21**.

> Honesty rule: every "gap" here is backed by either a code citation or a benchmark
> miss. No aspirational scoring. If a number isn't measured, it says so.

---

## The rubric — what "industry-leading" decomposes into

tyto is scored on six axes. The first three are measured today by the benchmark
(`proving-ground/bench.py`); the last three are assessed from the code and tracked
toward measurement.

| Axis | Measured by | Today |
| --- | --- | --- |
| **1. Detection coverage** | benchmark `coverage` | **7/15 (46.7%)** |
| **2. Proof / validation** | benchmark `validated` (no false-positive credit) | **7/15 (46.7%)** |
| **3. Exploitation depth** | benchmark `chain_depth` 0–3 | **3/3** (single-host proxy — weak) |
| **4. Surface breadth** | arsenal inventory vs attack-surface map | web-deep; cloud/AD/k8s thin |
| **5. Autonomy / planning** | benchmark under `--planner ollama` | **unmeasured** (no local model here) |
| **6. Safety & governance** | design review | **ahead of field** (not the gap) |

Baseline captured in `proving-ground/scorecard.json`. The benchmark is the arsenal
*ceiling* (what a complete deterministic sweep detects); autonomy adds the question of
whether a model *chooses* to run the right tools.

---

## Where tyto is genuinely strong (keep, don't rebuild)

- **Safety & governance** — deterministic Scope Guard gating on authoritative tool
  metadata (`internal/guard`), signed-grant **and** self-attested authorization,
  tamper-evident hash-chained audit log, quarantined tool output with injection
  framing (`internal/state/quarantine.go`). Best-in-class; most competitors have none.
- **Proof-of-exploit** — `Validated` is set only on direct observation
  (`internal/state/finding.go:57`); `cmdexec`/`sqliexploit` prove RCE/SQLi rather than
  guess. Benchmark confirms: every found class is also *validated*.
- **Driveability** — MCP server (`cmd/tyto/mcp.go`) lets Claude drive the arsenal on a
  subscription; denials now return actionable redirects (structured `guard.DenyCode`).
- **Red + Blue + Purple in one binary** — `internal/blue` + `internal/purple`; the
  attack→prove-detection→draft-rule loop is differentiated.
- **54-tool web/recon/scan arsenal** — broad; the docs *understate* it (ROADMAP-100
  lists built tools as planned).

---

## Ranked gap backlog

Ordered by (benchmark points moved ÷ effort). Each item: the evidence, where it lives,
and which number it moves. Status: `[ ]` open · `[~]` in progress · `[x]` done.

### P1 — Chain discovered parameters into the injection tools  `[ ]`
**Moves: +3 classes** (sql-injection, reflected-xss, open-redirect).
Evidence: `webcrawl` reports "3 parameterized endpoint(s)" but `webinject`/`ssti`/
`sqliexploit` all report **"no query parameters to test"** — discovered endpoints
never reach the injection tools. This is the single highest-value gap: the arsenal can
exploit, it just isn't being fed targets. Fix the asset→action data flow so
parameterized URLs discovered by recon seed the injection tools.
Where: `internal/engine` (planning/seeding), the scripted sweep in
`internal/planner/llm/mock.go`, the injection tools' param intake.

### P2 — Invoke the full web battery in the methodology  `[ ]`
**Moves: +3 classes** (permissive-cors, dangerous-methods, graphql-introspection).
Evidence: `corscheck`, `httpmethods`, `graphqlcheck`, `cookieaudit`, `apidocs` all
exist in the 54-tool arsenal but the deterministic sweep never calls them, so a
CORS `*`+credentials, advertised PUT/DELETE/TRACE, and GraphQL introspection all go
undetected. Fix: expand the scripted methodology (and the `methodology.Recommend`
ranker) to cover the complete web battery; ensure `/api/graphql` is discovered.
Where: `internal/planner/llm/mock.go`, `internal/methodology`.

### P3 — secretscan reads HTML comments  `[ ]`
**Moves: +1 class** (admin-creds-comment). Evidence: `admin:Password123!` is planted
in an HTML comment; secretscan finds the AWS key and a generic secret but misses the
credential-in-comment. Add a credential-pattern pass over HTML comments.
Where: `internal/tool/builtin/secretscan`.

### P4 — Reliable sensitive-directory detection  `[ ]`
**Moves: +1 class + removes benchmark flake** (exposed-backup). Evidence: the
`/backup/` directory listing + `backup.sql` are detected only intermittently (raw
findings flicker 27–29). Make `webdiscover`/`dirfuzz` deterministically catch the
directory-listing + linked dump.
Where: `internal/tool/builtin/{webdiscover,dirfuzz}`.

### P5 — Stand up the autonomy tier of the benchmark  `[ ]`
**Unlocks axis 5.** Evidence: no local model in this environment, so autonomous recall
is unmeasured. Make the benchmark run under a local Ollama model (or an MCP-driven
pass) and record a second scorecard, so planning quality becomes a tracked number, not
a guess. Where: `proving-ground/bench.py` (+ env setup docs).

### P6 — Grow the lab toward real chain-depth  `[ ]`
**Fixes axis 3.** The single-host web lab caps `chain_depth` at a coarse 3/3. Add a
second lab host and a privilege/lateral step so depth measures recon→foothold→
priv-esc→lateral→loot for real. Where: `proving-ground/` (new lab targets + answer key).

---

## Strategic gaps (bigger than one loop iteration — scoped, not yet ranked in)

These are the distance to the funded leaders (e.g. XBOW-class autonomous bug-finding).
They become ranked P-items once the benchmark can measure them (P5/P6 first).

- **Exploitation chaining engine** — multi-stage, state-carrying exploit chains, not
  single-vuln proofs. The core of "autonomous pentester."
- **Modern surface breadth** — cloud (AWS/Azure/GCP enum + misconfig), containers/k8s,
  deep AD (BloodHound-class path-finding). Today: exposed-cred/S3 references only.
- **Scale / continuous ops** — scheduled, continuous, multi-host fleet validation.
- **Report polish** — CVSS everywhere, exec summary, retest workflow (have MD/SARIF/
  HTML/JSON).

---

## Honest placement

- As an **architecture + safety + orchestration platform**: ~75–85% of a strong
  product; *ahead* of the field on governance and the red/blue/purple + MCP combo.
- As a **measured autonomous offensive capability**: baseline **7/15 detection** on
  the first lab, exploitation-chaining and cloud/AD breadth largely absent, autonomy
  unmeasured. The fastest path up is P1→P4 (cheap, big coverage gains), then P5/P6 to
  start measuring the hard axes.
