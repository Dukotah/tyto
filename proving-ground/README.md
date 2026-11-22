# proving-ground — tyto capability benchmark

The **fitness function** for tyto's capability work. It runs tyto against a known
vulnerable local app, scores the findings against a fixed answer key, and writes a
reproducible scorecard. "How capable is tyto" stops being a vibe and becomes a
number that every change has to move.

## Files

| File | Role |
| --- | --- |
| `lab-vulnapp.py` | The target. A deliberately vulnerable app, **127.0.0.1:8080 only**, with a fixed planted vuln set. |
| `answer-key.json` | Ground truth: each planted vuln class + the strings that credit it as found. |
| `lab-northwind.engagement.yaml` | Self-attested, localhost-scoped engagement the run uses. |
| `bench.py` | The scorer: builds tyto, starts the lab, runs it, scores vs the key, writes `scorecard.json`. |
| `scorecard.json` | The latest result (tracked in git so deltas are visible). |
| `.bench/` | Rebuilt binary + per-run report/audit (gitignored). |

## Run it

```bash
python proving-ground/bench.py               # deterministic baseline (scripted planner, no model)
python proving-ground/bench.py --planner ollama --model llama3.1   # autonomous recall (needs a local model)
```

Exit `0` = ran and scored; exit `2` = infrastructure failure (build/lab/run) — the
loop treats those differently (a `2` is "unblock the harness", not "capability is 0").

## What it measures

- **coverage** — planted vuln classes tyto detected (found ≥1 matching finding).
- **validated** — classes where a matching finding was proven by direct observation
  (`validated=true`), not just flagged. This is the anti-false-positive number.
- **chain_depth** (0–3, coarse proxy for this single-host web lab) — 0 nothing · 1 a
  vuln detected · 2 a vuln validated · 3 high/critical impact proven. Real multi-stage
  depth needs multi-host labs (a backlog item).
- **raw / unmatched findings** — total findings and how many didn't map to a class
  (recon noise + anything the key doesn't model yet).

### Default planner is `scripted`, on purpose

`--planner scripted` drives a fixed recon→scan→exploit sweep with **no model**, so the
score is reproducible anywhere (including CI) and isolates *what the arsenal can detect
and prove* from *how well a model plans*. `--planner ollama` adds the autonomous-recall
dimension. A matcher credits a class on the finding's **content** (title/description/
evidence), never the tool name — running a tool is not detecting a vuln.

## Extending it (do both in one commit)

When you plant a new issue in `lab-vulnapp.py`, add its class to `answer-key.json` in
the **same commit**, or the score silently drifts. Keep match strings specific enough
not to cross-credit another class. Growing the lab (more vulns, more hosts) is how the
ceiling rises past 15 classes.

## Determinism note

Scored classes are stable run-to-run; the raw-finding count flickers by ±1 (a timing
flake on the `/backup/` path). Treat single-point moves with suspicion; re-run to
confirm. Tightening this flake is an early backlog item.
