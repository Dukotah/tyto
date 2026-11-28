# Blue-team features

tyto attacks on purpose so defenders can find out what they would have seen. These
features turn a run into output a SOC, detection engineer or security lead can act
on. All of them are derived from data tyto already records; none adds offensive
capability.

| Feature | What it answers | Where |
|---|---|---|
| Attack timeline | What exactly was done, when, to what — and where should we look? | `tyto purple timeline` |
| Detection coverage | Which of those actions did our tooling alert on, and how fast? | `tyto purple score` |
| ATT&CK Navigator layer | Which techniques are we blind to? | `tyto purple layer` |
| Traffic marker | Is this request the pentest or a real attack? | on by default |
| Defensive controls observed | Which controls actually pushed back? | every report |

The `purple` commands are offline post-processing over an audit log. They need no
engagement file and no model, and they never contact a target.

## The purple-team loop

```bash
# 1. Run the engagement as usual. The audit log is the ground truth.
tyto run --engagement acme.yaml            # writes ACME-001.audit.jsonl

# 2. Hand the SOC the timeline so they know the window and where to look.
tyto purple timeline --audit ACME-001.audit.jsonl --source 203.0.113.7 --out timeline.md

# 3. The SOC exports every alert that fired in that window (JSON, NDJSON or CSV).

# 4. Score it.
tyto purple score --audit ACME-001.audit.jsonl --alerts soc-alerts.csv \
    --resolve --layer-out coverage-layer.json --out coverage.md
```

`--source` is the address the client saw the traffic come from. The audit log
cannot know it (NAT, VPN, jump host), so the operator supplies it.

### Timeline

One row per **executed** action: start, end, target, tool, ATT&CK technique, and
the telemetry it should have produced ("burst of 404s from one source", "Event
4769 with RC4 for many SPNs"). Guard denials, refused approvals and dry-run
proposals are excluded — they never touched a target.

Formats: `--format md` (default), `json`, `csv` (for a SIEM lookup table).

The header states whether the audit hash chain verified. A timeline built from a
broken chain is still produced but says so, and must not be used as evidence.

### Detection coverage

`score` correlates the defender's alert export with the timeline.

- **Detected** — an alert naming the action's host fired between `--skew` before
  the action started and `--grace` after it ended (defaults 2m / 10m).
- **Weak** — an alert fired in the window but named no target. Reported
  separately; never counted in the coverage percentage.
- **Missed** — nothing fired. These are listed first, with where to look.
- **Not scored** — off-target activity (passive OSINT, offline CVE lookups) that
  no client sensor could have seen.

Each alert is credited to **one** action — the best match by target, then ATT&CK
technique, then time — so one noisy alert cannot mark a whole burst of concurrent
actions as detected.

The report also gives time to detect, coverage per technique and per target, and
**unattributed alerts**: alerts that fired during the test and match nothing tyto
did. Those are either false positives or something else happening on the network,
and are worth a look either way.

Alert fields are recognized by common names, so ECS/Elastic, Splunk CIM, Sentinel
and hand-made CSV all load without a mapping file:

| Meaning | Recognized as (case-insensitive) |
|---|---|
| time (required) | `@timestamp`, `timestamp`, `_time`, `time`, `TimeGenerated`, … — RFC 3339, `YYYY-MM-DD HH:MM:SS`, or epoch seconds/millis |
| target | `destination.ip`, `dest_ip`, `dest`, `host.name`, `hostname`, `host`, `url`, … |
| source | `source.ip`, `src_ip`, `src`, `client.ip`, … |
| rule name | `rule.name`, `signature`, `AlertName`, `name`, `title`, … |
| technique | `threat.technique.id`, `mitre_technique_id`, `technique`, … or a `T1234` id inside the rule name |

Timestamps with no zone are read as UTC unless `--alert-tz America/Chicago` says
otherwise. Rows with no readable timestamp are skipped with a warning.

If alerts name IP addresses and the engagement targeted hostnames, pass
`--resolve` so the two can be matched (this does DNS lookups at report time).

`--min-coverage 60` makes the command exit non-zero below that percentage, so a
scheduled run against a staging environment works as a detection regression test.

### Navigator layer

`tyto purple layer --audit run.audit.jsonl` shows the techniques exercised. With
`--alerts` (or `score --layer-out`) the layer is colored by coverage: red =
exercised and never detected, amber = partly, green = always. Load it at
<https://mitre-attack.github.io/attack-navigator/> with *Open Existing Layer*.

## Traffic marker

Every HTTP request tyto's native tools send to an **in-scope** host carries

```
X-Tyto-Engagement: <engagement id>
```

so defenders can separate the test from a real attack with one filter. The
header is only added for in-scope destinations (checked per request, redirects
included), so the engagement id is never sent to a third party.

```yaml
rules_of_engagement:
  traffic_marker:
    header: X-Bug-Bounty        # optional: a program-mandated header name
    value: researcher-handle    # optional: defaults to the engagement id
    # disabled: true            # for a covert detection exercise the client asked for
```

Whether the run was marked — or explicitly unmarked — is recorded in the audit
log and shown on the timeline.

**Not covered:** tools that shell out (nmap, nuclei, sqlmap, ffuf, hydra,
metasploit, `kali`) build their own requests, and non-HTTP protocols have no
header to carry. Use the timeline's source address and time windows for those.

## Defensive controls observed

Reports (Markdown, JSON, HTML) gain a section listing:

- **Controls that reacted** — rate limiting (429 / `Retry-After`), connections
  reset mid-test, 503 under load, and any WAF/CDN `wafdetect` fingerprinted — each
  with the exact signal and how many actions had already run against the host.
- **Targets with no visible reaction** — hosts that took exploitation, credential
  or high-volume scanning activity and never pushed back.

This is inference from how targets responded, not a control inventory. Refused
connections and timeouts are deliberately never reported as a control (a dead
service produces them too), and a control that only logs or alerts is invisible
from the attacker's side — that is what `purple score` measures.

The first reaction per host and kind is also written to the audit log
(`defense_observed`), so it appears on the timeline.

## Limits worth knowing

- **Timing granularity.** An action's window runs from when it was admitted to
  when its result was committed. Actions in one cycle run concurrently, so their
  windows overlap and are slightly wider than the traffic itself.
- **An action is not always an attack.** `webinject` against a page with no
  parameters sends no payloads but still appears as a T1190 action. Check the
  action's result in the audit log before chasing a "missed" injection.
- **Free-form tools.** `kali` runs arbitrary commands, so it has no fixed ATT&CK
  mapping; it is scored, but appears without a technique.
- **Clocks.** Correlation assumes the tyto host and the SIEM agree on the time to
  within `--skew`.
- **The mapping is tyto's.** `internal/attack` maps each tool to the technique its
  traffic resembles. A test fails the build if a registered tool has no mapping.
