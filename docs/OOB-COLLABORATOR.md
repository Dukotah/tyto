# OOB Interaction Collaborator (`internal/oob`)

Status: **package complete and green, deliberately NOT yet wired into the engine.**
This document describes the subsystem, its public API, and the precise deferred
plan for integrating it later — written so the integration can be done as one
isolated change without colliding with in-flight recon/vuln-tool work.

## What it is

`internal/oob` is tyto's **Out-of-Band (OOB) Interaction Collaborator**: a small,
hand-rolled DNS + HTTP listener the operator runs on infrastructure they control.
It exists to confirm the class of vulnerabilities that leave **no signal in the
response body** — blind SSRF, blind/stored XSS, OOB OS-command injection, and
OOB (DNS/UNC-exfil) SQL injection.

These bugs share one trait: the target's response looks identical whether the
payload fired or not. The only observable proof is the target's backend reaching
back out — resolving a DNS name or fetching a URL that only the probe could have
known. So an injection tool embeds a unique per-probe callback domain
(`<token>.<base-domain>`) in its payload, then later asks this package whether
that token was ever seen. A recorded callback ("Hit"), correlated to the probe's
token, is high-confidence out-of-band evidence the blind bug is real.

### Authority / quarantine boundary

The package **only LISTENS and CORRELATES** — it never initiates traffic and
widens no authority surface. It is the engine, upstream, that authorizes the
injection that makes a target call back here; this collaborator is a passive
sink. Consequently everything a `Hit` carries (`RemoteAddr`, request line,
User-Agent, the queried name) is attacker-influenced and **UNTRUSTED**. It must
land only in quarantined `state.Finding` fields (`Evidence`, `Repro`, `Tool`,
`Description`, `ID`, `Impact`, `CVSS` are all tagged `planner:"quarantined"`) —
never interpolated into a planner prompt.

## Design notes

- **No third-party deps.** The DNS server is hand-rolled on
  `net.ListenPacket("udp", ...)` with stdlib `encoding/binary` byte parsing
  (`dns.go`). No `miekg/dns` or any other DNS library — keeping `go.mod`
  untouched. Imports are stdlib only, plus `internal/state` (for `Finding`).
- **Deterministic tokens.** `mintToken` derives a 10-char lowercase base36 token
  from a monotonic counter via a golden-ratio LCG scramble — a pure function of
  the counter, so token values are reproducible and unit-testable, and a restart
  can't reissue a live token within a run.
- **Defensive DNS parsing.** Every inbound byte is untrusted: queries are parsed
  with bounds checks, compression pointers in QNAMEs are rejected, responses are
  capped at the 512-byte UDP limit, and malformed packets are silently dropped
  (never recorded as a hit, never panic).
- **Concurrency.** A single `sync.RWMutex` guards the token/hit maps; a separate
  `sync.Mutex` guards the listener handles so `Start`/`Close` don't race the
  serve goroutines. `Poll`/`Hits`/`Interactions` return defensive copies.

## Files

| File                | Role                                                            |
|---------------------|-----------------------------------------------------------------|
| `doc.go`            | Package doc (why/how/authority boundary).                       |
| `collaborator.go`   | **Core.** `Collaborator`, `New`, token store, HTTP listener, `Start`/`Close`/`serveHTTP`/`handleHTTP`, `Register`/`Record`/`Poll`/`Hits`/`Interactions`/`Lookup`/`MatchToken`. |
| `interaction.go`    | Core types: `Proto`, `Interaction`, `Hit`, `Config`, `mintToken`, `domainFor`, `urlFor`. |
| `dns.go`            | Hand-rolled UDP DNS server: `serveDNS`, `handleDNSPacket`, `parseDNSQuery`, `readDNSName`, `buildDNSResponse`. |
| `payload.go`        | Pure payload generators on `Interaction`: `SSRFTargets`, `BlindXSS`, `CmdInjection`, `SQLiOOB`, `dedupe`. |
| `correlate.go`      | `Confirm` / `ConfirmAll` → validated, Critical `state.Finding`s; per-class report wording + CVSS. |
| `collector.go`      | Thin env-driven convenience wrapper (`Collector`, `Default()` from `TYTO_OOB_*`). |
| `*_test.go`         | Unit + live-socket tests (token determinism, MatchToken, HTTP/DNS record paths, garbage-no-panic, Confirm/ConfirmAll, payload containment). |

## Public API

Construction / config:

```go
func New(cfg Config) *Collaborator
func (c *Collaborator) Config() Config
```

`Config` fields: `BaseDomain`, `PublicHost`, `HTTPAddr` (default `:8090`),
`DNSAddr` (default `:53535`), `Scheme` (default `http`). Empty fields are filled
by `withDefaults()`.

Lifecycle (binds TCP HTTP + UDP DNS listeners):

```go
func (c *Collaborator) Start(ctx context.Context) error   // first bind error, leaves nothing half-up
func (c *Collaborator) Close() error                       // idempotent
```

Probe issuance / correlation:

```go
func (c *Collaborator) Register(class, target, param string) *Interaction
func (c *Collaborator) Record(h Hit)                       // drops hits for unknown tokens
func (c *Collaborator) Poll(token string) []Hit            // copy
func (c *Collaborator) Hits() []Hit                        // copy of all
func (c *Collaborator) Interactions() []Interaction        // copy of all
func (c *Collaborator) Lookup(token string) (Interaction, bool)
func (c *Collaborator) MatchToken(s string) (string, bool) // pull a live token from a host/path
```

Payload generators (each returns a deduped `[]string` embedding the probe's
Domain/URL/Token):

```go
func (in Interaction) SSRFTargets() []string
func (in Interaction) BlindXSS() []string
func (in Interaction) CmdInjection() []string
func (in Interaction) SQLiOOB() []string
```

Confirmation (turns recorded callbacks into report findings):

```go
func (c *Collaborator) Confirm(token string) (state.Finding, bool) // Validated + Critical
func (c *Collaborator) ConfirmAll() []state.Finding                // one per hit token, token-sorted
```

`class` strings recognized by the report wording: `"ssrf"`, `"blind-xss"`,
`"cmd-injection"`, `"sqli-oob"` (anything else falls back to a generic
out-of-band profile). Every confirmed finding is `Severity = Critical`,
`Validated = true`, `Tool = "oobcheck"` — an OOB callback is unforgeable proof
the injected input reached a network-egress sink.

## DEFERRED INTEGRATION PLAN

This package is **intentionally unreferenced** by the rest of the tree right now.
`go build ./...` stays green because nothing imports it. Wiring it in touches
several **shared** files that other agents are concurrently editing (recon/vuln
tools register in `wiring.go`, add nodes to `catalog.json`, etc.), so the
integration was deliberately left out to avoid collisions. When the in-flight
work settles, do the integration as a single change in this order.

### Goal

An `oobcheck` blind-injection tool that:

1. **At run start**, starts a process- or run-scoped `Collaborator`
   (`New(cfg)` + `Start(ctx)`), config sourced from `TYTO_OOB_*` env or
   engagement config. If a listener can't bind, degrade to "OOB unavailable"
   (the rest of the run continues, just without OOB confirmation).
2. **During injection**, for each parameterized endpoint, calls
   `Register(class, target, param)` per class and injects the resulting
   `Interaction.SSRFTargets()` / `BlindXSS()` / `CmdInjection()` / `SQLiOOB()`
   payloads into params **alongside** the existing `webinject` payloads (same
   endpoint-fuzzing seam; OOB payloads add the out-of-band-only confirmation
   path on top of `webinject`'s in-band detection).
3. **After a delay** (callbacks are asynchronous — the backend may resolve/fetch
   seconds later), calls `ConfirmAll()` and emits the returned validated,
   Critical `state.Finding`s into engine state / the report.

### Shared files that step will need to edit (LEFT UNTOUCHED ON PURPOSE)

- **`cmd/tyto/wiring.go`** — add `r.MustRegister(oobcheck.New(collab))` in
  `defaultRegistry()` (or pass the run-scoped collaborator through a registry
  hook). The new `oobcheck` adapter lives under a *new*
  `internal/tool/builtin/oobcheck/` dir (no collision with existing tool dirs).
  Because OOB injection coerces the target into outbound requests, classify it
  in the exploitation tier (RiskHigh / `exploit` category) so the Scope Guard
  only lets it run with a verified authorization grant — mirror the
  `cmdexec`/`sqliexploit` registration block and the `defaultClassifier()`
  treatment.
- **`internal/methodology/catalog.json`** — add a methodology node so the
  planner selects it on parameterized endpoints, e.g. next to the existing
  `endpoint-injection` (`webinject`) node:
  ```json
  {
    "id": "endpoint-oob-injection",
    "name": "Out-of-band / blind injection (SSRF, blind XSS, OOB cmd/SQLi)",
    "phase": "exploitation",
    "category": "exploit",
    "tool": "oobcheck",
    "applies_to": {"asset_type": "endpoint"},
    "why": "confirm blind SSRF / blind XSS / OOB command & SQL injection via a collaborator callback when the response body shows no signal"
  }
  ```
- **`cmd/tyto/serve.go`** — add a run lifecycle hook: start the `Collaborator`
  when an engagement run begins (near `launchEngagement` / `runEngagement`,
  ~line 376/423) and `Close()` it in the run's `defer` cleanup
  (the `defer func(){...}()` at the top of `runEngagement`). The same hook should
  schedule the post-delay `ConfirmAll()` sweep so late callbacks are still
  captured before the report is finalized. (The CLI `run.go` path would need the
  symmetric hook if OOB is wanted outside the serve console.)

None of the above were edited as part of finalizing this package, specifically to
avoid colliding with the concurrent recon/vuln-tool changes landing in those same
shared files. The `oob` package is self-contained and ready; the wiring is a
clean, additive follow-up.
