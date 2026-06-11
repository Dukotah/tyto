# tyto — 100-feature power & automation roadmap

Goal: a more powerful, more fully-automated authorized pentest operator. Items are
grouped by theme. Status: `[x]` done, `[~]` partial/in-progress, `[ ]` planned.
The governing principle is unchanged: **deterministic Go enforces and drives the
methodology; the (untrusted) local model only selects**; tool output is quarantined
from the prompt.

## A. Reconnaissance & attack surface (1–15)
1. [x] JS endpoint/param/secret mining (`jsmine`)
2. [x] Asset seeding from scope before cycle 1
3. [x] `httpprobe` emits service assets (self-propagating graph)
4. [ ] Exposed `.git`/VCS metadata disclosure (`dotgit`)
5. [ ] API doc discovery (`/swagger.json`, `/openapi.json`, `/api-docs`)
6. [ ] GraphQL endpoint + introspection detection (`graphqlcheck`)
7. [ ] `security.txt` / `.well-known` discovery
8. [ ] robots.txt / sitemap.xml harvesting into the asset graph
9. [ ] Wayback/CommonCrawl historical URL ingestion (offline cache if present)
10. [ ] Certificate-transparency subdomain ingestion (offline feed)
11. [ ] DNS permutation/altdns brute (wordlist-driven)
12. [ ] favicon-hash technology fingerprinting
13. [ ] virtual-host / vhost fuzzing
14. [ ] cloud-bucket (S3/GCS/Azure) reference discovery from JS/HTML
15. [ ] headless-browser crawl for SPA XHR/DOM surface

## B. Vulnerability detection (16–35)
16. [x] Header/hardening, TLS, CORS, methods, secrets, JWT, CVE, templates (web battery)
17. [ ] Cookie flag audit (Secure/HttpOnly/SameSite) (`cookieaudit`)
18. [ ] Clickjacking (missing XFO/CSP frame-ancestors) dedicated check
19. [ ] Host-header injection / password-reset poisoning probe
20. [ ] Web cache deception / cache-poisoning header probe
21. [ ] HTTP request smuggling (CL.TE/TE.CL) detector
22. [ ] Mass-assignment / parameter-pollution probe
23. [ ] GraphQL field suggestion + batching abuse
24. [ ] Prototype-pollution (client + server reflection) probe
25. [ ] SSRF via URL params (paired with OOB collaborator)
26. [ ] Blind XSS injection (paired with OOB collaborator)
27. [ ] XXE detection on XML endpoints
28. [ ] Open S3/GCS bucket read/write test
29. [ ] Subdomain takeover (have `subtakeover`) + dangling-CNAME expansion
30. [ ] CRLF/header injection
31. [ ] Insecure deserialization signature probe
32. [ ] Rate-limit / brute-force resistance probe (lockout-aware)
33. [ ] Email spoofing (SPF/DKIM/DMARC) — have `emailsec`; add report scoring
34. [ ] Default/known-path admin panel discovery
35. [ ] CSP bypass/weakness analyzer

## C. Exploitation & impact (36–48)
36. [x] Error-based SQLi extraction (`sqliexploit`) + UNION dump
37. [x] Full Kali arsenal via approval-gated `kali` tool
38. [ ] OOB collaborator server (DNS+HTTP) for blind SSRF/RCE/SQLi/XSS
39. [ ] Authenticated multi-identity IDOR/BOLA differ (two sessions)
40. [ ] Reflected→stored XSS confirmation via headless render
41. [ ] Command-injection time-based blind confirmation
42. [ ] Path-traversal → file read PoC capture
43. [ ] JWT forgery (alg:none, weak secret crack) exploit step
44. [ ] Chained exploit synthesis (finding → next action graph)
45. [ ] Auto credential spraying (lockout-aware) across discovered logins
46. [ ] Session-fixation / cookie-replay PoC
47. [ ] CORS-with-credentials data-exfil PoC
48. [ ] Evidence capture: request/response pairs + screenshots per PoC

## D. Identity / auth / internal (49–58)
49. [x] login + session injection + provisioned creds
50. [x] SMB/LDAP/Kerberos adapters
51. [ ] Authenticated-scan mode: operator supplies cookie/API key up front
52. [ ] Multi-identity slot store (attacker/victim/admin)
53. [ ] BloodHound data collection adapter
54. [ ] NTLM-relay opportunity detection
55. [ ] Password-policy + lockout discovery before any spray
56. [ ] OAuth/OIDC misconfig checks (redirect_uri, PKCE, state)
57. [ ] SAML signature-wrapping probe
58. [ ] Credential→asset correlation engine (opaque-ID resolution at guard)

## E. Reasoning / the brain (59–70)
59. [x] num_ctx fix (no silent prompt truncation)
60. [x] Methodology frontier (Go-computed, ranked)
61. [x] Planner scratchpad (denied/done feedback)
62. [ ] Hypothesis ledger (Go-maintained, model tags selections)
63. [ ] CycleContext structured state doc (typed projection)
64. [ ] Go reflection pass (untested-class → new frontier entries)
65. [ ] Confidence scoring of findings (Go-computed signals)
66. [ ] Hybrid reasoner: Claude for triage/report/strategy on triggers
67. [ ] Per-finding false-positive adversarial re-check
68. [ ] Priority signals (cred found / vuln-class confirmed) in prompt
69. [ ] Tool-argument validation feedback loop (bad-arg → repair hint)
70. [ ] Model-agnostic Reasoner interface + pluggable backends

## F. State / memory / persistence (71–78)
71. [x] Concurrent asset/finding/credential store + quarantine projection
72. [x] Resumable snapshots (completed-action keys)
73. [ ] Persistent engagement DB (sqlstore) wired into runs
74. [ ] Differential/regression testing across runs (new vs regressed)
75. [ ] Asset-graph projection (host→service→finding), budget-capped
76. [ ] Cross-host systemic-finding clustering (one CVE, N hosts)
77. [ ] Long-run memory compaction (summarize old cycles)
78. [ ] Per-target evidence retention for the report

## G. Reporting (79–86)
79. [x] MD/HTML/SARIF/JSON + bug-bounty submission formats
80. [x] CVSS on findings
81. [ ] Per-finding remediation guidance
82. [ ] Executive summary section (auto-generated)
83. [ ] Per-finding reproduction steps (curl/PoC) in report
84. [ ] Severity-sorted, dedup-clustered report ordering
85. [ ] Confidence/likelihood column in findings
86. [ ] HackerOne/Bugcrowd-ready single-finding export

## H. UI / UX (87–93)
87. [x] Dashboard live timeline + run-bar + findings panel
88. [x] "Thinking" planning state + no-cache + auto-attach live feed
89. [ ] Severity-colored timeline events (not just findings panel)
90. [ ] Visual attack graph (asset → finding → next action)
91. [ ] Prominent per-tool approve/deny inline in the timeline
92. [ ] Run history view + per-run diff
93. [ ] `tyto watch` terminal live feed (done) + summary mode

## I. Safety / guardrails (94–97)
94. [x] Deterministic Scope Guard + signed grants + hash-chained audit
95. [x] Shell-RCE removed from planner; arsenal access via approval-gated `kali`
96. [x] Audit fsync (durability, fail-closed)
97. [ ] Grant ScopeVersion (mid-run scope-change TOCTOU close)

## J. Infra / ops / integrations (98–100)
98. [ ] MCP external-tool bridge (signed manifests, no recompile)
99. [ ] Constrained allow-listed Kali runner (broad reach, no free RCE)
100. [ ] Scheduled/recurring engagements + notification on new criticals

---
Implemented in the overnight batch are marked `[x]`/`[~]` above as they land.
Each implemented item ships with tests and a green build.
