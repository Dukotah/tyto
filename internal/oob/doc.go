// Package oob is tyto's Out-of-Band Interaction Collaborator: a small DNS + HTTP
// listener the operator runs on infrastructure they control, used to confirm a
// class of vulnerabilities that leave NO signal in the response body.
//
// WHY this exists. Blind SSRF, blind XSS, OOB OS-command injection, and OOB /
// DNS-exfil SQL injection all share one trait — the target's response to the
// injected request looks identical whether the payload fired or not. The only
// observable proof is the target's backend reaching back out: resolving a DNS
// name or fetching a URL that only the probe could have known. So instead of
// pattern-matching a response, an injection tool embeds a unique per-probe
// callback domain (<token>.<base-domain>) in its payload, then asks this package
// whether that token was ever seen. A recorded callback ("Hit"), correlated to
// the probe's token, is high-confidence out-of-band evidence the blind bug is
// real.
//
// HOW it works. New mints a Collaborator over a Config (the public base domain,
// the host its A record points at, and the HTTP/DNS listen addresses). Register
// mints a token, builds the callback Domain and URL, records the Interaction, and
// returns it for the tool to inject. Start binds a TCP HTTP listener and a UDP
// DNS listener: the HTTP side records any request whose Host subdomain or path
// carries a known token; the hand-rolled DNS side (a sibling file) answers A
// queries for the base zone and records the lookup. Poll / Hits / Interactions
// let a tool correlate callbacks back to the probe that caused them.
//
// AUTHORITY boundary. This package only LISTENS and CORRELATES — it never
// initiates traffic and widens no authority surface. It is the engine, upstream,
// that authorizes the injection which makes a target call back here; this
// collaborator is a passive sink. Consequently, everything a Hit carries
// (RemoteAddr, request line, User-Agent, the queried name) is attacker-influenced
// and UNTRUSTED: it must land only in quarantined Finding fields the quarantine
// boundary keeps out of any planner prompt — never interpolated as instructions.
package oob
