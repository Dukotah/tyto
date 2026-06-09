# Ethics & legal use

`strix` is a tool for **authorized** penetration testing and security research.

## The one rule

**Only test systems you own or have explicit, written permission to test.**

Unauthorized access to computer systems is a crime in nearly every jurisdiction
(e.g. the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, and
equivalents worldwide). A tool does not make an action legal. *You* are
responsible for every packet `strix` sends on your behalf.

## How strix enforces this

`strix` is built so that authorization is structural, not advisory:

1. **No engagement, no action.** The engine will not run without a loaded
   engagement file that includes an authorization record (who approved the test,
   when, and a reference to the signed agreement).
2. **The Scope Guard is mandatory.** Every action the AI proposes is checked
   against the engagement's scope and rules before it can execute. Out-of-scope
   targets are refused. The model cannot disable or bypass the guard.
3. **Everything is logged.** An append-only audit trail records every decision
   and action, so you can prove what was and was not done.

These are safety rails, not a legal shield. Fill in the authorization record
truthfully and keep your signed scope agreement on file.

## Responsible disclosure

If `strix` finds a vulnerability in third-party software during authorized
testing, follow coordinated disclosure: report it to the vendor and give them
reasonable time to fix it before any public discussion.

## Reporting misuse or vulnerabilities in strix itself

See `SECURITY.md` (to be added) for how to report security issues in `strix`.
