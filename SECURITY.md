# Security Policy

## Supported versions

Only the latest commit on `main` receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through [GitHub private vulnerability reporting](https://github.com/developingchet/vuln-hunt/security/advisories/new) (the **Security** tab, then **Report a vulnerability**).

Please include:
- the vuln-hunt commit and Claude Code version
- how you ran it (launcher or not, attestation or not, static or dynamic mode)
- steps to reproduce, and the impact you expect

GitHub keeps the report confidential until a fix is released.

## Response timeline

- Acknowledgement within 3 business days.
- A status update within 7 business days.
- A fix within 30 days of a confirmed reproduction. Critical issues (CVSS 9.0 or higher) are expedited on a best-effort basis.

Disclosure is coordinated with the reporter, who is credited unless they prefer otherwise.

## Scope

In scope:
- a scanned repository making a research worker run commands, write files or reach the network despite its tool restrictions
- the attestation helper, wrappers or installer executing a `git`, `node` or `claude` binary from inside the scanned repository
- the reporter writing outside `.vuln-hunt/runs/<runId>/`, or following a link or reparse point out of it
- strict provenance accepting a stale or altered attestation

Out of scope:
- false positives or missed vulnerabilities in scan results
- problems in Claude Code or the models themselves (report those to Anthropic)
- dynamic mode run without the external containment it asserts; see [ISOLATION.md](ISOLATION.md)
- prompt injection that only changes model output and does not cross a tool or file boundary
