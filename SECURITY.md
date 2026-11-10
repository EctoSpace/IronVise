# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.8.x | Yes |
| 0.6.x and older | No. Upgrade the server and both SDKs to 0.8.x. |

Security fixes ship as a new 0.8 patch release. Older lines are not patched.

## Reporting a vulnerability

Please do not open a public issue. Report privately by either:

- email to **ironvise@ectospace.com** with "SECURITY" in the subject, or
- GitHub private vulnerability reporting: **Security > Report a vulnerability** on this repository.

Include the version or commit, your configuration (ledger backend, build
features, guard on or off) and the smallest steps that reproduce the problem.
A sample certificate, ledger file or session export helps more than a
description of one.

## What to expect

- Acknowledgement within 5 working days.
- An initial assessment (is it a vulnerability, how severe) within 10 working days.
- A fix or a mitigation plan agreed with you before anything is disclosed. Credit
  is given in the release notes unless you prefer otherwise.

IronVise has one maintainer, so these are targets, not a contractual SLA.

## Scope

In scope: the `ironvise` binary and Observer API, the guard worker, the ledger
backends, the sandbox crates, the `.elc` certificate format and its verifiers
(CLI and browser), the Python and TypeScript SDKs, the agent hooks and the MCP
proxy. Anything that makes a verifier accept evidence it should reject is
especially welcome.

Out of scope: attacks that need write access to the ledger database itself (see
[docs/reference/threat-model.md](docs/reference/threat-model.md)), the
insecure-by-design demo configuration (`docker-compose.demo.yml`), and resource
exhaustion against an endpoint you are already authenticated to call.

IronVise has not had an independent security audit.
