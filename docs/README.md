# IronVise documentation

Start with **Getting started**, then read [integrations](guides/integrations.md)
before choosing how to connect your agent: recording an action and stopping it
are different things, and that page says which surface does which.

## Getting started

| Page | What it covers |
|---|---|
| [Quickstart](getting-started/quickstart.md) | Install, `make start` / `make demo`, your first audit |
| [Demo image](getting-started/demo.md) | The insecure-by-design demo container and what it shows |
| [Running securely](getting-started/running-securely.md) | The hardened configuration, compared with the demo |

## Guides

| Page | What it covers |
|---|---|
| [Integrations](guides/integrations.md) | CLI, SDKs, agent hooks, MCP proxy, recording proxy: what each sees and can stop |
| [Policies](guides/policies.md) | Writing and applying an audit policy, and the built-in SOC 2, PCI DSS and OWASP packs |
| [CLI reference](guides/cli.md) | Every `ironvise` subcommand and flag |
| [Configuration](guides/configuration.md) | Environment variables, build features, `settings.json` |
| [Desktop app](guides/desktop-app.md) | Every screen of the desktop app, and troubleshooting |
| [Scaling](guides/scaling.md) | Several instances on one PostgreSQL database |

## Reference

| Page | What it covers |
|---|---|
| [Architecture](reference/architecture.md) | Crates and repository layout |
| [Threat model](reference/threat-model.md) | What the guards catch, documented bypasses, known limits |
| [Sandboxing](reference/sandboxing.md) | Landlock, seccomp, Seatbelt, Job Objects, Docker, Firecracker, by platform |
| [Ledger schema](reference/schema.md) | Event layout and the canonical content hash |
| [Certificate format](reference/elc-spec.md) | The `.elc` format, enough to write your own verifier |
| [Testing](reference/testing.md) | What is tested and how to run it |
| [Compatibility](reference/compatibility.md) | Names kept from EctoLedger for compatibility |

## Compliance

| Page | What it covers |
|---|---|
| [EU AI Act Article 12](compliance/eu-ai-act-article12.md) | Record-keeping mapping (Articles 12 and 19) |
| [ISO/IEC 42001](compliance/iso42001.md) | Control mapping. Organisations are certified, not software. |

These mappings are aids, not legal advice or certification.

Release history is in [CHANGELOG.md](../CHANGELOG.md), and how to report a
vulnerability in [SECURITY.md](../SECURITY.md).
