# Project Layout

```
IronVise/
├── ironvise-win.ps1         # Windows one-click launcher
├── crates/
│   ├── core/               # Pure logic - no I/O; shared with the SP1 zkVM guest
│   │   └── src/
│   │       ├── hash.rs         # SHA-256 helpers (sha256_hex, compute_content_hash)
│   │       ├── merkle.rs       # Binary Merkle tree, inclusion proofs
│   │       ├── intent.rs       # ProposedIntent, ValidatedIntent
│   │       ├── policy.rs       # PolicyEngine, all policy structs, policy_hash_bytes
│   │       └── schema.rs       # SP1 zkVM protocol types: ChainEvent, GuestInput, GuestOutput
│   ├── guest/              # SP1 RISC-V reference source (proving withdrawn in 0.8)
│   │   └── src/main.rs     # Verifies genesis, hash chain, Merkle root, policy patterns
│   ├── guard_unikernel/    # Bare-metal guard unikernel (aarch64-unknown-none)
│   │   └── src/main.rs     # Standalone guard binary for hardware enclaves
│   ├── ledger-api/         # Pluggable LedgerBackend trait - standalone, no host dependency
│   │   └── src/lib.rs      # LedgerBackend, LedgerError, LedgerEvent, Session, AppendResult
│   ├── elc/                # The .elc certificate format and its offline verifier (no DB, network, or async runtime)
│   ├── elc-wasm/            # The .elc verifier compiled for the browser: a C-ABI wrapper over `elc`, no wasm-bindgen
│   ├── compliance/         # Anchoring & verifiable-credential crate
│   │   └── src/
│   │       ├── ots.rs                    # OpenTimestamps / Bitcoin anchoring
│   │       └── verifiable_credential.rs  # W3C VC-JWT issuance/verification (Ed25519 & P-256 / did:key)
│   ├── llm/                # LLM backends: Ollama, OpenAI, Anthropic (+ Ollama auto-setup)
│   ├── sandbox/            # Sandbox isolation + canonical output formatting
│   │   └── src/
│   │       ├── sandbox/    # one file per mechanism: seccomp, Landlock, Seatbelt, Job Objects, Docker, Firecracker
│   │       └── output.rs   # Canonical sandbox output formatter
│   └── host/               # Main application: ectoledger, guard-worker, verify-cert
│       ├── src/
│       │   ├── main.rs             # CLI arguments and entry point
│       │   ├── cli/                # The binary's start-up, offline commands, ledger opening, dispatch
│       │   ├── agent/              # Cognitive loop, one file per stage
│       │   │   ├── mod.rs          # AgentLoopConfig, run_cognitive_loop, the step
│       │   │   ├── preflight.rs    # Goal scan, cloud credentials, enclave start
│       │   │   ├── propose.rs      # Prompt, token budget, model call
│       │   │   ├── checks.rs       # Policy, tripwire and guard checks
│       │   │   ├── approval.rs     # Approval gates (terminal or dashboard)
│       │   │   ├── execute.rs      # Isolation tiers and the host executor
│       │   │   ├── observation.rs  # Output scanner and observation rules
│       │   │   ├── record.rs       # Signed events, webhooks, key rotation, credential
│       │   │   └── loop_detection.rs # Repeated-action detection
│       │   ├── ledger.rs           # Module root - re-exports postgres free functions
│       │   ├── ledger/
│       │   │   ├── postgres.rs     # PostgresLedger implementing LedgerBackend
│       │   │   └── sqlite.rs       # SqliteLedger implementing LedgerBackend
│       │   ├── server/             # Axum server (Observer dashboard and REST API)
│       │   │   ├── mod.rs          # AppState, index page, router assembly, CORS
│       │   │   ├── auth.rs         # Bearer-token auth middleware, Role RBAC
│       │   │   ├── redact.rs       # Redaction applied before events reach SSE
│       │   │   ├── stream.rs       # SSE event streaming, SSE_WAKEUP
│       │   │   ├── sessions.rs     # Session create/list/fetch, verifiable credentials
│       │   │   ├── chat.rs         # Direct LLM chat (no agent loop, guard, or tripwire)
│       │   │   ├── policies.rs     # Policy pack listing and editing
│       │   │   ├── exports.rs      # Certificates, reports, events JSON API
│       │   │   ├── approvals_api.rs # Human-in-the-loop approval queue
│       │   │   ├── settings.rs     # Config, status, tripwire settings, demo reset
│       │   │   ├── observability.rs # Prometheus metrics, security-metrics summary
│       │   │   ├── tokens.rs       # RBAC API token management
│       │   │   ├── webhooks_api.rs # Dynamic webhook / SIEM egress config
│       │   │   └── sdk.rs          # REST endpoints used by the Python/TS SDKs
│       │   ├── orchestrator.rs     # Multi-agent: Recon → Analysis → Verify + CrossLedgerSeal
│       │   ├── guard.rs            # Guard trait; in-process fallback
│       │   ├── guard_process.rs    # Spawns guard-worker, communicates via stdin/stdout JSON
│       │   ├── tripwire/           # Structural intent validation, one file per kind of check
│       │   ├── output_scanner.rs   # Hybrid scanner (13 regex + 8 exfil patterns + structural JSON/AST)
│       │   ├── policy.rs           # Host-side policy loader
│       │   ├── certificate.rs      # .elc: Merkle, OTS, Ed25519, optional SP1 ZK proof
│       │   ├── report.rs           # SARIF 2.1, HTML, GitHub Actions, GitLab CQ, certificate
│       │   ├── webhook.rs          # Async SIEM egress (JSON/CEF/LEEF); EgressKind enum
│       │   ├── signing.rs          # Ed25519 session keypair and per-event signing
│       │   ├── cloud_creds.rs      # Ephemeral cloud credential injection
│       │   ├── approvals.rs        # Approval gate state, session pause/resume
│       │   ├── red_team.rs         # Adversarial payload generation and defense testing
│       │   ├── snapshot.rs         # Agent state snapshots
│       │   ├── executor/           # run_command / read_file / http_get, one file each, and the program allowlist
│       │   ├── config/             # Settings from the environment and files, one module per concern
│       │   ├── metrics.rs          # Prometheus metrics and counters
│       │   ├── compensation.rs     # Compensating-action planner for rollback
│       │   ├── schema.rs           # Event types: Genesis, Thought, Action, Observation, …
│       │   ├── pool/               # DatabasePool (Postgres / SQLite dispatch), queries by concern
│       │   ├── db_setup.rs         # Embedded PostgreSQL bootstrap (pg-embed, PG_V15)
│       │   ├── pg_notify.rs        # PostgreSQL LISTEN/NOTIFY SSE fanout
│       │   ├── wakeup.rs           # Cross-instance session wakeup signalling
│       │   ├── secrets.rs          # Secure in-memory secret loading / zeroization
│       │   ├── sqlcipher.rs        # SQLCipher at-rest encryption (feature: sqlcipher)
│       │   ├── blocking.rs         # Blocking-task helpers
│       │   ├── commands/           # CLI command handlers: audit, serve, orchestrate, report, prove, anchor
│       │   ├── enclave/            # Guard-enclave IPC + remote attestation
│       │   ├── llm/                # Host-side LLM glue over crates/llm
│       │   └── bin/                # guard_worker.rs, verify_cert.rs
│       ├── migrations/         # PostgreSQL migrations (000001-000015)
│       │   └── sqlite/         # SQLite migrations (001-013)
│       ├── tests/
│       │   ├── adversarial_guards.rs           # 124 adversarial prompt injection tests (pure Rust, no I/O)
│       │   └── cross_platform_cmd_guards.rs    # Windows CMD + Linux host injection guard tests
│       └── policies/           # Policy packs: soc2, pci-dss, owasp-top10, iso42001
├── assets/
│   └── ironvise-mark.webp     # README logo and icon source (icons generated via npm run icon:generate)
├── scripts/
│   ├── test-integration.sh         # Integration test harness (Docker Postgres)
│   ├── setup-firecracker.sh        # Firecracker microVM setup (Linux/KVM)
│   └── provision-firecracker.sh    # Firecracker provisioning with custom prefix
├── gui/                    # Tauri 2 + Svelte 5 management GUI
│   ├── scripts/
│   │   └── generate-icons.mjs   # Generates Tauri icons from assets/ironvise-mark.webp
│   ├── src/
│   │   ├── App.svelte              # Root layout - three-tab glassmorphic shell
│   │   └── lib/
│   │       ├── Sidebar.svelte      # Navigation sidebar
│   │       ├── Dashboard.svelte    # Test Prompt panel + live metrics
│   │       ├── LiveDashboard.svelte # Real-time streaming agent activity view
│   │       ├── MetricsView.svelte  # Prometheus metrics tab
│   │       ├── Sessions.svelte     # Session browser, event viewer, certificate export
│   │       ├── PolicyEditor.svelte # TOML policy editor with live validation
│   │       ├── TripwireView.svelte # Tripwire config (paths, domains, commands, justification)
│   │       ├── TokensView.svelte   # RBAC API token management
│   │       ├── WebhooksView.svelte # Webhook/SIEM egress configuration
│   │       ├── ObserverPanel.svelte # Embedded Observer dashboard panel
│   │       ├── TestingView.svelte  # Adversarial testing interface
│   │       ├── DevHub.svelte       # Developer reference and integration guides
│   │       ├── SetupWizard.svelte  # First-run onboarding wizard
│   │       └── Settings.svelte     # LLM backend and model settings
│   └── src-tauri/          # Tauri 2 Rust backend (~37 HTTP-proxy commands in commands.rs + 6 in setup.rs)
├── sdk/
│   ├── python/             # Python SDK - pip install -e ./sdk/python
│   │   └── ironvise_sdk/       # Complete Python implementation
│   │       ├── client.py       # LedgerClient (httpx + pydantic)
│   │       ├── models.py       # Session, LedgerEvent, AppendResult, MetricsSummary
│   │       ├── langchain/      # LedgerCallbackHandler (BaseCallbackHandler)
│   │       └── autogen/        # LedgerHook (AutoGen tool wrapper)
│   └── typescript/         # TypeScript SDK - built from source (registry is 0.6.3)
│       └── src/
│           ├── client.ts       # IronViseClient (native fetch, zero dependencies)
│           ├── models.ts       # Typed interfaces
│           └── index.ts        # Barrel export
├── docs/
│   ├── cli.md              # CLI reference (verified against clap definitions)
│   ├── configuration.md    # Feature flags and environment variables
│   ├── elc-spec.md         # .elc audit certificate v1 specification
│   ├── integrations.md     # Enforcement vs observation coverage matrix
│   ├── quickstart.md       # Quickstart guide
│   ├── running-securely.md # Production deployment checklist
│   ├── schema.md           # Event schema and migration reference
│   ├── security-findings-open.md # Public register of open/closed findings
│   ├── testing.md          # Test suite and CI workflow reference
│   ├── threat-model.md     # Threat model and adversarial guard coverage
│   ├── iso42001.md         # ISO 42001:2023 control mapping reference
│   ├── eu-ai-act-article12.md # EU AI Act Article 12 & 19 mapping
│   ├── sandbox-parity.md   # Sandbox feature parity matrix
│   └── sandbox-verification-report.md  # Sandbox verification test results
└── audit_policy.example.toml   # Annotated example policy file
```

---

