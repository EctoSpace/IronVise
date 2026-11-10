.PHONY: test-e2e test-mac test-api test-sdk test-scripts demo-mcp start setup rebuild backend demo reset-db env-file gui-deps verify test test-qa test-elc test-blake3 mutants wasm-verifier test-wasm-verifier tamper-suite test-integration test-enclave test-enclave-hv test-sqlcipher check-python-wheel check-upgrade check test-gui-unit check-guards check-tauri check-trailers clean help demo-hook demo-hook-record

# ── Platform detection ───────────────────────────────────────────────────────
# Windows (MSYS/MINGW/CYGWIN) keeps its one-click PowerShell launcher; on
# macOS/Linux the targets below call cargo and npm directly. There is no Unix
# launcher script: the Tauri GUI starts its own embedded Axum backend
# (gui/src-tauri/src/embedded.rs), so "start backend + GUI" is a single
# command and the extra indirection earned nothing.
UNAME_S := $(shell uname -s)
IS_WINDOWS := $(findstring MINGW,$(UNAME_S))$(findstring MSYS,$(UNAME_S))$(findstring CYGWIN,$(UNAME_S))

# Embedded-PostgreSQL data directory, mirroring db_setup.rs::app_data_dir().
ifeq ($(UNAME_S),Darwin)
  ECTO_DATA_HOME := $(HOME)/Library/Application Support/ectoledger
else
  ECTO_DATA_HOME := $(HOME)/.local/share/ectoledger
endif

CARGO ?= cargo
NPM   ?= npm

start: ## Start the desktop GUI (embeds the backend). Windows: uses the PS1 launcher
ifneq (,$(IS_WINDOWS))
	pwsh -File ./ironvise-win.ps1
else
	@$(MAKE) --no-print-directory gui-deps
	@echo "Starting IronVise desktop GUI (backend runs in-process)…"
	@echo "Use the desktop window - do not open http://localhost:1420 in a browser."
	cd gui && BROWSER=none $(NPM) run tauri dev
endif

setup: ## Build the CLI binary and install GUI dependencies (no servers started)
ifneq (,$(IS_WINDOWS))
	pwsh -File ./ironvise-win.ps1 -setup
else
	@command -v $(CARGO) >/dev/null || { echo "error: cargo not found - install Rust from https://rustup.rs/"; exit 1; }
	@$(MAKE) --no-print-directory env-file
	$(CARGO) build --release -p ectoledger
	@$(MAKE) --no-print-directory gui-deps
	@echo ""
	@echo "Setup complete."
	@echo "  CLI binary : target/release/ironvise"
	@echo "  Config     : .env (edit to choose your LLM backend)"
	@echo "  Next       : make start   (desktop GUI)"
	@echo "               make backend (server only, http://127.0.0.1:3000)"
	@echo "               make demo    (SQLite + demo mode, no LLM required)"
endif

rebuild: ## Force a rebuild of the CLI binary, then start the GUI
ifneq (,$(IS_WINDOWS))
	pwsh -File ./ironvise-win.ps1 -rebuild
else
	$(CARGO) clean -p ectoledger
	$(CARGO) build --release -p ectoledger
	@$(MAKE) --no-print-directory start
endif

backend: ## Start the Observer backend only, no GUI (127.0.0.1:3000)
ifneq (,$(IS_WINDOWS))
	pwsh -File ./ironvise-win.ps1 -backendOnly
else
	@# Default to the zero-infrastructure SQLite ledger so a fresh clone works
	@# with no setup; export DATABASE_URL yourself to use PostgreSQL instead.
	DATABASE_URL="$${DATABASE_URL:-sqlite://ectoledger.db}" \
		$(CARGO) run --release -p ectoledger -- serve
endif

demo: ## Zero-config demo: SQLite ledger, demo mode, no Docker or Postgres needed
	ECTO_DEMO_MODE=1 DATABASE_URL=sqlite://ectoledger-demo.db \
		$(CARGO) run --release -p ectoledger -- serve

demo-mcp: ## The MCP proxy in front of the official filesystem MCP server (needs npm)
	@$(CARGO) build --bin ironvise
	@bash examples/demo/mcp-proxy-demo.sh

demo-hook: ## Run the deny-and-tamper demo end to end (asserts at every step)
	@$(CARGO) build --bin ironvise
	@bash examples/demo/hook-denial-demo.sh

# ASCIINEMA is resolved rather than assumed: pip and Homebrew install asciinema
# in ways that give you one invocation form and not the other, so checking for
# the CLI and then calling the module would pass the guard and fail the recipe.
ASCIINEMA := $(shell command -v asciinema 2>/dev/null \
	|| { python3 -c "import asciinema" 2>/dev/null && echo "python3 -m asciinema"; })

demo-hook-record: ## Re-record docs/assets/hook-denial-demo.{cast,gif}
	@test -n "$(ASCIINEMA)" \
		|| { echo "error: asciinema not found - pip install asciinema"; exit 1; }
	@command -v agg >/dev/null \
		|| { echo "error: agg not found - cargo install --git https://github.com/asciinema/agg"; exit 1; }
	@$(CARGO) build --bin ironvise
	DEMO_PACE=1 $(ASCIINEMA) rec docs/assets/hook-denial-demo.cast \
		--overwrite --cols 100 --rows 34 -c "bash examples/demo/hook-denial-demo.sh"
	agg --theme monokai --font-size 15 \
		docs/assets/hook-denial-demo.cast docs/assets/hook-denial-demo.gif

reset-db: ## Wipe the embedded PostgreSQL data directory (fixes auth failures after a partial first run)
	@echo "Removing $(ECTO_DATA_HOME)/postgres and postgres-demo…"
	@rm -rf "$(ECTO_DATA_HOME)/postgres" "$(ECTO_DATA_HOME)/postgres-demo"
	@echo "Done. The next launch will re-initialise the database."

# Internal: create .env from the template on first setup. The docs promise a
# .env exists after first launch (the removed launcher scripts used to write
# one); this keeps that promise without resurrecting them.
env-file:
	@if [ ! -f .env ]; then \
		cp .env.example .env && \
		echo "Created .env from .env.example - edit it to choose your LLM backend."; \
	fi

# Internal: install GUI npm dependencies only when they are missing.
gui-deps:
	@command -v $(NPM) >/dev/null || { echo "error: npm not found - install Node.js 20+ from https://nodejs.org/"; exit 1; }
	@if [ ! -d gui/node_modules ]; then \
		echo "Installing GUI dependencies (first run only)…"; \
		cd gui && $(NPM) install; \
	fi

# Run this before pushing. `make test` alone is not enough: it builds only the
# targets the tests need, so a caller that no longer compiles - an #[ignore]d
# integration test, a bench, an example - passes here and breaks the tree for
# everyone else. `--all-targets` is what catches that.
verify: ## Pre-push gate: formatting, lints, and a full --all-targets build
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	$(CARGO) build --workspace --all-targets
	python3 scripts/check-commit-trailers.py
	python3 scripts/check-migration-checksums.py
	python3 scripts/check-product-layout.py

test: ## Run all Rust unit tests
	$(CARGO) test --workspace

test-qa: ## Full QA: workspace tests, workflow/Tauri guards, hook-denial demo
	$(CARGO) test --workspace
	@$(MAKE) --no-print-directory test-elc
	@$(MAKE) --no-print-directory test-blake3
	@$(MAKE) --no-print-directory test-wasm-verifier
	@$(MAKE) --no-print-directory tamper-suite
	@$(MAKE) --no-print-directory check-guards
	@$(MAKE) --no-print-directory check-sdk
	@$(MAKE) --no-print-directory check-tauri
	@$(MAKE) --no-print-directory test-gui-unit
	@$(MAKE) --no-print-directory demo-hook

# Twice on purpose. The desktop app's dependencies switch preserve_order on and
# Cargo unifies features across a build, which once changed the bytes a
# certificate's signature covered. The canonical form must not move.
test-elc: ## Certificate verifier tests, with and without serde_json/preserve_order
	$(CARGO) test -p ectoledger-elc
	$(CARGO) test -p ectoledger-elc --features serde_json/preserve_order

# hash-blake3 switches the chain hash, and nothing else may move with it:
# goal and policy hashes stay SHA-256 because every verifier recomputes them
# that way. Untested, the feature once made every certificate read INVALID.
test-blake3: ## Core and host tests with --features hash-blake3
	$(CARGO) test -p ectoledger_core --features hash-blake3
	$(CARGO) test -p ectoledger --features hash-blake3

# Every mutant cargo-mutants makes of the certificate verifier and of the
# core hash and Merkle code must fail a test in its own crate. Exits non-zero
# on any survivor. Exit 3 means only timeouts: a mutant that made a loop
# endless, which the tests caught by never passing. Code compiled only under
# hash-blake3 is mutated in a run with that feature. Exclusions, each with its
# reason, are in .cargo/mutants.toml. Results in target/mutants-*/mutants.out.
mutants: ## Mutation testing of the verifier and core hash/Merkle (needs cargo-mutants)
	@command -v cargo-mutants >/dev/null || { echo "cargo install cargo-mutants --locked"; exit 1; }
	@mkdir -p target  # cargo-mutants does not create the parent of -o; a fresh checkout has no target/
	$(CARGO) mutants -p ectoledger-elc -o target/mutants-elc
	$(CARGO) mutants -p ectoledger_core -f crates/core/src/hash.rs -f crates/core/src/merkle.rs \
		--exclude-re goal_hash_matches -o target/mutants-core || [ $$? -eq 3 ]
	$(CARGO) mutants -p ectoledger_core -f crates/core/src/hash.rs --features hash-blake3 \
		--re 'goal_hash_matches|verify_content_hash_any_scheme|sha256_hex' -o target/mutants-core-blake3

wasm-verifier: ## Build the browser verifier into site/verify-bundle.js
	@rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown || rustup target add wasm32-unknown-unknown
	# Remap build paths: panic messages in the module otherwise embed the
	# builder's home directory (username) and make the hash differ per machine.
	RUSTFLAGS="--remap-path-prefix=$$HOME/.cargo=/cargo --remap-path-prefix=$$HOME/.rustup=/rustup --remap-path-prefix=$(CURDIR)=/ectoledger" \
		$(CARGO) build -p ectoledger-elc-wasm --target wasm32-unknown-unknown --release
	node scripts/build-verify-page.mjs

test-api: ## Black-box HTTP API suite (tests/api) against a fresh server; needs pytest, pytest-asyncio, httpx, the SDK
	$(CARGO) build -p ectoledger --bin ironvise
	python3 -m pytest tests/api -q

test-sdk: ## Python and TypeScript SDK unit tests (hermetic; needs pytest, the SDK dev extras, npm)
	cd sdk/python && python3 -m pytest tests -q
	cd sdk/typescript && $(NPM) ci --no-audit --no-fund && npx vitest run

test-scripts: ## Tests of the repository check scripts and the QA scripts themselves (needs pytest)
	python3 -m pytest scripts -q -p no:cacheprovider

test-e2e: ## End-to-end QA on this OS (macOS, Linux; Windows: py scripts\qa\run.py): real binaries, model, sandbox, keychain (needs Ollama)
	python3 scripts/qa/run.py

test-mac: test-e2e ## Alias of test-e2e (macOS adds the built app bundle and its scenarios)

test-wasm-verifier: ## The browser verifier must agree with verify-cert on every example and mutation
	$(CARGO) build -p ectoledger --bin verify-cert
	node scripts/check-wasm-verifier.mjs

tamper-suite: ## Attack fresh, genuine ledgers 18 ways, with and without a held certificate
	$(CARGO) build -p ectoledger --bin ironvise
	ECTOLEDGER_BIN=target/debug/ironvise python3 tests/tamper-suite/suite.py \
		--adapter ironvise-sqlite --adapter ironvise-sqlite-cert \
		--markdown tests/tamper-suite/RESULTS.md

test-integration: ## Run integration tests against ephemeral Postgres (requires Docker)
	./scripts/test-integration.sh

check-upgrade: ## A session recorded by v0.6.3 (OLD_BIN=…) verifies and signs under the candidate; needs PostgreSQL
	$(CARGO) build -p ectoledger
	bash scripts/check-upgrade-from-0.6.3.sh

check-python-wheel: ## Python SDK from its built wheel in a clean venv, against the candidate server
	$(CARGO) build -p ectoledger
	bash scripts/check-python-wheel.sh

test-sqlcipher: ## SQLCipher at-rest encryption against real SQLCipher (needs OpenSSL dev files)
	$(CARGO) test -p ectoledger --features sqlcipher --lib sqlcipher
	$(CARGO) test -p ectoledger --features sqlcipher --test sqlcipher

test-enclave: ## Run enclave IPC + remote attestation unit tests (no hardware required)
	$(CARGO) test --features enclave -p ectoledger --lib -- enclave::ipc::tests --nocapture
	$(CARGO) test --features enclave -p ectoledger --test enclave_ipc -- --nocapture
	$(CARGO) test --features enclave-remote -p ectoledger --lib -- enclave::remote::tests --nocapture

test-enclave-hv: ## Run Apple Hypervisor enclave boot tests (macOS Apple Silicon, requires codesigning)
	$(CARGO) test --features sandbox-apple-enclave --no-run
	@BIN=$$(ls -t target/debug/deps/enclave_apple_boot-* | grep -v '\\.' | head -1) && \
		echo "Codesigning $$BIN" && \
		codesign -s - --entitlements entitlements.xml --force "$$BIN" && \
		"$$BIN" --nocapture

check: ## Type-check the Svelte/TypeScript GUI
	@$(MAKE) --no-print-directory gui-deps
	cd gui && $(NPM) run check

test-gui-unit: ## Run the GUI's Vitest unit tests (front-end logic, no browser)
	@$(MAKE) --no-print-directory gui-deps
	cd gui && $(NPM) run test:unit

check-guards: ## Verify workflow guards and that applied migrations were not edited
	python3 scripts/check-workflow-guards.py
	python3 scripts/check-migration-checksums.py

check-sdk: ## Verify every server route is wrapped by both SDKs or listed as deliberately not wrapped
	python3 scripts/check-sdk-coverage.py

check-tauri: ## Verify the Tauri Rust crates and npm packages agree on major.minor
	python3 scripts/check-tauri-versions.py

check-trailers: ## Verify unpushed commits carry no assistant attribution trailers
	python3 scripts/check-commit-trailers.py

clean: ## Remove build artifacts and node_modules
	$(CARGO) clean
	rm -rf gui/node_modules gui/dist gui/src-tauri/target

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := start
