# Migration fixtures

Ledgers written by earlier releases, kept as static binary data so that later
releases can prove they still verify them. Exercised by
`crates/host/tests/migration_fixtures.rs`; any change to the event schema must
keep it passing.

| File | Written by | Revision | Hash scheme | Expectation |
|---|---|---|---|---|
| `ledger-0.7.2-tree.sqlite` | internal 0.7.x tree state | `698b1c2` | canonical v2 | **must verify** |
| `ledger-v0.6.4.sqlite` | development tag | `v0.6.4` | legacy v1 | **must not verify** - see below |
| `ledger-v0.6.4-postgres.sql` | development tag (PostgreSQL dump) | `v0.6.4` | legacy v1 | **must verify** after migrations (`migration_fixture_postgres.rs`) |

Each is 7 events in 1 session, signed, and includes a legacy prose refusal
(`thought` with a `"Guard denied: "` prefix) so that the typed `guard_denial`
and `tripwire_rejection` variants added in 0.8.0 are held to staying compatible
with the shape they replaced.

## The rule

**Never regenerate these with the current tree.** A fixture produced by the code
under test proves nothing at all - it would agree with itself by construction
and the test would pass through any compatibility break. Both files were made by
checking out the revision and running a generator against *that tree's own*
`SqliteLedger`.

If a fixture genuinely has to be rebuilt, rebuild it the same way, from the same
revision, and say why in the commit message.

## How they were made

The generators are kept beside the fixtures as `generators/*.rs.txt` - `.txt` so
Cargo does not try to compile them, since they only build against their own
revision.

```bash
# 1. Check out the revision in a throwaway worktree.
git worktree add /tmp/el-v064 v0.6.4          # or: /tmp/el-v072 698b1c2

# 2. Drop the matching generator in as an integration test.
cp crates/host/tests/fixtures/generators/gen_v0.6.4.rs.txt \
   /tmp/el-v064/crates/host/tests/gen_fixture.rs

# 3. Run it. It writes the SQLite file and prints the tip hash.
cd /tmp/el-v064
ECTO_FIXTURE_OUT=/tmp/v064-ledger.sqlite \
  cargo test -p ectoledger --test gen_fixture -- --nocapture

# 4. Checkpoint the WAL into a single clean file. Skipping this is the trap:
#    SQLite leaves committed rows in a `-wal` sidecar, and copying only the main
#    file yields "database disk image is malformed" on the next open.
sqlite3 /tmp/v064-ledger.sqlite "VACUUM INTO '/tmp/v064-clean.sqlite'"
cp /tmp/v064-clean.sqlite crates/host/tests/fixtures/ledger-v0.6.4.sqlite

# 5. Remove the worktree.
cd - && git worktree remove --force /tmp/el-v064
```

`VACUUM INTO` rebuilds the file but preserves every column value, and the hashes
are computed over values rather than file bytes, so it does not affect
verification.

## Why the v0.6.4 fixture must *not* verify

This looks wrong and is not. **v0.6.4's SQLite backend could not verify its own
ledgers.** Its append path hashed one string and stored a different one:

```rust
let payload_json  = serde_json::to_string(payload)?;   // hashed
let content_hash  = compute_content_hash(&previous_hash, sequence, &payload_json);
let payload_value = serde_json::to_value(payload)?;    // stored
.bind(sqlx::types::Json(&payload_value))
```

`to_string` on the internally-tagged enum emits `type` first -
`{"type":"genesis","message":"…"}`. `to_value` builds a `serde_json::Map` over a
`BTreeMap`, so the stored text comes back alphabetised -
`{"message":"…","type":"genesis"}`. v0.6.4's SQLite verifier read that stored
text verbatim and recomputed a digest that could never match.

Confirmed by experiment rather than by reading: v0.6.4 was built and asked to
verify a ledger it had itself just written. It returned `false`.

**Postgres was not affected.** That verifier re-serialised the typed value
(`serde_json::to_string(&row.payload.0)`) instead of the stored JSONB, so both
sides agreed on ordering. Production ledgers from v0.6.4 verify; SQLite ones -
the dev and CI backend - never did.

The current write path binds the same string it hashes, which is what fixed it.

### What this means for the release

- There is no verifiable v0.6.4 **SQLite** ledger anywhere, so there is nothing
  of that kind to stay compatible with. The compatibility risk for that backend
  is zero, for an uncomfortable reason.
- The release-blocking v0.6.4 fixture is **Postgres** (`ledger-v0.6.4-postgres.sql`),
  which is the backend that produced verifiable ledgers and the one production
  users have. It is exercised by `crates/host/tests/migration_fixture_postgres.rs`
  (run via `scripts/test-integration.sh` against a live PostgreSQL instance).
- The two `v064_sqlite_*` tests pin the current situation exactly: the chain
  links are intact, the payloads still parse, re-serialising the typed value
  reproduces the stored hash, and only the stored text does not. If any of that
  changes, the tests fail and force a decision rather than quietly passing.

## Third-party fixtures

| File | What | Source and licence |
|---|---|---|
| `nitro-sample-attestation.cbor` | A real AWS Nitro Enclaves attestation document (COSE_Sign1), verified by `enclave::nitro_attestation` against the embedded AWS root at the document's own timestamp, since its short-lived certificates have expired | [`evervault/attestation-doc-validation`](https://github.com/evervault/attestation-doc-validation), `test-data/valid-attestation-doc-base64`, Apache-2.0 |
| `openshell/` | NVIDIA OpenShell decision logs | see `openshell/README.md` |
