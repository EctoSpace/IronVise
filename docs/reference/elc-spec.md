# The `.elc` audit certificate - format specification

Version 1 of the container. Written against IronVise 0.8.0,
**2026-08-12**.

This document is complete enough to write an independent verifier in another
language without reading the Rust. If you find a place where it is not, that is
a bug in this document - please report it.

**You may do this.** The BUSL Additional Use Grant in [`LICENSE`](../../LICENSE)
permits running the verifier and implementing this format for any purpose,
commercial included, without further permission. Evidence nobody may check is
not evidence.

Reference implementation: [`crates/elc/src/verify.rs`](../../crates/elc/src/verify.rs)
and [`crates/elc/src/lib.rs`](../../crates/elc/src/lib.rs) (the container and checks,
used by [`crates/host/src/bin/verify_cert.rs`](../../crates/host/src/bin/verify_cert.rs),
`ironvise verify-certificate`, and [`crates/elc-wasm`](../../crates/elc-wasm)),
[`crates/host/src/certificate.rs`](../../crates/host/src/certificate.rs) (export),
[`crates/core/src/merkle.rs`](../../crates/core/src/merkle.rs) (the tree), and
[`crates/core/src/hash.rs`](../../crates/core/src/hash.rs) (the chain).
A worked example, genuine and tampered, is in
[`examples/verified-session/`](../../examples/verified-session/).

---

## 1. Container

A `.elc` file is **UTF-8 JSON**, one top-level object. No framing, no
compression, no envelope. `application/json` is the correct media type.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `version` | integer | always | Format version. `1` at time of writing. |
| `session_id` | string (UUID) | always | The audited session. |
| `goal` | string | always | The goal the session was given. |
| `goal_hash` | hex string | always | `SHA-256(goal_utf8_bytes)`. |
| `policy_hash` | hex string | optional | Hash of the active policy pack. Opaque here. |
| `session_public_key` | hex string | optional | Ed25519 public key, 32 bytes hex. Required if `signature` is present. |
| `ledger_tip_hash` | hex string | always | `content_hash` of the last event. |
| `merkle_root` | hex string | always | Root over all event `content_hash`es. See §3. |
| `event_count` | integer | always | Number of entries in `events`. |
| `started_at` | string | always | RFC 3339. |
| `completed_at` | string | optional | RFC 3339. |
| `events` | array | always | `{sequence: int, content_hash: hex}`, ascending. See §2. |
| `findings` | array | always (may be empty) | See §4. |
| `ots_proof_hex` | hex string | optional | OpenTimestamps *raw timestamp* over the 32 bytes of `ledger_tip_hash`, as the calendar returned it (no detached-file header). Covered by the signature, so it is never upgraded in place: an upgraded proof travels beside the certificate as a detached `.ots` file. |
| `zk_proof` | any | optional | Base64 SP1 proof. **Excluded from the signature** - see §5. |
| `enclave_attestation` | object | optional | `{level, measurement_hash, raw_attestation_hex?}`. Signed. |
| `signature` | hex string | optional | Ed25519 over §5's canonical bytes. |
| `issuer` | object | optional | `{public_key, signature}`: the issuing installation's Ed25519 countersignature. **Excluded from the session signature** - see §5a. |

Optional fields are **omitted entirely** when absent, not set to `null`. A
verifier must treat "absent" and "null" alike on input, but must reproduce
omission exactly when recomputing signing bytes (§5).

All hashes in this format are lowercase hex SHA-256 unless stated otherwise. A
build with the `hash-blake3` feature may write BLAKE3 event hashes into the
ledger, but those enter the certificate as opaque strings: nothing in `.elc`
verification rehashes an event payload, so the digest choice does not change
any procedure here.

---

## 2. `events`

Each entry is exactly:

```json
{ "sequence": 3, "content_hash": "c4255f9a…" }
```

Two properties are checkable offline:

1. `sequence` values are **consecutive ascending integers** - a gap is a
   failure. The first sequence is whatever the session began at (0 for a
   session containing its genesis event); the spec constrains the *steps*, not
   the start.
2. `events[len-1].content_hash` **must equal** `ledger_tip_hash`, and
   `len(events)` must equal `event_count`.

**What is not checkable offline, and why.** The certificate embeds hashes, not
payloads. So a verifier cannot recompute `content_hash` from event content, and
therefore cannot confirm that each event actually chains to its predecessor. It
confirms the *structure* - no gaps, tip matches, root matches - and the
signature over all of it.

The chain-linkage check requires the ledger itself, via `verify-session`. §7
states this limit again because it is the one most easily overstated.

For completeness, the ledger-side scheme a `content_hash` comes from (v2,
canonical since 0.7.0):

```text
SHA-256( "ELv2\x00" ‖ previous_hash ‖ 0x00 ‖ sequence ‖ 0x00
                    ‖ payload_json  ‖ 0x00 ‖ session_id ‖ 0x00 ‖ created_at )
```

with all parts UTF-8, `sequence` in decimal, `session_id` the empty string when
absent, and `created_at` the RFC 3339 rendering of the stored timestamp
truncated to **microseconds** (both backends store no finer). `payload_json` is
`serde_json` compact output - no spaces, keys in the struct's serialization
order. Older ledgers may carry v1-scheme hashes; see
[`docs/reference/schema.md`](schema.md) and `verify_content_hash_any_scheme`.

---

## 3. Merkle root

An RFC 6962-style binary tree with domain separation, over the `content_hash`
of every entry in `events`, **in array order**.

```text
leaf_i  = SHA-256( 0x00 ‖ ascii_bytes_of(events[i].content_hash) )
parent  = SHA-256( 0x01 ‖ decode_hex(left) ‖ decode_hex(right) )
```

Two details that will bite an independent implementer:

- **Leaves hash the hex string's ASCII bytes**, not the 32 decoded bytes.
  Internal nodes hash the **decoded** bytes of their children. This asymmetry
  is deliberate but easy to get backwards.
- **Odd layers duplicate the last node**: when a layer has an odd count, the
  final node is paired with itself. (This is the classic Bitcoin-style
  construction and carries its known duplicate-leaf ambiguity; it is retained
  for compatibility with certificates already issued. An odd event list and
  the same list with its last hash repeated share a root, so the root alone
  does not fix the count: the signature does, because it covers `events` and
  `event_count`.)

Build layers bottom-up until one node remains. That node is `merkle_root`. An
empty `events` array yields no root - a certificate with no events cannot be
meaningfully verified and should be rejected.

`merkle_root` **must be recomputed and compared on every verification**,
including when `findings` is empty. Skipping it there was a real vulnerability
in this project - see §8.

### Inclusion proofs

`MerkleProof` is `{leaf_index: int, path: [{side, hash}]}` where `side` is
`"left"` or `"right"`, naming **the side the sibling is on**, and `hash` is the
sibling's hex. To verify:

```
h = SHA-256(0x00 ‖ ascii(content_hash_of_leaf))
for node in path:
    if node.side == "left":  h = SHA-256(0x01 ‖ hex_decode(node.hash) ‖ hex_decode(h))
    else:                    h = SHA-256(0x01 ‖ hex_decode(h) ‖ hex_decode(node.hash))
assert h == merkle_root
```

---

## 4. `findings`

```json
{
  "title": "…", "severity": "…",
  "evidence_sequence": [3, 7],
  "evidence_quotes": ["…", "…"],
  "merkle_proofs": [ {…}, {…} ]
}
```

`merkle_proofs[k]` proves that the event at `evidence_sequence[k]` is in the
tree. A verifier should check every proof in every finding, and should require
`len(merkle_proofs) == len(evidence_sequence)`.

`evidence_quotes` are **not** bound by any hash in this format. They are
human-readable context; treat them as claims, not evidence. What the proofs
establish is that the cited *events* are in the committed set, not that the
quoted text is what those events said.

---

## 5. Signature

Ed25519 over the **canonical JSON** of the certificate with three fields removed:

1. Serialize the certificate to a JSON object.
2. Remove `signature`. Remove `zk_proof`. Remove `issuer`.
3. Re-serialize with **all object keys sorted lexicographically at every
   level**, compact (no whitespace).
4. Verify those UTF-8 bytes against `session_public_key` (32-byte Ed25519,
   hex) using the 64-byte hex `signature`.

`zk_proof` is stripped so that attaching or altering a ZK proof can never
affect the signature over the audit evidence; the proof verifies independently
through the SP1 verifier. `signature` is stripped for the obvious reason, and
`issuer` because the issuer signs these same bytes (§5a).

### 5a. Issuer countersignature

An installation with an issuer key (`ironvise issuer-key init`) countersigns
every certificate it exports. `issuer.signature` is Ed25519, by
`issuer.public_key`, over the ASCII bytes `ectoledger-issuer-v1` and a newline
followed by the canonical bytes of §5. The prefix keeps an issuer signature
from ever standing in for a session signature, or the reverse.

The issuer key outlives sessions, so an export made after the session's key is
gone is still signed, and a relying party pins one key per installation:
`verify-cert --issuer <hex>`. On its own an issuer signature satisfies
`--strict`; `--expected-key` still names a session key. A verifier that
predates this section ignores the field and checks the session signature as
before. Replacing the key (`issuer-key init --replace`) does not invalidate
certificates it signed; a signed statement linking old key to new is not part
of 0.8.

The reference verifier (`verify-cert`, the browser page) checks neither: a
present `zk_proof` is reported as not verified and not signed, and the
`enclave_attestation` pillar as claimed by the signer, since nothing checks it
against a hardware root. Both are warnings, never a pass.

> **Sorted at every level.** In a language whose JSON maps preserve insertion
> order, you must sort recursively yourself, or you will produce different bytes
> for an identical certificate. The Rust implementation learned this the hard
> way: it used to sort only the top level and rely on `serde_json::Map` being a
> `BTreeMap`, which stops being true when serde_json's `preserve_order` feature
> is on, and the desktop app's dependencies turn it on. It now sorts
> recursively itself (`crates/elc/src/lib.rs`).
>
> **Legacy form, accepted by the reference verifier.** Certificates exported by
> builds that had `preserve_order` on were signed over the top level sorted and
> nested objects in field declaration order. The reference verifier accepts
> that form as well, reports that it did, and produces the same verdict
> otherwise. An independent verifier may reject it; that is not a
> disagreement about the evidence, only about its encoding. Re-exporting from a
> current build gives the canonical form.

**Unsigned certificates are permitted by the format, and the reference verifier
distinguishes them loudly.** The per-session Ed25519 key is generated at session
creation and held in memory for the life of the server process (or optionally
saved as an encrypted session key file by `audit`), so `GET /api/certificates/{id}`
signs while the server still holds the key, and `report --format certificate` /
`prove-audit` sign when given that session's encrypted key file. In addition, an
installation issuer key (`ironvise issuer-key init`) countersigns every
exported certificate (`issuer` in §5a below). A missing `session_public_key`
when `signature` *is* present is a failure either way.

The verifier has two modes, because the question "is this file internally
consistent?" and the question "who issued it?" are different:

| Mode | What it requires | Unsigned certificate |
|---|---|---|
| default (inspection) | checks 2-4 below | passes, reported as *internally consistent*, not *valid* |
| `--strict` | a signature that verifies | fails |
| `--expected-key HEX` | the signature to be by that key; implies `--strict` | fails |
| `--issuer HEX` | an `issuer` block signed by that installation key over `session_id` + `session_public_key` (§5a); implies `--strict` | fails |
| `--require-anchor` | a Bitcoin attestation in the OTS stamp | unaffected; fails a calendar-only stamp |

Checks 2-4 are all recomputed from the certificate's own contents, so a
certificate forged from scratch satisfies every one of them. Only the signature
ties the document to a key, and only an **expected key obtained away from the
file** ties that key to anyone. A consumer in an adversarial setting should use
`--expected-key`; anything less is inspection.

---

## 6. Verification procedure

In the order the reference verifier uses:

| # | Check | Failure is |
|---|---|---|
| 1 | Signature, per §5 - warning if absent, fatal if absent under `--strict` | fatal when present and wrong, or by an unexpected key |
| 2 | `events` consecutive; tip equals `ledger_tip_hash`; count matches | fatal |
| 3 | Recompute `merkle_root` per §3 - **always**, then every finding's proofs | fatal |
| 4 | `goal_hash == SHA-256(goal)` | fatal |
| 5 | OTS stamp over `ledger_tip_hash`: the embedded raw timestamp, or a detached `.ots` file given separately (`--ots`), walked from the tip's 32 bytes | warning when pending or unreadable; fatal when a detached file stamps a different digest, and under `--require-anchor` without a Bitcoin attestation |
| 6 | Enclave attestation | informational |

Exit 0 if no fatal check failed, non-zero otherwise. The reference binary prints
one line per pillar so a human can see which one gave way.

---

## 7. What a valid certificate does and does not prove

**Does:** this file has not been altered since it was produced. The event set is
committed to by `merkle_root`; the cited findings' events are in that set; the
goal text matches its hash; and if signed, the holder of the session key
attested to all of it.

**Does not:**

- **Completeness.** Nothing here shows that everything which happened was
  recorded. A hash chain constrains what can happen *after* an event is written;
  it says nothing about an event that was never written. This is the limit most
  often glossed over, including, historically, by this project.
- **Chain linkage.** Payloads are absent, so per-event `content_hash` values
  cannot be recomputed (§2). Use `verify-session` against the ledger for that.
- **Time.** Without a recognised OTS stamp, `started_at` is a self-reported
  string. Anchoring is what upgrades tamper-evident to provable-at-a-time.
- **Truth of quotes.** `evidence_quotes` are unbound text (§4).
- **Compliance.** A certificate is supporting evidence for your process. See
  [`docs/compliance/eu-ai-act-article12.md`](../compliance/eu-ai-act-article12.md) and
  [`docs/compliance/iso42001.md`](../compliance/iso42001.md).

---

## 8. Known history

Until **2026-08-12**, the reference verifier returned early for certificates
with no findings and never recomputed `merkle_root`. Any event hash other than
the last could be substituted and the certificate still passed - a forgery path.
Fixed, with regression tests in `verify_cert.rs`, and
`examples/verified-session/session-tampered.elc` is that exact mutation, kept so
the gap cannot reopen unnoticed.

It is recorded here because a format specification that omits its own failures
is a marketing document.

---

## 9. Stability

`version` is the container version. Additive fields may appear without a bump;
a verifier **must ignore unknown fields** rather than reject. Any change to the
meaning of an existing field, to §3's tree construction, or to §5's
canonicalisation is a version bump. The v2 content-hash scheme in §2 is a
separate, ledger-level versioning axis and is documented in
[`docs/reference/schema.md`](schema.md).
