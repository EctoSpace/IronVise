// IronVise - SP1 zkVM Guest Program
//
// This program runs inside the Succinct SP1 RISC-V virtual machine and produces a
// zero-knowledge proof that:
//
//   1. The event hash chain is valid: every link recalculates correctly.
//   2. The genesis event starts from the canonical all-zeros previous hash.
//   3. The final event's content hash matches the expected ledger tip hash.
//   4. A Merkle tree over all content hashes produces the expected root.
//   5. No event's payload JSON matches any forbidden policy pattern.
//
// Performance decisions:
//   - Input is read via `sp1_zkvm::io::read` (bincode, not JSON). Zero JSON parsing in guest.
//   - All `regex_lite::Regex` patterns are compiled exactly once before the event loop.
//   - The Merkle tree is built from computed hashes (never from DB-fetched values).

#![no_main]
sp1_zkvm::entrypoint!(main);

use ectoledger_core::hash::verify_content_hash_any_scheme;
use ectoledger_core::merkle;
use ectoledger_core::schema::{GuestInput, GuestOutput};
use regex_lite::Regex;

pub fn main() {
    let input: GuestInput = sp1_zkvm::io::read::<GuestInput>();

    assert!(!input.events.is_empty(), "guest: event list is empty");

    // Patterns are compiled here, before the event loop, so regex compilation cost
    // is O(P) rather than O(P × N) where P = number of patterns and N = event count.
    let compiled_patterns: Vec<(Regex, usize)> = input
        .policy_patterns
        .iter()
        .enumerate()
        .filter_map(|(idx, pattern)| {
            Regex::new(pattern)
                .ok()
                .map(|re| (re, idx))
        })
        .collect();

    // For every event we re-derive its content hash with the canonical v2
    // scheme - binding previous_hash, sequence, payload_json, session_id, and
    // created_at - falling back through the pre-migration v1 layouts (the same
    // multi-scheme verifier the host backends use). The expected value for
    // event i is event i+1's `previous_hash` (or `tip_hash` for the last
    // event), so a match proves the chain has no gaps, insertions, or
    // tampered payloads.

    // Verify the first event links to the expected anchor. For a chain slice
    // starting at the global genesis this is the all-zeros hash; for a
    // session-scoped slice it is the content hash of the preceding event.
    assert_eq!(
        input.events[0].previous_hash,
        input.anchor_previous_hash,
        "guest: first event must link back to the expected anchor previous_hash"
    );

    let mut violations: Vec<String> = Vec::new();
    let mut computed_content_hashes: Vec<String> = Vec::with_capacity(input.events.len());

    for (i, event) in input.events.iter().enumerate() {
        // The expected content hash for this event: the next event's
        // previous_hash, or the tip hash for the final event.
        let expected_hash = if i + 1 < input.events.len() {
            &input.events[i + 1].previous_hash
        } else {
            &input.tip_hash
        };

        let scheme = verify_content_hash_any_scheme(
            &event.previous_hash,
            event.sequence,
            &event.payload_json,
            event.session_id.as_deref(),
            Some(&event.created_at),
            expected_hash,
        );
        assert!(
            scheme.is_some(),
            "guest: hash chain break at sequence {} (no scheme reproduces the expected hash)",
            event.sequence,
        );
        computed_content_hashes.push(expected_hash.clone());

        // Each event's raw payload_json is checked against every compiled pattern.
        // Matches are recorded as violations and included in GuestOutput.
        // Policy violations do NOT abort the proof - the host decides how to handle them.
        for (re, pattern_idx) in &compiled_patterns {
            if re.is_match(&event.payload_json) {
                violations.push(format!(
                    "event seq={} matched forbidden pattern[{}]: {}",
                    event.sequence,
                    pattern_idx,
                    &input.policy_patterns[*pattern_idx],
                ));
            }
        }
    }

    let actual_tip = computed_content_hashes.last().expect("guest: no computed hashes");
    assert_eq!(
        actual_tip,
        &input.tip_hash,
        "guest: computed tip hash does not match expected tip_hash"
    );

    let actual_genesis = computed_content_hashes.first().expect("guest: no computed hashes");
    assert_eq!(
        actual_genesis,
        &input.genesis_hash,
        "guest: computed genesis hash does not match expected genesis_hash"
    );

    // Build the Merkle tree from the COMPUTED content hashes (not from any DB values).
    // This proves the tree is derived from the same chain we just verified.
    let hash_refs: Vec<&str> = computed_content_hashes.iter().map(|s| s.as_str()).collect();
    let tree = merkle::build_merkle_tree(&hash_refs)
        .unwrap_or_else(|e| panic!("guest: failed to build Merkle tree: {e}"));
    let actual_root = merkle::root(&tree)
        .unwrap_or_else(|e| panic!("guest: failed to get Merkle root: {e}"));

    assert_eq!(
        actual_root,
        input.merkle_root,
        "guest: computed Merkle root does not match expected merkle_root"
    );

    // The verifier on the host can read GuestOutput back from the proof's public values.
    // `verified = true` is only committed when ALL hash and Merkle checks passed above
    // (any failure would have caused a panic, aborting proof generation).
    let output = GuestOutput {
        verified: true,
        event_count: input.events.len() as u64,
        violations,
    };

    sp1_zkvm::io::commit::<GuestOutput>(&output);
}
