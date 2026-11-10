//! Integration test: enclave IPC crypto round-trip.
//!
//! Exercises the `SharedMemoryChannel` in isolation - no hypervisor or remote
//! enclave required.  This test is designed to run on any platform (Linux, macOS,
//! Windows) and verifies the full IPC protocol:
//!
//!   1. Host writes X25519 pubkey to `page[0..32]`.
//!   2. Guest writes X25519 pubkey to `page[32..64]`.
//!   3. Both sides derive the same pair of directional ChaCha20-Poly1305 keys.
//!   4. Host encrypts a prompt, guest decrypts it.
//!   5. Guest encrypts a response, host decrypts it.
//!
//! Run:  cargo test --features enclave -p ectoledger --test enclave_ipc

#[cfg(feature = "enclave")]
mod tests {
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    use ectoledger::enclave::ipc::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// The guest's `(request, response)` ciphers, derived from its own secret
    /// and the host pubkey in the page.
    fn guest_ciphers(
        guest_secret: &StaticSecret,
        page: &[u8],
    ) -> (ChaCha20Poly1305, ChaCha20Poly1305) {
        let mut host_pk = [0u8; 32];
        host_pk.copy_from_slice(&page[OFF_HOST_PUBKEY..OFF_HOST_PUBKEY + 32]);
        let shared = guest_secret.diffie_hellman(&PublicKey::from(host_pk));
        let (request_key, response_key) = directional_keys(shared.as_bytes());
        (
            ChaCha20Poly1305::new((&request_key).into()),
            ChaCha20Poly1305::new((&response_key).into()),
        )
    }

    /// Guest decrypts the request in the page, which must carry `counter`.
    fn guest_open(request_cipher: &ChaCha20Poly1305, page: &[u8], counter: u64) -> Vec<u8> {
        let len =
            u32::from_le_bytes(page[OFF_REQ_LEN..OFF_REQ_LEN + 4].try_into().unwrap()) as usize;
        assert_eq!(page[OFF_PAYLOAD..OFF_PAYLOAD + 12], nonce_for(counter));
        request_cipher
            .decrypt(
                &Nonce::from(nonce_for(counter)),
                Payload {
                    msg: &page[OFF_PAYLOAD + 12..OFF_PAYLOAD + len],
                    aad: &aad_for(DIR_HOST_TO_GUEST, counter),
                },
            )
            .expect("guest decrypt failed")
    }

    /// Guest encrypts `response` under `counter` and puts it in the page.
    fn guest_reply(
        response_cipher: &ChaCha20Poly1305,
        page: &mut [u8],
        counter: u64,
        response: &[u8],
    ) {
        let ct = response_cipher
            .encrypt(
                &Nonce::from(nonce_for(counter)),
                Payload {
                    msg: response,
                    aad: &aad_for(DIR_GUEST_TO_HOST, counter),
                },
            )
            .unwrap();
        let total = 12 + ct.len();
        page[OFF_PAYLOAD..OFF_PAYLOAD + 12].copy_from_slice(&nonce_for(counter));
        page[OFF_PAYLOAD + 12..OFF_PAYLOAD + total].copy_from_slice(&ct);
        page[OFF_RESP_LEN..OFF_RESP_LEN + 4].copy_from_slice(&(total as u32).to_le_bytes());
        page[OFF_STATUS] = STATUS_RESPONSE_READY;
    }

    /// Full bidirectional round-trip: host sends prompt, guest responds.
    #[test]
    fn full_round_trip() {
        let mut page = vec![0u8; 4096];

        let mut host = SharedMemoryChannel::new(&mut page);

        // Verify host pubkey written to page[0..32].
        let host_pk = &page[OFF_HOST_PUBKEY..OFF_HOST_PUBKEY + 32];
        assert_ne!(host_pk, &[0u8; 32]);

        let guest_secret = StaticSecret::random_from_rng(&mut rand::rng());
        let guest_pubkey = PublicKey::from(&guest_secret);
        page[OFF_GUEST_PUBKEY..OFF_GUEST_PUBKEY + 32].copy_from_slice(guest_pubkey.as_bytes());

        host.handshake(&page).unwrap();

        // Guest derives the same keys independently.
        let (request_cipher, response_cipher) = guest_ciphers(&guest_secret, &page);

        // Host sends a prompt, guest responds, repeated for each exchange below.
        let prompts: [&[u8]; 3] = [
            b"Analyze the PCI-DSS compliance gaps.",
            b"Which of them are critical?",
            b"Summarize.",
        ];
        let responses: [&[u8]; 3] = [
            b"Found 3 critical gaps in requirement 6.",
            b"Requirements 6.2, 6.3 and 6.5.",
            b"Patch management and secure development need work.",
        ];
        for (i, (prompt, response)) in prompts.iter().zip(responses).enumerate() {
            let counter = i as u64;
            host.send(&mut page, prompt).unwrap();
            assert_eq!(page[OFF_COMMAND], CMD_REQUEST_READY);
            assert_eq!(&guest_open(&request_cipher, &page, counter), prompt);

            guest_reply(&response_cipher, &mut page, counter, response);
            let plaintext = host.receive(&page).expect("host decrypt failed");
            assert_eq!(&plaintext, response);
        }
    }

    /// The layout, asserted deliberately and in one place.
    ///
    /// Every other test in this file reaches the page through the `OFF_*`
    /// constants, so this is the only test that should ever mention a literal
    /// offset. If the layout changes on purpose, exactly one test fails.
    #[test]
    fn memory_layout_byte_ranges() {
        assert_eq!(OFF_HOST_PUBKEY, 0);
        assert_eq!(OFF_GUEST_PUBKEY, 32);
        assert_eq!(OFF_COMMAND, 64);
        assert_eq!(OFF_STATUS, 65);
        assert_eq!(OFF_REQ_LEN, 68);
        assert_eq!(OFF_RESP_LEN, 72);
        assert_eq!(OFF_GUEST_SEED, 80);
        assert_eq!(OFF_SENTINEL, 112);
        assert_eq!(OFF_PAYLOAD, 128);
        assert_eq!(GUEST_SEED_LEN, 32);
        assert_eq!(SENTINEL.len(), 16);
        assert_eq!(MAX_CIPHERTEXT, 4096 - OFF_PAYLOAD - 12);

        let mut page = vec![0u8; 4096];
        let _host = SharedMemoryChannel::new(&mut page);

        // Host pubkey occupies exactly its 32 bytes and nothing else moved.
        assert_ne!(
            &page[OFF_HOST_PUBKEY..OFF_HOST_PUBKEY + 32],
            &[0u8; 32],
            "host pubkey must be written at OFF_HOST_PUBKEY"
        );
        assert_eq!(
            &page[OFF_GUEST_PUBKEY..OFF_GUEST_PUBKEY + 32],
            &[0u8; 32],
            "the guest pubkey slot must be untouched before the guest writes"
        );
        assert_eq!(page[OFF_COMMAND], CMD_IDLE);
        assert_eq!(page[OFF_STATUS], STATUS_IDLE);
        assert_eq!(&page[OFF_REQ_LEN..OFF_REQ_LEN + 4], &[0u8; 4]);
        assert_eq!(&page[OFF_RESP_LEN..OFF_RESP_LEN + 4], &[0u8; 4]);
    }

    /// No two fields overlap - the specific mistake this layout was rebuilt to
    /// remove.
    ///
    /// The sentinel used to live at offset 0, on top of the host public key.
    /// The guest wrote 15 bytes of it over the key it was about to read, so the
    /// two sides derived different session keys while both reporting a
    /// successful handshake. `overlapping_sentinel_breaks_the_channel` shows
    /// what that did; this is the structural guarantee that it cannot recur.
    #[test]
    fn no_two_fields_of_the_page_overlap() {
        let fields: [(&str, usize, usize); 8] = [
            ("host pubkey", OFF_HOST_PUBKEY, 32),
            ("guest pubkey", OFF_GUEST_PUBKEY, 32),
            ("command", OFF_COMMAND, 1),
            ("status", OFF_STATUS, 1),
            ("request length", OFF_REQ_LEN, 4),
            ("response length", OFF_RESP_LEN, 4),
            ("guest seed", OFF_GUEST_SEED, GUEST_SEED_LEN),
            ("sentinel", OFF_SENTINEL, SENTINEL.len()),
        ];
        for (i, (name_a, start_a, len_a)) in fields.iter().enumerate() {
            for (name_b, start_b, len_b) in fields.iter().skip(i + 1) {
                let overlaps = *start_a < start_b + len_b && *start_b < start_a + len_a;
                assert!(
                    !overlaps,
                    "{name_a} [{start_a}..{}) overlaps {name_b} [{start_b}..{})",
                    start_a + len_a,
                    start_b + len_b
                );
            }
            assert!(
                start_a + len_a <= OFF_PAYLOAD,
                "{name_a} runs into the payload area"
            );
        }
    }

    /// The bug the layout change fixed, reproduced.
    ///
    /// Write the sentinel where it used to go - over the first 15 bytes of the
    /// host public key - and have the guest read the key back from there, which
    /// is exactly what the old unikernel did. Both sides still complete a
    /// handshake and both still build a cipher. Nothing looks wrong until a
    /// message crosses, and then it cannot be decrypted.
    ///
    /// That is why `initialize` now sends a probe through the channel before
    /// reporting an Apple Hypervisor attestation: agreeing to derive a key is
    /// not evidence of having derived the same one.
    #[test]
    fn overlapping_sentinel_breaks_the_channel() {
        let mut page = vec![0u8; 4096];
        let mut host = SharedMemoryChannel::new(&mut page);

        // The guest clobbers the start of the host pubkey, as it used to.
        page[0..15].copy_from_slice(b"ECTO_ENCLAVE_OK");

        let guest_secret = StaticSecret::random_from_rng(&mut rand::rng());
        page[OFF_GUEST_PUBKEY..OFF_GUEST_PUBKEY + 32]
            .copy_from_slice(PublicKey::from(&guest_secret).as_bytes());

        // The host still handshakes: it reads the guest key, which is intact.
        host.handshake(&page)
            .expect("the host cannot tell its own key was overwritten");

        // The guest derives from the corrupted key it can see.
        let (request_cipher, _) = guest_ciphers(&guest_secret, &page);

        // Both sides have ciphers. Neither can read the other.
        host.send(&mut page, b"anyone there?").unwrap();
        let len =
            u32::from_le_bytes(page[OFF_REQ_LEN..OFF_REQ_LEN + 4].try_into().unwrap()) as usize;
        let decrypted = request_cipher.decrypt(
            &Nonce::from(nonce_for(0)),
            Payload {
                msg: &page[OFF_PAYLOAD + 12..OFF_PAYLOAD + len],
                aad: &aad_for(DIR_HOST_TO_GUEST, 0),
            },
        );
        assert!(
            decrypted.is_err(),
            "the keys must not agree - if they do, this no longer reproduces the bug"
        );
    }

    /// The host seeds the guest, and can tell when the guest has consumed it.
    #[test]
    fn the_guest_seed_is_written_and_its_consumption_is_observable() {
        let mut page = vec![0u8; 4096];
        let _host = SharedMemoryChannel::new(&mut page);

        assert!(
            SharedMemoryChannel::guest_consumed_seed(&page),
            "an unseeded slot reads as consumed, which is why boot seeds it first"
        );

        SharedMemoryChannel::seed_guest(&mut page).expect("seed");
        assert_ne!(
            &page[OFF_GUEST_SEED..OFF_GUEST_SEED + GUEST_SEED_LEN],
            &[0u8; GUEST_SEED_LEN],
            "the seed must actually be written"
        );
        assert!(
            !SharedMemoryChannel::guest_consumed_seed(&page),
            "a freshly written seed has not been consumed"
        );

        // Seeding must not disturb the keys either side of it.
        assert_ne!(&page[OFF_HOST_PUBKEY..OFF_HOST_PUBKEY + 32], &[0u8; 32]);
        assert_eq!(&page[OFF_GUEST_PUBKEY..OFF_GUEST_PUBKEY + 32], &[0u8; 32]);
        assert_eq!(
            &page[OFF_SENTINEL..OFF_SENTINEL + SENTINEL.len()],
            &[0u8; 16]
        );

        // The guest wipes the slot; the host sees that.
        page[OFF_GUEST_SEED..OFF_GUEST_SEED + GUEST_SEED_LEN].fill(0);
        assert!(SharedMemoryChannel::guest_consumed_seed(&page));
    }

    /// Two successive seeds differ, so the guest's key is not fixed per build.
    #[test]
    fn each_boot_gets_a_different_seed() {
        let mut a = vec![0u8; 4096];
        let mut b = vec![0u8; 4096];
        SharedMemoryChannel::seed_guest(&mut a).expect("seed a");
        SharedMemoryChannel::seed_guest(&mut b).expect("seed b");
        assert_ne!(
            &a[OFF_GUEST_SEED..OFF_GUEST_SEED + GUEST_SEED_LEN],
            &b[OFF_GUEST_SEED..OFF_GUEST_SEED + GUEST_SEED_LEN],
            "two boots must not share a guest secret"
        );
    }

    /// The sentinel is only reported once it is fully written.
    #[test]
    fn a_partial_sentinel_does_not_count_as_booted() {
        let mut page = vec![0u8; 4096];
        assert!(!SharedMemoryChannel::guest_booted(&page));
        page[OFF_SENTINEL..OFF_SENTINEL + SENTINEL.len() - 1]
            .copy_from_slice(&SENTINEL[..SENTINEL.len() - 1]);
        assert!(
            !SharedMemoryChannel::guest_booted(&page),
            "a sentinel missing its last byte is not a sentinel"
        );
        page[OFF_SENTINEL..OFF_SENTINEL + SENTINEL.len()].copy_from_slice(SENTINEL);
        assert!(SharedMemoryChannel::guest_booted(&page));
    }

    /// Keys derived independently on host and guest sides must agree: what the
    /// host encrypts, the guest decrypts with its own derivation.
    #[test]
    fn symmetric_key_agreement() {
        let mut page = vec![0u8; 4096];
        let mut host = SharedMemoryChannel::new(&mut page);

        let guest_secret = StaticSecret::random_from_rng(&mut rand::rng());
        let guest_pubkey = PublicKey::from(&guest_secret);
        page[OFF_GUEST_PUBKEY..OFF_GUEST_PUBKEY + 32].copy_from_slice(guest_pubkey.as_bytes());

        host.handshake(&page).unwrap();
        let (request_cipher, _) = guest_ciphers(&guest_secret, &page);

        let msg = b"test";
        host.send(&mut page, msg).unwrap();

        // Guest decrypts - if this works, keys are identical.
        //
        // Offsets come from the constants, never spelled out. This test used to
        // hardcode 80/92 and broke the moment the payload moved to make room
        // for the seed and the sentinel - a test that pins the layout by
        // accident rather than on purpose. `memory_layout_byte_ranges` is where
        // the numbers are asserted deliberately.
        assert_eq!(&guest_open(&request_cipher, &page, 0), msg);
    }
}
