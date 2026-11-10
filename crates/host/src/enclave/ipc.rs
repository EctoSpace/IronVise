//! Encrypted IPC channel over a shared memory page.
//!
//! Layout of the 4 KiB shared memory page (guest physical address inside guest RAM):
//!
//! ```text
//! Offset   Size   Field
//! ──────   ────   ─────
//!   0       32    Host X25519 public key
//!  32       32    Guest X25519 public key
//!  64        1    Command byte (host → guest): 0x00 = idle, 0x01 = request ready
//!  65        1    Status byte  (guest → host): 0x00 = idle, 0x02 = response ready
//!  66        2    Reserved (alignment padding)
//!  68        4    Request length  (little-endian u32)
//!  72        4    Response length (little-endian u32)
//!  76        4    Reserved
//!  80       32    Guest secret-key seed, written by the host, zeroed by the guest
//! 112       16    Boot sentinel, written by the guest once it is ready
//! 128       ..    Nonce (12 bytes) ‖ ciphertext (up to page end)
//! ```
//!
//! Protocol:
//! 1. Host writes its public key at offset 0 and a CSPRNG seed at offset 80.
//! 2. Host boots the guest / resumes the vCPU.
//! 3. Guest derives its X25519 secret from the seed, zeroes the seed slot, reads
//!    the host pubkey, writes its own pubkey at offset 32, derives the shared
//!    secret, and only then writes the sentinel and traps back with `HVC`.
//! 4. Host writes an encrypted request at offset 128, sets `command = 0x01`,
//!    and resumes the vCPU.
//! 5. Guest decrypts, processes, writes an encrypted response at offset 128,
//!    sets the response length and `status = 0x02`, and traps back with `HVC`.
//! 6. Host reads the response and decrypts.
//!
//! ## Encryption (protocol v2)
//!
//! HKDF-SHA256 over the X25519 shared secret yields one ChaCha20-Poly1305 key
//! per direction (info = `PROTOCOL ‖ " host->guest"` / `" guest->host"`), so a
//! message sent by one side never decrypts as a message from the other. Each
//! direction has its own counter starting at 0. The nonce is the counter (8
//! bytes little-endian) ‖ 4 zero bytes, and the AAD is `PROTOCOL ‖ direction ‖
//! counter`. The receiver requires the nonce to equal its expected counter
//! before decrypting and advances the counter only once the tag verifies, so
//! replayed and out-of-order messages are refused and a refused message costs
//! nothing.
//!
//! ## Why the host supplies the guest's key material
//!
//! The guest has no entropy source. It runs bare-metal on a vCPU whose only
//! architectural RNG is `RNDR` (FEAT_RNG), and no Apple silicon implements
//! FEAT_RNG - the instruction is undefined there, and executing it kills the
//! guest before it writes anything. Since Apple silicon is the only hardware
//! this unikernel ever runs on, a hardware-RNG path would be unreachable code
//! that fails closed on every supported machine.
//!
//! So the host draws the seed from the OS CSPRNG - the same source it uses for
//! its own secret - and hands it over through the page. That does mean the host
//! could reconstruct the guest's private key. It costs nothing: this channel has
//! exactly two parties, the host already holds one half of it, and the host
//! loaded the guest image and owns every byte of its RAM. The property the
//! channel provides is confidentiality of host↔guest traffic against everything
//! *else* on the machine, and host-supplied entropy does not weaken it.
//!
//! The guest zeroes the slot after reading it, so the key material does not sit
//! in the page for the rest of the session; the host checks that it did, which
//! doubles as proof the guest reached that line.
//!
//! ## Why the sentinel is not at offset 0
//!
//! Offset 0 overlaps the host public key. A sentinel there would have the
//! guest write 15 bytes of `ECTO_ENCLAVE_OK` over the first 15 bytes of the
//! host's key and then read that corrupted value back as the key it is
//! supposed to agree with, so the two sides derive different
//! ChaCha20-Poly1305 keys - silently, since nothing short of a message sent
//! through the channel afterwards would catch it.

#[cfg(feature = "enclave")]
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
#[cfg(feature = "enclave")]
use hkdf::Hkdf;
#[cfg(feature = "enclave")]
use sha2::Sha256;
#[cfg(feature = "enclave")]
use x25519_dalek::{PublicKey, StaticSecret};

/// Byte offsets within the shared memory page.
///
/// These are a wire contract with `crates/guard_unikernel/src/main.rs`, which
/// carries the same constants. The two ship together - the unikernel binary is
/// built by host's `build.rs` and embedded - so changing the layout means
/// changing both sides in the same commit, and nothing else.
pub const OFF_HOST_PUBKEY: usize = 0;
pub const OFF_GUEST_PUBKEY: usize = 32;
pub const OFF_COMMAND: usize = 64;
pub const OFF_STATUS: usize = 65;
pub const OFF_REQ_LEN: usize = 68;
pub const OFF_RESP_LEN: usize = 72;
pub const OFF_GUEST_SEED: usize = 80;
pub const OFF_SENTINEL: usize = 112;
pub const OFF_PAYLOAD: usize = 128;

/// Size of the guest's secret-key seed, in bytes.
pub const GUEST_SEED_LEN: usize = 32;

/// Written by the guest once it has derived its key and published its pubkey.
///
/// Sixteen bytes, none of them zero. That matters: the page is zeroed before
/// boot, so a sentinel ending in NUL would be indistinguishable from the same
/// sentinel one byte short - a guest that died mid-write would still read as
/// ready. Every byte must be something the guest had to put there.
pub const SENTINEL: &[u8; 16] = b"ECTO-ENCLAVE-OK!";

/// Maximum ciphertext size = page size − payload offset − nonce (12 bytes).
pub const MAX_CIPHERTEXT: usize = 4096 - OFF_PAYLOAD - 12;

/// Command byte values (host → guest).
pub const CMD_IDLE: u8 = 0x00;
pub const CMD_REQUEST_READY: u8 = 0x01;
pub const CMD_SHUTDOWN: u8 = 0xFF;

/// Status byte values (guest → host).
pub const STATUS_IDLE: u8 = 0x00;
pub const STATUS_BUSY: u8 = 0x01;
pub const STATUS_RESPONSE_READY: u8 = 0x02;
/// The guest refused the request: a bad length, a failed decrypt, or - before
/// it ever gets this far - a missing seed.
pub const STATUS_ERROR: u8 = 0x03;

/// Protocol label, bound into both directional keys and every AAD.
///
/// Wire contract with `crates/guard_unikernel/src/main.rs`, like the layout.
pub const PROTOCOL: &[u8] = b"ectoledger-enclave-ipc-v2";

/// Direction bytes (AAD): host → guest requests and guest → host responses.
pub const DIR_HOST_TO_GUEST: u8 = 0x01;
pub const DIR_GUEST_TO_HOST: u8 = 0x02;

/// Derive the `(host→guest, guest→host)` ChaCha20-Poly1305 keys from the
/// X25519 shared secret.
#[cfg(feature = "enclave")]
pub fn directional_keys(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let expand = |label: &[u8]| {
        let mut key = [0u8; 32];
        hkdf.expand_multi_info(&[PROTOCOL, label], &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        key
    };
    (expand(b" host->guest"), expand(b" guest->host"))
}

/// Nonce for message `counter`: 8 bytes little-endian ‖ 4 zero bytes.
pub fn nonce_for(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// AAD for message `counter` in `direction`: `PROTOCOL ‖ direction ‖ counter`.
pub fn aad_for(direction: u8, counter: u64) -> [u8; 34] {
    let n = PROTOCOL.len();
    let mut aad = [0u8; 34];
    aad[..n].copy_from_slice(PROTOCOL);
    aad[n] = direction;
    aad[n + 1..].copy_from_slice(&counter.to_le_bytes());
    aad
}

/// Host-side encrypted IPC channel.
///
/// The host holds a static X25519 secret and derives one ChaCha20-Poly1305 key
/// per direction after reading the guest's public key from the shared page.
#[cfg(feature = "enclave")]
pub struct SharedMemoryChannel {
    secret: StaticSecret,
    host_pubkey: PublicKey,
    /// Host → guest cipher, derived after handshake.
    send_cipher: Option<ChaCha20Poly1305>,
    /// Guest → host cipher, derived after handshake.
    recv_cipher: Option<ChaCha20Poly1305>,
    /// Counter of the next request to send.
    send_counter: u64,
    /// Counter the next response must carry.
    recv_counter: u64,
}

#[cfg(feature = "enclave")]
impl SharedMemoryChannel {
    /// Create a new channel.  Writes the host public key to `shared_page[0..32]`.
    pub fn new(shared_page: &mut [u8]) -> Self {
        let secret = StaticSecret::random_from_rng(&mut rand::rng());
        let host_pubkey = PublicKey::from(&secret);

        shared_page[OFF_HOST_PUBKEY..OFF_HOST_PUBKEY + 32].copy_from_slice(host_pubkey.as_bytes());

        Self {
            secret,
            host_pubkey,
            send_cipher: None,
            recv_cipher: None,
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// Return the host's public key bytes (for attestation embedding).
    pub fn host_pubkey_bytes(&self) -> [u8; 32] {
        *self.host_pubkey.as_bytes()
    }

    /// Draw the guest's secret-key seed from the OS CSPRNG and write it into
    /// the page. See the module header for why the host supplies it.
    ///
    /// Rejects an all-zero draw rather than trusting it. X25519 clamping turns
    /// a zero scalar into a low-order-adjacent key, so the one value that must
    /// never reach the guest is the one a broken RNG is most likely to produce.
    pub fn seed_guest(shared_page: &mut [u8]) -> Result<(), String> {
        use rand::Rng;

        let mut seed = [0u8; GUEST_SEED_LEN];
        rand::rng().fill_bytes(&mut seed);
        if seed == [0u8; GUEST_SEED_LEN] {
            return Err("CSPRNG returned an all-zero guest seed".to_string());
        }
        shared_page[OFF_GUEST_SEED..OFF_GUEST_SEED + GUEST_SEED_LEN].copy_from_slice(&seed);
        Ok(())
    }

    /// Whether the guest has zeroed the seed slot.
    ///
    /// The guest zeroes it immediately after copying the seed out, so this is
    /// both "the key material is no longer sitting in the page" and "the guest
    /// definitely reached that line" - which is a stronger statement than the
    /// sentinel alone, since the sentinel is a constant the guest could in
    /// principle write without having done anything with the seed.
    pub fn guest_consumed_seed(shared_page: &[u8]) -> bool {
        shared_page[OFF_GUEST_SEED..OFF_GUEST_SEED + GUEST_SEED_LEN] == [0u8; GUEST_SEED_LEN]
    }

    /// Whether the guest has published its boot sentinel.
    pub fn guest_booted(shared_page: &[u8]) -> bool {
        &shared_page[OFF_SENTINEL..OFF_SENTINEL + SENTINEL.len()] == SENTINEL.as_slice()
    }

    /// Complete the handshake: read the guest's public key from `shared_page[32..64]`
    /// and derive the two directional keys via HKDF-SHA256(shared_secret).
    pub fn handshake(&mut self, shared_page: &[u8]) -> Result<(), String> {
        let mut guest_key_bytes = [0u8; 32];
        guest_key_bytes.copy_from_slice(&shared_page[OFF_GUEST_PUBKEY..OFF_GUEST_PUBKEY + 32]);

        // Reject the null public key (indicates the guest never wrote its key).
        if guest_key_bytes == [0u8; 32] {
            return Err("Guest public key is all-zero - handshake not completed".to_string());
        }

        let guest_pubkey = PublicKey::from(guest_key_bytes);
        let shared_secret = self.secret.diffie_hellman(&guest_pubkey);

        let (to_guest, to_host) = directional_keys(shared_secret.as_bytes());
        self.send_cipher = Some(ChaCha20Poly1305::new((&to_guest).into()));
        self.recv_cipher = Some(ChaCha20Poly1305::new((&to_host).into()));
        Ok(())
    }

    /// Encrypt `plaintext` and write `[nonce ‖ ciphertext]` into the shared page at
    /// offset 80.  Also sets the request length field.  The send counter advances
    /// only once the message is in the page.
    pub fn send(&mut self, shared_page: &mut [u8], plaintext: &[u8]) -> Result<(), String> {
        let cipher = self.send_cipher.as_ref().ok_or("Handshake not completed")?;

        let counter = self.send_counter;
        let next = counter
            .checked_add(1)
            .ok_or("Send counter exhausted (u64::MAX) - session key must be renegotiated")?;
        let nonce_bytes = nonce_for(counter);
        let aad = aad_for(DIR_HOST_TO_GUEST, counter);

        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| format!("Encrypt failed: {e}"))?;

        if ciphertext.len() > MAX_CIPHERTEXT {
            return Err(format!(
                "Ciphertext too large for shared page: {} > {}",
                ciphertext.len(),
                MAX_CIPHERTEXT
            ));
        }

        let total = 12 + ciphertext.len();
        shared_page[OFF_PAYLOAD..OFF_PAYLOAD + 12].copy_from_slice(&nonce_bytes);
        shared_page[OFF_PAYLOAD + 12..OFF_PAYLOAD + total].copy_from_slice(&ciphertext);

        // Request length covers nonce + ciphertext.
        let len_bytes = (total as u32).to_le_bytes();
        shared_page[OFF_REQ_LEN..OFF_REQ_LEN + 4].copy_from_slice(&len_bytes);

        shared_page[OFF_COMMAND] = CMD_REQUEST_READY;

        self.send_counter = next;
        Ok(())
    }

    /// Read the guest's encrypted response from the shared page and decrypt it.
    ///
    /// The nonce must equal the expected receive counter; the counter advances
    /// only when the tag verifies.
    pub fn receive(&mut self, shared_page: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = self.recv_cipher.as_ref().ok_or("Handshake not completed")?;

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&shared_page[OFF_RESP_LEN..OFF_RESP_LEN + 4]);
        let total_len = u32::from_le_bytes(len_bytes) as usize;

        if !(12..=12 + MAX_CIPHERTEXT).contains(&total_len) {
            return Err(format!("Response length out of range: {total_len}"));
        }

        let counter = self.recv_counter;
        let next = counter
            .checked_add(1)
            .ok_or("Receive counter exhausted (u64::MAX) - session key must be renegotiated")?;

        let nonce_bytes = &shared_page[OFF_PAYLOAD..OFF_PAYLOAD + 12];
        let ciphertext = &shared_page[OFF_PAYLOAD + 12..OFF_PAYLOAD + total_len];

        if nonce_bytes != nonce_for(counter) {
            return Err(format!(
                "Response replayed or out-of-order: nonce does not match expected counter {counter}"
            ));
        }

        let aad = aad_for(DIR_GUEST_TO_HOST, counter);
        let plaintext = cipher
            .decrypt(
                &Nonce::from(nonce_for(counter)),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|e| format!("Decrypt failed: {e}"))?;

        self.recv_counter = next;
        Ok(plaintext)
    }
}

#[cfg(test)]
#[cfg(feature = "enclave")]
mod tests {
    use super::*;

    fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(key.into())
    }

    fn seal(key: &[u8; 32], nonce: [u8; 12], aad: [u8; 34], msg: &[u8]) -> Vec<u8> {
        cipher(key)
            .encrypt(&Nonce::from(nonce), Payload { msg, aad: &aad })
            .unwrap()
    }

    /// Put `[nonce ‖ ciphertext]` in the response slot, as the guest would.
    fn put_response(page: &mut [u8], nonce: [u8; 12], ciphertext: &[u8]) {
        let total = 12 + ciphertext.len();
        page[OFF_PAYLOAD..OFF_PAYLOAD + 12].copy_from_slice(&nonce);
        page[OFF_PAYLOAD + 12..OFF_PAYLOAD + total].copy_from_slice(ciphertext);
        page[OFF_RESP_LEN..OFF_RESP_LEN + 4].copy_from_slice(&(total as u32).to_le_bytes());
        page[OFF_STATUS] = STATUS_RESPONSE_READY;
    }

    /// A host channel plus a guest simulated from the public helpers.
    struct Pair {
        page: Vec<u8>,
        host: SharedMemoryChannel,
        /// Guest's request key (host → guest).
        request_key: [u8; 32],
        /// Guest's response key (guest → host).
        response_key: [u8; 32],
        guest_send: u64,
    }

    impl Pair {
        fn new() -> Self {
            let mut page = vec![0u8; 4096];
            let mut host = SharedMemoryChannel::new(&mut page);

            let guest_secret = StaticSecret::random_from_rng(&mut rand::rng());
            let guest_pubkey = PublicKey::from(&guest_secret);
            page[OFF_GUEST_PUBKEY..OFF_GUEST_PUBKEY + 32].copy_from_slice(guest_pubkey.as_bytes());
            host.handshake(&page).unwrap();

            let mut host_key_bytes = [0u8; 32];
            host_key_bytes.copy_from_slice(&page[OFF_HOST_PUBKEY..OFF_HOST_PUBKEY + 32]);
            let shared = guest_secret.diffie_hellman(&PublicKey::from(host_key_bytes));
            let (request_key, response_key) = directional_keys(shared.as_bytes());

            Self {
                page,
                host,
                request_key,
                response_key,
                guest_send: 0,
            }
        }

        /// Guest decrypts the request in the page, which must carry `counter`.
        fn guest_open(&self, counter: u64) -> Vec<u8> {
            let len =
                u32::from_le_bytes(self.page[OFF_REQ_LEN..OFF_REQ_LEN + 4].try_into().unwrap())
                    as usize;
            assert_eq!(
                self.page[OFF_PAYLOAD..OFF_PAYLOAD + 12],
                nonce_for(counter),
                "request nonce must encode its counter"
            );
            cipher(&self.request_key)
                .decrypt(
                    &Nonce::from(nonce_for(counter)),
                    Payload {
                        msg: &self.page[OFF_PAYLOAD + 12..OFF_PAYLOAD + len],
                        aad: &aad_for(DIR_HOST_TO_GUEST, counter),
                    },
                )
                .expect("guest decrypt failed")
        }

        /// Guest writes a genuine response under its next send counter.
        fn guest_reply(&mut self, msg: &[u8]) {
            let counter = self.guest_send;
            let ct = seal(
                &self.response_key,
                nonce_for(counter),
                aad_for(DIR_GUEST_TO_HOST, counter),
                msg,
            );
            put_response(&mut self.page, nonce_for(counter), &ct);
            self.guest_send += 1;
        }
    }

    #[test]
    fn round_trip_encrypt_decrypt() {
        let mut page = vec![0u8; 4096];

        // Host creates channel (writes host pubkey).
        let host_chan = SharedMemoryChannel::new(&mut page);

        let host_pk_slot = &page[OFF_HOST_PUBKEY..OFF_HOST_PUBKEY + 32];
        assert_ne!(
            host_pk_slot, &[0u8; 32],
            "host pubkey must be non-zero after new()"
        );
        assert_eq!(host_pk_slot, host_chan.host_pubkey_bytes().as_slice());

        // Several messages each way, counters advancing on both sides.
        let mut pair = Pair::new();
        for i in 0..4u64 {
            let prompt = format!("request {i}");
            pair.host.send(&mut pair.page, prompt.as_bytes()).unwrap();
            assert_eq!(pair.page[OFF_COMMAND], CMD_REQUEST_READY);
            assert_eq!(pair.guest_open(i), prompt.as_bytes());

            let response = format!("response {i}");
            pair.guest_reply(response.as_bytes());
            assert_eq!(pair.host.receive(&pair.page).unwrap(), response.as_bytes());
        }
    }

    /// The host's own request, copied into the response slot, is not a response.
    #[test]
    fn reflected_request_is_rejected() {
        let mut pair = Pair::new();
        pair.host.send(&mut pair.page, b"ping").unwrap();

        // Both directions start at counter 0, so the nonce matches; the key and
        // AAD direction are what stop it.
        let len = u32::from_le_bytes(pair.page[OFF_REQ_LEN..OFF_REQ_LEN + 4].try_into().unwrap());
        pair.page[OFF_RESP_LEN..OFF_RESP_LEN + 4].copy_from_slice(&len.to_le_bytes());
        pair.page[OFF_STATUS] = STATUS_RESPONSE_READY;

        let err = pair.host.receive(&pair.page).unwrap_err();
        assert!(err.contains("Decrypt failed"), "got: {err}");
    }

    #[test]
    fn replayed_response_is_rejected() {
        let mut pair = Pair::new();
        pair.guest_reply(b"once");
        assert_eq!(pair.host.receive(&pair.page).unwrap(), b"once");

        let err = pair.host.receive(&pair.page).unwrap_err();
        assert!(err.contains("replayed or out-of-order"), "got: {err}");
    }

    /// The AAD must carry the same counter and direction as the nonce.
    #[test]
    fn response_with_mismatched_aad_is_rejected() {
        let mut pair = Pair::new();
        let nonce = nonce_for(0);

        let wrong_counter = seal(
            &pair.response_key,
            nonce,
            aad_for(DIR_GUEST_TO_HOST, 1),
            b"x",
        );
        put_response(&mut pair.page, nonce, &wrong_counter);
        let err = pair.host.receive(&pair.page).unwrap_err();
        assert!(err.contains("Decrypt failed"), "got: {err}");

        let wrong_direction = seal(
            &pair.response_key,
            nonce,
            aad_for(DIR_HOST_TO_GUEST, 0),
            b"x",
        );
        put_response(&mut pair.page, nonce, &wrong_direction);
        let err = pair.host.receive(&pair.page).unwrap_err();
        assert!(err.contains("Decrypt failed"), "got: {err}");
    }

    #[test]
    fn nonce_with_nonzero_tail_is_rejected() {
        let mut pair = Pair::new();
        let mut nonce = nonce_for(0);
        nonce[11] = 1;

        // Otherwise genuine: right key, right counter in the AAD.
        let ct = seal(
            &pair.response_key,
            nonce,
            aad_for(DIR_GUEST_TO_HOST, 0),
            b"x",
        );
        put_response(&mut pair.page, nonce, &ct);
        let err = pair.host.receive(&pair.page).unwrap_err();
        assert!(err.contains("replayed or out-of-order"), "got: {err}");
    }

    #[test]
    fn directional_keys_differ() {
        let (to_guest, to_host) = directional_keys(&[7u8; 32]);
        assert_ne!(to_guest, to_host);
        assert_eq!(directional_keys(&[7u8; 32]), (to_guest, to_host));
        assert_ne!(directional_keys(&[8u8; 32]).0, to_guest);
    }

    /// Pins the derivation, which the guest must reproduce byte for byte.
    #[test]
    fn directional_keys_known_answer() {
        let (to_guest, to_host) = directional_keys(&[7u8; 32]);
        assert_eq!(
            hex::encode(to_guest),
            "bf61c8b00ff69724f25577712429c8ee0cbbf8ba66d28166f9e6ae56b3805ce5"
        );
        assert_eq!(
            hex::encode(to_host),
            "5859f107a045600b438aeeba4bcaf0e4601d1a110978e412cd9e267905fcb10d"
        );
    }

    #[test]
    fn nonce_and_aad_layout() {
        let counter = 0x0807_0605_0403_0201u64;
        assert_eq!(nonce_for(counter), [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0]);

        let aad = aad_for(DIR_GUEST_TO_HOST, counter);
        assert_eq!(&aad[..PROTOCOL.len()], PROTOCOL);
        assert_eq!(aad[PROTOCOL.len()], DIR_GUEST_TO_HOST);
        assert_eq!(&aad[PROTOCOL.len() + 1..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    /// A refused message must not advance the counter or poison the channel.
    #[test]
    fn genuine_message_succeeds_after_a_rejected_one() {
        let mut pair = Pair::new();

        pair.guest_reply(b"first");
        let first = pair.page.clone();
        assert_eq!(pair.host.receive(&pair.page).unwrap(), b"first");

        // A forgery under the next counter fails the tag check.
        put_response(&mut pair.page, nonce_for(1), &[0u8; 32]);
        let err = pair.host.receive(&pair.page).unwrap_err();
        assert!(err.contains("Decrypt failed"), "got: {err}");

        // So does a replay of the first response.
        pair.page.copy_from_slice(&first);
        let err = pair.host.receive(&pair.page).unwrap_err();
        assert!(err.contains("replayed or out-of-order"), "got: {err}");

        pair.guest_reply(b"second");
        assert_eq!(pair.host.receive(&pair.page).unwrap(), b"second");
    }

    /// A request that does not fit the page must not burn a counter, or the
    /// guest (which expects them strictly in order) would refuse every later one.
    #[test]
    fn oversize_send_does_not_consume_a_counter() {
        let mut pair = Pair::new();
        let err = pair
            .host
            .send(&mut pair.page, &vec![0u8; MAX_CIPHERTEXT])
            .unwrap_err();
        assert!(err.contains("too large"), "got: {err}");

        pair.host.send(&mut pair.page, b"fits").unwrap();
        assert_eq!(pair.guest_open(0), b"fits");
    }

    #[test]
    fn exhausted_counters_are_refused() {
        let mut pair = Pair::new();

        pair.host.send_counter = u64::MAX;
        let err = pair.host.send(&mut pair.page, b"x").unwrap_err();
        assert!(err.contains("exhausted"), "got: {err}");
        assert_eq!(pair.page[OFF_COMMAND], CMD_IDLE);

        pair.host.recv_counter = u64::MAX;
        let ct = seal(
            &pair.response_key,
            nonce_for(u64::MAX),
            aad_for(DIR_GUEST_TO_HOST, u64::MAX),
            b"x",
        );
        put_response(&mut pair.page, nonce_for(u64::MAX), &ct);
        let err = pair.host.receive(&pair.page).unwrap_err();
        assert!(err.contains("exhausted"), "got: {err}");
    }

    /// Handshake must reject an all-zero guest public key (guest never wrote its key).
    #[test]
    fn handshake_rejects_null_guest_pubkey() {
        let mut page = vec![0u8; 4096];
        let mut chan = SharedMemoryChannel::new(&mut page);

        // page[32..64] is still all zeros - guest never wrote.
        let err = chan.handshake(&page).unwrap_err();
        assert!(
            err.contains("all-zero"),
            "expected null-pubkey rejection, got: {err}"
        );
    }

    /// send() before handshake must return an error (no cipher available).
    #[test]
    fn send_before_handshake_fails() {
        let mut page = vec![0u8; 4096];
        let mut chan = SharedMemoryChannel::new(&mut page);

        let err = chan.send(&mut page, b"hello").unwrap_err();
        assert!(
            err.contains("Handshake not completed"),
            "expected handshake error, got: {err}"
        );
    }

    /// receive() before handshake must return an error.
    #[test]
    fn receive_before_handshake_fails() {
        let mut page = vec![0u8; 4096];
        let mut chan = SharedMemoryChannel::new(&mut page);

        let err = chan.receive(&page).unwrap_err();
        assert!(
            err.contains("Handshake not completed"),
            "expected handshake error, got: {err}"
        );
    }

    /// Nonce counter must increment after each send, producing distinct ciphertexts.
    #[test]
    fn nonce_increments_across_sends() {
        let mut page = vec![0u8; 4096];
        let mut chan = SharedMemoryChannel::new(&mut page);

        // Set up guest key for handshake.
        let guest_secret = StaticSecret::random_from_rng(&mut rand::rng());
        let guest_pubkey = PublicKey::from(&guest_secret);
        page[OFF_GUEST_PUBKEY..OFF_GUEST_PUBKEY + 32].copy_from_slice(guest_pubkey.as_bytes());
        chan.handshake(&page).unwrap();

        // Send twice and capture the nonces.
        chan.send(&mut page, b"msg1").unwrap();
        let mut nonce1 = [0u8; 12];
        nonce1.copy_from_slice(&page[OFF_PAYLOAD..OFF_PAYLOAD + 12]);

        chan.send(&mut page, b"msg2").unwrap();
        let mut nonce2 = [0u8; 12];
        nonce2.copy_from_slice(&page[OFF_PAYLOAD..OFF_PAYLOAD + 12]);

        assert_ne!(nonce1, nonce2, "nonces must differ between sends");
        assert_eq!(nonce1, nonce_for(0));
        assert_eq!(nonce2, nonce_for(1));
    }

    /// Pubkey layout: host at [0..32], guest at [32..64], no overlap.
    #[test]
    fn pubkey_layout_non_overlapping() {
        let mut page = vec![0u8; 4096];
        let _chan = SharedMemoryChannel::new(&mut page);

        let host_pk = &page[0..32];
        assert_ne!(
            host_pk, &[0u8; 32],
            "host pubkey must be written at page[0..32]"
        );

        // Guest area must still be zero (guest hasn't written yet).
        let guest_pk = &page[32..64];
        assert_eq!(
            guest_pk, &[0u8; 32],
            "guest pubkey at page[32..64] must be zero before handshake"
        );

        // Command/status bytes at [64] and [65] must be idle.
        assert_eq!(page[64], CMD_IDLE);
        assert_eq!(page[65], STATUS_IDLE);
    }
}
