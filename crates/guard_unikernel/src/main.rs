#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;

// Memory layout below must match host apple_hv.rs.
/// Base address of the 4 KiB shared IPC page inside guest RAM.
const SHARED_PAGE: *mut u8 = 0x4407_0000 as *mut u8;

// IPC offsets (must match host ipc.rs).
const OFF_HOST_PUBKEY: usize = 0;
const OFF_GUEST_PUBKEY: usize = 32;
const OFF_COMMAND: usize = 64;
const OFF_STATUS: usize = 65;
const OFF_REQ_LEN: usize = 68;
const OFF_RESP_LEN: usize = 72;
const OFF_GUEST_SEED: usize = 80;
const OFF_SENTINEL: usize = 112;
const OFF_PAYLOAD: usize = 128;

/// Length of the host-supplied secret-key seed.
const GUEST_SEED_LEN: usize = 32;

/// Maximum plaintext payload size (shared page minus header).
/// The 4 KiB page has 128 bytes of header; the remaining space holds
/// the encrypted payload (ciphertext + 12-byte nonce + 16-byte tag).
const MAX_PAYLOAD: usize = 4096 - OFF_PAYLOAD - 12 - 16;

/// Scratch buffer size: everything after the header.
const BUF_LEN: usize = 4096 - OFF_PAYLOAD;

// IPC command bytes written by the host at OFF_COMMAND.
const CMD_NONE: u8 = 0x00;
const CMD_REQUEST: u8 = 0x01;
const CMD_SHUTDOWN: u8 = 0xFF;

// Status bytes written by the guest at OFF_STATUS.
const STATUS_IDLE: u8 = 0x00;
const STATUS_BUSY: u8 = 0x01;
const STATUS_READY: u8 = 0x02;
const STATUS_ERROR: u8 = 0x03;

/// Written at `OFF_SENTINEL` once the guest is ready to serve requests.
///
/// No byte of it is zero, because the host zeroes the page before boot: a
/// sentinel with a NUL in it could be completed by memory the guest never
/// touched, and a guest that died halfway through writing it would still be
/// reported as ready.
///
/// It is written *last*, after the key exchange and after the guest public key
/// is in the page, so its presence means the whole boot sequence completed.
/// Writing it any earlier would let a guest that died mid-handshake look ready.
const SENTINEL: &[u8; 16] = b"ECTO-ENCLAVE-OK!";

// Channel crypto: protocol v2, must match host ipc.rs.

/// Protocol label, bound into both directional keys and every AAD.
const PROTOCOL: &[u8] = b"ectoledger-enclave-ipc-v2";

/// Direction bytes (AAD): host → guest requests and guest → host responses.
const DIR_HOST_TO_GUEST: u8 = 0x01;
const DIR_GUEST_TO_HOST: u8 = 0x02;

/// Derive the `(host→guest, guest→host)` keys from the X25519 shared secret.
fn directional_keys(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, shared_secret);
    let expand = |label: &[u8]| {
        let mut key = [0u8; 32];
        hkdf.expand_multi_info(&[PROTOCOL, label], &mut key)
            .expect("HKDF expand failed");
        key
    };
    (expand(b" host->guest"), expand(b" guest->host"))
}

/// Nonce for message `counter`: 8 bytes little-endian ‖ 4 zero bytes.
fn nonce_for(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// AAD for message `counter` in `direction`: `PROTOCOL ‖ direction ‖ counter`.
fn aad_for(direction: u8, counter: u64) -> [u8; 34] {
    let n = PROTOCOL.len();
    let mut aad = [0u8; 34];
    aad[..n].copy_from_slice(PROTOCOL);
    aad[n] = direction;
    aad[n + 1..].copy_from_slice(&counter.to_le_bytes());
    aad
}

// There is no entropy source in here, deliberately. The only architectural RNG available to
// a bare-metal aarch64 guest is `RNDR` (FEAT_RNG), and no Apple silicon
// implements it - `mrs` on an unimplemented system register is UNDEFINED, and
// with no vector table installed that ends the guest on the spot. Apple silicon
// is the only hardware this unikernel runs on, so a hardware-RNG path here
// would be code that cannot succeed anywhere it can execute.
//
// The secret is seeded by the host from the OS CSPRNG, through the shared
// page. See the module header of `crates/host/src/enclave/ipc.rs` for why that
// costs nothing in a two-party host↔guest channel.

// Entry point: pure assembly, link-section pinned.

global_asm!(
    r#"
    .section .text._start, "ax"
    .global _start
    .align 2
    _start:
        mov x0, #0
        movk x0, #0x4200, lsl #16
        mov sp, x0
        bl main
    1:  b 1b
    "#
);

#[inline(always)]
unsafe fn write_vol(addr: *mut u8, val: u8) {
    unsafe { addr.write_volatile(val) };
}

#[inline(always)]
unsafe fn read_vol(addr: *const u8) -> u8 {
    unsafe { addr.read_volatile() }
}

#[inline(always)]
fn dmb_ish() {
    unsafe { core::arch::asm!("dmb ish", options(nostack)) };
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> ! {
    // 1. Take the host-supplied seed and clear it from the page immediately.
    //
    // Order matters: the seed is this guest's private key material, and the
    // page stays mapped and readable for the whole session. Copy it out, wipe
    // the slot, and never read that slot again. The host checks the slot is
    // zero, which is how it knows a guest - rather than a stale page - got
    // this far.
    let mut seed = [0u8; GUEST_SEED_LEN];
    dmb_ish();
    unsafe {
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = SHARED_PAGE.add(OFF_GUEST_SEED + i).read_volatile();
        }
        for i in 0..GUEST_SEED_LEN {
            write_vol(SHARED_PAGE.add(OFF_GUEST_SEED + i), 0);
        }
    }
    dmb_ish();

    // An all-zero seed means the host did not write one. Refuse rather than
    // deriving a key from it: X25519 clamping would still yield a usable-looking
    // public key, the handshake would succeed, and the channel would be
    // encrypted under a key anyone could reproduce. Halt without the sentinel
    // so the host reports a guest that never became ready.
    if seed == [0u8; GUEST_SEED_LEN] {
        unsafe {
            write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_ERROR);
        }
        dmb_ish();
        unsafe {
            core::arch::asm!("hvc #0");
        }
        halt();
    }

    // 2. Derive the keypair from the seed.
    let guest_secret = x25519_dalek::StaticSecret::from(seed);
    let guest_pubkey = x25519_dalek::PublicKey::from(&guest_secret);
    seed.fill(0);

    // 3. Read the host public key and derive the shared secret.
    let mut host_pubkey_bytes = [0u8; 32];
    dmb_ish();
    unsafe {
        for (i, byte) in host_pubkey_bytes.iter_mut().enumerate() {
            *byte = SHARED_PAGE.add(OFF_HOST_PUBKEY + i).read_volatile();
        }
    }
    dmb_ish();

    let host_pubkey = x25519_dalek::PublicKey::from(host_pubkey_bytes);
    let shared_secret = guest_secret.diffie_hellman(&host_pubkey);

    // Derive one ChaCha20-Poly1305 key per direction, and build both ciphers
    // once; reuse them for the entire session.
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::AeadInPlace};
    let (mut request_key, mut response_key) = directional_keys(shared_secret.as_bytes());
    let request_cipher = ChaCha20Poly1305::new((&request_key).into());
    let response_cipher = ChaCha20Poly1305::new((&response_key).into());
    request_key.fill(0);
    response_key.fill(0);

    // 4. Publish the guest public key, then the sentinel - in that order.
    //
    // The sentinel is the host's "the guest is ready" signal, so anything the
    // host needs must already be in the page before it appears.
    dmb_ish();
    unsafe {
        for (i, &b) in guest_pubkey.as_bytes().iter().enumerate() {
            write_vol(SHARED_PAGE.add(OFF_GUEST_PUBKEY + i), b);
        }
    }
    dmb_ish();
    unsafe {
        for (i, &b) in SENTINEL.iter().enumerate() {
            write_vol(SHARED_PAGE.add(OFF_SENTINEL + i), b);
        }
    }
    dmb_ish();

    // 5. Signal the host that boot + handshake is complete (status = IDLE).
    unsafe {
        write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_IDLE);
    }
    dmb_ish();
    unsafe {
        core::arch::asm!("hvc #0");
    }

    // IPC poll loop protocol:
    //   1. Host writes encrypted request at OFF_PAYLOAD, length at OFF_REQ_LEN,
    //      then sets OFF_COMMAND = CMD_REQUEST and issues HVC to wake guest.
    //   2. Guest reads command byte; if CMD_REQUEST:
    //      a. Set status = BUSY
    //      b. Read payload; its nonce must equal the expected request counter,
    //         then decrypt (a refused request changes no counter)
    //      c. Process request (currently: echo back)
    //      d. Encrypt response, write at OFF_PAYLOAD, length at OFF_RESP_LEN
    //      e. Set status = READY, HVC to wake host
    //   3. If CMD_SHUTDOWN: break loop and halt.
    //   4. Otherwise: wait-for-event (WFE) and re-poll.

    // Per-direction counters; each advances only after a successful use.
    let mut recv_counter: u64 = 0;
    let mut send_counter: u64 = 0;

    loop {
        dmb_ish();
        let cmd = unsafe { read_vol(SHARED_PAGE.add(OFF_COMMAND)) };

        match cmd {
            CMD_SHUTDOWN => {
                // Acknowledge, then trap once more before halting.
                //
                // The HVC is the acknowledgement: without it the host has no
                // event to wait on and sits out its whole guest deadline on
                // every teardown, because `halt()` traps on nothing.
                unsafe {
                    write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_IDLE);
                    write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                }
                dmb_ish();
                unsafe {
                    core::arch::asm!("hvc #0");
                }
                break;
            }
            CMD_REQUEST => {
                // Mark busy while processing.
                unsafe {
                    write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_BUSY);
                }
                dmb_ish();

                // Read encrypted request length (little-endian u32 at OFF_REQ_LEN).
                let req_len = unsafe {
                    let b0 = read_vol(SHARED_PAGE.add(OFF_REQ_LEN)) as u32;
                    let b1 = (read_vol(SHARED_PAGE.add(OFF_REQ_LEN + 1)) as u32) << 8;
                    let b2 = (read_vol(SHARED_PAGE.add(OFF_REQ_LEN + 2)) as u32) << 16;
                    let b3 = (read_vol(SHARED_PAGE.add(OFF_REQ_LEN + 3)) as u32) << 24;
                    (b0 | b1 | b2 | b3) as usize
                };

                // Sanity check length: nonce (12) + tag (16) is the floor,
                // and the page's payload area is the ceiling.
                if !(28..=BUF_LEN).contains(&req_len) {
                    unsafe {
                        write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_ERROR);
                        write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                    }
                    dmb_ish();
                    unsafe { core::arch::asm!("hvc #0"); }
                    continue;
                }

                // Read encrypted payload: [nonce(12) | ciphertext+tag(N)]
                let mut enc_buf = [0u8; BUF_LEN];
                dmb_ish();
                unsafe {
                    for (i, byte) in enc_buf.iter_mut().enumerate().take(req_len) {
                        *byte = read_vol(SHARED_PAGE.add(OFF_PAYLOAD + i));
                    }
                }

                // Split nonce (first 12 bytes) and ciphertext+tag (rest).
                let nonce_bytes: [u8; 12] = {
                    let mut n = [0u8; 12];
                    n.copy_from_slice(&enc_buf[..12]);
                    n
                };
                let nonce = Nonce::from(nonce_bytes);
                let ct_len = req_len - 12;
                let mut plaintext_buf = [0u8; BUF_LEN];
                plaintext_buf[..ct_len].copy_from_slice(&enc_buf[12..12 + ct_len]);

                // Refuse a replayed or out-of-order request before decrypting.
                let next_recv = match recv_counter.checked_add(1) {
                    Some(n) if nonce_bytes == nonce_for(recv_counter) => n,
                    _ => {
                        unsafe {
                            write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_ERROR);
                            write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                        }
                        dmb_ish();
                        unsafe { core::arch::asm!("hvc #0"); }
                        continue;
                    }
                };

                // Decrypt in-place (tag is appended to ciphertext by ChaCha20-Poly1305).
                // Copy tag out first to avoid simultaneous mutable+immutable borrow.
                let mut tag_bytes = [0u8; 16];
                tag_bytes.copy_from_slice(&plaintext_buf[ct_len - 16..ct_len]);
                match request_cipher.decrypt_in_place_detached(
                    &nonce,
                    &aad_for(DIR_HOST_TO_GUEST, recv_counter),
                    &mut plaintext_buf[..ct_len - 16],
                    (&tag_bytes).into(),
                ) {
                    Ok(()) => {}
                    Err(_) => {
                        unsafe {
                            write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_ERROR);
                            write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                        }
                        dmb_ish();
                        unsafe { core::arch::asm!("hvc #0"); }
                        continue;
                    }
                }
                recv_counter = next_recv;

                let plaintext_len = ct_len - 16;

                // Phase 2.5: echo the plaintext back as the response.
                // Future phases will dispatch to policy evaluation / guard logic.
                let response = &plaintext_buf[..plaintext_len];

                // Encrypt response. Nonce and AAD come from the guest→host counter, which only
                // advances once the response is in the page.
                let resp_nonce = nonce_for(send_counter);
                let resp_nonce_obj = Nonce::from(resp_nonce);

                let resp_len = response.len();
                let next_send = match send_counter.checked_add(1) {
                    Some(n) if resp_len <= MAX_PAYLOAD => n,
                    _ => {
                        unsafe {
                            write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_ERROR);
                            write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                        }
                        dmb_ish();
                        unsafe { core::arch::asm!("hvc #0"); }
                        continue;
                    }
                };

                // Prepare buffer: copy plaintext response, then encrypt in-place
                // and append tag.
                let mut resp_buf = [0u8; BUF_LEN];
                resp_buf[..resp_len].copy_from_slice(response);
                let tag = match response_cipher.encrypt_in_place_detached(
                    &resp_nonce_obj,
                    &aad_for(DIR_GUEST_TO_HOST, send_counter),
                    &mut resp_buf[..resp_len],
                ) {
                    Ok(tag) => tag,
                    Err(_) => {
                        unsafe {
                            write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_ERROR);
                            write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                        }
                        dmb_ish();
                        unsafe { core::arch::asm!("hvc #0"); }
                        continue;
                    }
                };
                // Append tag after ciphertext.
                resp_buf[resp_len..resp_len + 16].copy_from_slice(&tag);
                let total_resp = 12 + resp_len + 16; // nonce + ciphertext + tag

                // Write response: [nonce(12) | ciphertext(N) | tag(16)]
                dmb_ish();
                unsafe {
                    // Write nonce first
                    for (i, &b) in resp_nonce.iter().enumerate() {
                        write_vol(SHARED_PAGE.add(OFF_PAYLOAD + i), b);
                    }
                    // Write ciphertext + tag
                    for (i, &b) in resp_buf.iter().enumerate().take(resp_len + 16) {
                        write_vol(SHARED_PAGE.add(OFF_PAYLOAD + 12 + i), b);
                    }
                    // Write response length (LE u32)
                    let len_bytes = (total_resp as u32).to_le_bytes();
                    for (i, &b) in len_bytes.iter().enumerate() {
                        write_vol(SHARED_PAGE.add(OFF_RESP_LEN + i), b);
                    }
                }
                dmb_ish();
                send_counter = next_send;

                // Signal completion.
                unsafe {
                    write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                    write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_READY);
                }
                dmb_ish();
                unsafe { core::arch::asm!("hvc #0"); }
            }
            // CMD_NONE, and anything the host has no business writing.
            _ => {
                // No pending command - wait for event (low-power poll).
                unsafe { core::arch::asm!("wfe") };
            }
        }
    }

    halt();
}

/// Park the vCPU forever.
///
/// Reached after a clean `CMD_SHUTDOWN`, and on the refusal path when the host
/// supplied no seed. `wfe` rather than a spin so the vCPU is not burning a core
/// while the host tears the VM down.
fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}