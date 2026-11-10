//! The `.elc` verifier as a WebAssembly module, for `site/verify.html`.
//!
//! No wasm-bindgen: three plain exports and a few lines of JavaScript glue
//! (`site/verify.js`), so rebuilding needs only `cargo` and the
//! `wasm32-unknown-unknown` target:
//!
//! ```text
//! cargo build -p ectoledger-elc-wasm --target wasm32-unknown-unknown --release
//! ```
//!
//! (`make wasm-verifier` does that and copies the result into `site/`.)
//!
//! The verification itself is [`ectoledger_elc::verify::verify`], the same
//! function `verify-cert` calls. Nothing here decides anything.
//!
//! ## Calling convention
//!
//! 1. `elc_alloc(n)` returns a buffer for the certificate bytes; write them in.
//! 2. `elc_verify(ptr, len, flags, key_ptr, key_len, ots_ptr, ots_len)` returns a pointer to a
//!    result buffer: a little-endian `u32` length, then that many bytes of
//!    UTF-8 JSON (a [`Report`], or `{"error": …}` for an unreadable file).
//! 3. `elc_free(ptr, n)` releases each buffer. For the result, `n` is the
//!    length prefix plus four.
//!
//! `flags`: bit 0 requires a signature (`--strict`), bit 1 requires a Bitcoin
//! anchor (`--require-anchor`). A non-empty key implies bit 0
//! (`--expected-key`). A non-empty `.ots` buffer is used as `verify-cert --ots`.

use ectoledger_elc::verify::{Report, Requirements, verify};

pub const FLAG_STRICT: u32 = 1;
pub const FLAG_REQUIRE_ANCHOR: u32 = 2;

/// Allocate `len` bytes for the caller to fill.
#[unsafe(no_mangle)]
pub extern "C" fn elc_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len.max(1));
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Release a buffer from `elc_alloc` or `elc_verify`.
///
/// # Safety
/// `ptr` must come from this module and `len` must be the length it was
/// allocated with (for a result buffer, the length prefix plus four).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn elc_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(unsafe { Vec::from_raw_parts(ptr, 0, len.max(1)) });
    }
}

/// Verify the certificate in `[ptr, ptr+len)` and return a result buffer.
///
/// # Safety
/// `ptr`/`len` and `key_ptr`/`key_len` must describe readable memory owned by
/// the caller (`key_len` may be 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn elc_verify(
    ptr: *const u8,
    len: usize,
    flags: u32,
    key_ptr: *const u8,
    key_len: usize,
    ots_ptr: *const u8,
    ots_len: usize,
) -> *mut u8 {
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let key = if key_len == 0 || key_ptr.is_null() {
        None
    } else {
        let raw = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };
        Some(String::from_utf8_lossy(raw).into_owned())
    };
    let ots = if ots_len == 0 || ots_ptr.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(ots_ptr, ots_len) }.to_vec())
    };
    into_result_buffer(verify_json(bytes, flags, key.as_deref(), ots))
}

/// The whole operation as a plain function: bytes in, JSON out. The native
/// tests call this; the export above only adds the memory handling. `ots` is a
/// kept `.ots` file, as `verify-cert --ots` takes.
pub fn verify_json(
    bytes: &[u8],
    flags: u32,
    expected_key: Option<&str>,
    ots: Option<Vec<u8>>,
) -> String {
    let cert = match ectoledger_elc::parse_certificate(bytes) {
        Ok(c) => c,
        Err(e) => {
            return serde_json::json!({ "error": format!("Could not read certificate: {e}") })
                .to_string();
        }
    };
    let req = Requirements {
        signature: flags & FLAG_STRICT != 0,
        expected_key: expected_key.map(str::to_string),
        anchor: flags & FLAG_REQUIRE_ANCHOR != 0,
        ots_file: ots,
        issuer: None,
    };
    let report: Report = verify(&cert, &req);
    let mut value = serde_json::to_value(&report).unwrap_or_default();
    if let Some(obj) = value.as_object_mut() {
        // The same final line the CLI prints, so the page never paraphrases it.
        obj.insert("verdict_line".into(), report.verdict_line().into());
        obj.insert("valid".into(), report.is_valid().into());
    }
    value.to_string()
}

fn into_result_buffer(json: String) -> *mut u8 {
    let body = json.into_bytes();
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    let ptr = out.as_mut_ptr();
    // Capacity equals length here, so elc_free(ptr, len + 4) reconstructs it.
    debug_assert_eq!(out.capacity(), out.len());
    std::mem::forget(out);
    ptr
}
