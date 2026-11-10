//! Apple Hypervisor enclave: boot, attest, round-trip, tear down.
//!
//! These need real hardware - Apple silicon, and a binary codesigned with
//! `entitlements.xml`. `make test-enclave-hv` does both. There is exactly one
//! legitimate skip, and it is narrow on purpose: the hypervisor being
//! unavailable, which is what happens inside a VM. Anything else is a failure.
//!
//! That distinction is the point of this file. It used to also skip when the
//! hypervisor *was* available and the key exchange had degraded, which is the
//! case these tests exist to catch - the target exited 0 for months while the
//! guest was dying on an undefined instruction before it ever published a key.

// The Apple Hypervisor allows one VM at a time per process, so these tests must
// not run concurrently. A static mutex serialises access.
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
static HV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The hypervisor is genuinely unavailable - nested virtualisation, or a
/// machine that does not have it. Not a stand-in for "something went wrong".
///
/// Narrower than "any `HypervisorError` from `VM create`", deliberately.
/// "owning resource is busy" is also a `HypervisorError` at that call, and it
/// means a *previous* VM in this process was never destroyed - the leak these
/// tests exist to catch. Treating it as an absent hypervisor would skip four of
/// the five tests here and put the false green back where it started.
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
fn hypervisor_absent(e: &str) -> bool {
    if !e.contains("VM create:") || e.contains("busy") {
        return false;
    }
    e.contains("unsupported operation") || e.contains("HypervisorError")
}

#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[test]
fn a_leaked_vm_is_not_mistaken_for_a_missing_hypervisor() {
    assert!(hypervisor_absent(
        "VM create: HypervisorError { code: -85377025, description: \"unsupported operation\" }"
    ));
    assert!(
        !hypervisor_absent(
            "VM create: HypervisorError { code: -85377022, description: \"owning resource is busy\" }"
        ),
        "a leaked VM must fail these tests, not skip them"
    );
    assert!(!hypervisor_absent(
        "guest trapped without publishing its boot sentinel (status byte 0x03)"
    ));
}

#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[test]
fn enclave_apple_boot() {
    let _guard = HV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    match ectoledger::enclave::test_enclave_boot() {
        Ok(()) => {}
        Err(e) if hypervisor_absent(&e) => {
            eprintln!("SKIPPED: Apple Hypervisor not available: {e}");
        }
        Err(e) => panic!("Apple Hypervisor boot failed: {e}"),
    }
}

/// Full lifecycle: boot, attest at the level claimed, send a message through
/// the encrypted channel, tear down.
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[test]
fn enclave_runtime_lifecycle() {
    let _guard = HV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use ectoledger::enclave::apple_hv::AppleHvEnclaveRuntime;
    use ectoledger::enclave::runtime::{EnclaveLevel, EnclaveRequest, EnclaveRuntime};

    let mut rt = AppleHvEnclaveRuntime::new();

    let attestation = match rt.initialize() {
        Ok(a) => a,
        Err(e) if hypervisor_absent(&e) => {
            eprintln!("SKIPPED: Apple Hypervisor not available: {e}");
            return;
        }
        // Every other error is a defect, including a failed key exchange.
        // `initialize` no longer has a degraded success to return.
        Err(e) => panic!("initialize failed: {e}"),
    };

    assert_eq!(
        attestation.level,
        EnclaveLevel::AppleHypervisor,
        "initialize returned a level other than the one it succeeded at"
    );
    assert_eq!(
        attestation.measurement_hash.len(),
        64,
        "measurement must be a hex SHA-256 of the unikernel image, got {:?}",
        attestation.measurement_hash
    );
    assert_eq!(rt.level(), EnclaveLevel::AppleHypervisor);

    // The guest is an echo responder, so equality here is not "the enclave did
    // something clever" - it is "these bytes were encrypted on the host,
    // decrypted inside the guest, re-encrypted there and decrypted back". Under
    // the bug this replaces, host and guest held different session keys and
    // this would fail to decrypt at all.
    let prompt = b"round-trip through the guest's AEAD".to_vec();
    let response = rt
        .execute(EnclaveRequest {
            prompt: prompt.clone(),
            model_id: "none".to_string(),
        })
        .expect("execute through the encrypted channel");
    assert_eq!(
        response.output, prompt,
        "the guest echoes; a mismatch means the two sides disagree on the key"
    );
    assert_eq!(response.attestation.level, EnclaveLevel::AppleHypervisor);

    // Several messages, because the nonce counter advances per send and a
    // channel that only survives one exchange is not a channel.
    for i in 0..3u8 {
        let msg = vec![i; 64 + i as usize];
        let out = rt
            .execute(EnclaveRequest {
                prompt: msg.clone(),
                model_id: "none".to_string(),
            })
            .unwrap_or_else(|e| panic!("execute #{i} failed: {e}"));
        assert_eq!(
            out.output, msg,
            "message {i} did not survive the round trip"
        );
    }

    rt.destroy().expect("destroy failed");

    // Executing after teardown must be refused rather than answered from a
    // cached attestation.
    let after = rt.execute(EnclaveRequest {
        prompt: b"after destroy".to_vec(),
        model_id: "none".to_string(),
    });
    assert!(
        after.is_err(),
        "execute must fail once the enclave is destroyed, got {after:?}"
    );
}

/// Boot, tear down, boot again in the same process.
///
/// Apple's Hypervisor permits one VM per process and `hv_vm_destroy` only runs
/// when the last `VirtualMachineInstance` reference drops. The vCPU and the
/// watchdog both hold that guard, so with the fields in the wrong order the VM
/// was never destroyed and the *second* `VirtualMachine::new()` failed with
/// "owning resource is busy" - invisible to any test that only booted once.
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[test]
fn the_vm_is_released_so_a_second_enclave_can_boot() {
    let _guard = HV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use ectoledger::enclave::apple_hv::AppleHvEnclaveRuntime;
    use ectoledger::enclave::runtime::EnclaveRuntime;

    let mut first = AppleHvEnclaveRuntime::new();
    match first.initialize() {
        Ok(_) => {}
        Err(e) if hypervisor_absent(&e) => {
            eprintln!("SKIPPED: Apple Hypervisor not available: {e}");
            return;
        }
        Err(e) => panic!("first initialize failed: {e}"),
    }
    first.destroy().expect("first destroy");

    let mut second = AppleHvEnclaveRuntime::new();
    second
        .initialize()
        .expect("second initialize - the first VM was not released");
    second.destroy().expect("second destroy");
}

/// A second `initialize` on a live runtime is refused rather than silently
/// leaking the first VM and failing further down.
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[test]
fn initializing_twice_is_refused() {
    let _guard = HV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use ectoledger::enclave::apple_hv::AppleHvEnclaveRuntime;
    use ectoledger::enclave::runtime::EnclaveRuntime;

    let mut rt = AppleHvEnclaveRuntime::new();
    match rt.initialize() {
        Ok(_) => {}
        Err(e) if hypervisor_absent(&e) => {
            eprintln!("SKIPPED: Apple Hypervisor not available: {e}");
            return;
        }
        Err(e) => panic!("initialize failed: {e}"),
    }

    let again = rt.initialize();
    assert!(
        again.is_err_and(|e| e.contains("already initialized")),
        "a second initialize must be refused"
    );
    rt.destroy().expect("destroy");
}

/// Teardown must not sit out the guest deadline.
///
/// The guest acknowledges `CMD_SHUTDOWN` with an `HVC` before halting. Without
/// that acknowledgement there is no event for the host to wait on - `halt()` is
/// a `wfe` loop that traps on nothing - so every `destroy` blocked for the full
/// five-second deadline and then gave up. Nothing failed; it was just slow, on
/// a path that runs at the end of every audit.
///
/// A wall-clock bound is the only way to observe this from outside, so the
/// bound is deliberately loose: two seconds against a deadline of five and an
/// observed teardown well under a tenth of a second. It cannot fire on a busy
/// machine without also meaning the acknowledgement is gone.
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[test]
fn teardown_is_acknowledged_rather_than_timed_out() {
    let _guard = HV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use ectoledger::enclave::apple_hv::AppleHvEnclaveRuntime;
    use ectoledger::enclave::runtime::EnclaveRuntime;

    let mut rt = AppleHvEnclaveRuntime::new();
    match rt.initialize() {
        Ok(_) => {}
        Err(e) if hypervisor_absent(&e) => {
            eprintln!("SKIPPED: Apple Hypervisor not available: {e}");
            return;
        }
        Err(e) => panic!("initialize failed: {e}"),
    }

    let started = std::time::Instant::now();
    rt.destroy().expect("destroy");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "destroy took {elapsed:?} - the guest is not acknowledging CMD_SHUTDOWN \
         and the host is waiting out its whole deadline"
    );
}
