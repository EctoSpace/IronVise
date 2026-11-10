//! Level 2 enclave: a bare-metal aarch64 unikernel under the Apple Hypervisor.
//!
//! The VM lives on a dedicated thread for its whole lifetime. `hv_vcpu_create`
//! binds a vCPU to the thread that created it and `hv_vcpu_run` returns
//! `HV_BAD_ARGUMENT` from any other one, so the vCPU cannot be created here and
//! run from a tokio worker later. [`AppleHvEnclaveRuntime`] therefore owns a
//! channel to that thread rather than owning the VM, and every operation is a
//! message.
//!
//! The wire protocol and page layout are in [`crate::enclave::ipc`].

#![cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

// Named imports rather than `applevisor::prelude::*`: the prelude exports its
// own single-parameter `Result<T>` alias, which shadows `std::result::Result`
// for the whole module and turns every `Result<T, String>` in the file into a
// confusing arity error.
use applevisor::memory::{MemPerms, Memory};
use applevisor::vcpu::{ExitReason, Reg, SysReg, Vcpu, VcpuExit};
use applevisor::vm::{GicDisabled, VirtualMachine, VirtualMachineInstance};

use crate::enclave::ipc::{self, SharedMemoryChannel};
use crate::enclave::runtime::{
    EnclaveAttestation, EnclaveLevel, EnclaveRequest, EnclaveResponse, EnclaveRuntime,
};

const GUEST_RAM_BASE: u64 = 0x4008_0000;
const GUEST_RAM_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

/// IPC shared page, at a fixed offset inside guest RAM.
/// Must match `SHARED_PAGE` in `guard_unikernel/src/main.rs`.
const SHARED_PAGE_IPA: u64 = 0x4407_0000;
const SHARED_PAGE_SIZE: usize = 4096;

/// The unikernel image, built by `build.rs` and embedded.
const PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/guard_unikernel.bin"));

// Exception classes below are ESR_EL2.EC, bits 31:26.

/// `HVC` executed from AArch64 - the guest deliberately trapping to us.
const EC_HVC64: u64 = 0x16;
/// A trapped `WFI`/`WFE`. The guest is idle, not broken.
const EC_WFX: u64 = 0x01;

/// What a guest exception means to the host.
///
/// The distinction this type exists to make is the one the old loop did not:
/// `ExitReason::EXCEPTION` covers both "the guest is handing control back on
/// purpose" and "the guest just died", and treating them alike is how an
/// undefined instruction came to look like a successful boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trap {
    /// The guest called `HVC`. This is the protocol's only rendezvous point.
    Hvc,
    /// The guest is parked on `WFI`/`WFE`. Step over it and carry on.
    Idle,
    /// The guest faulted. `.0` is the exception class for the report.
    Fault(u64),
}

/// Classify an `ESR_EL2` value.
fn classify(syndrome: u64) -> Trap {
    match (syndrome >> 26) & 0x3f {
        EC_HVC64 => Trap::Hvc,
        EC_WFX => Trap::Idle,
        ec => Trap::Fault(ec),
    }
}

/// Plain-English gloss for the exception classes this guest can realistically
/// hit, so a failure report names a cause rather than a number.
fn explain(ec: u64) -> &'static str {
    match ec {
        0x00 => " (unknown reason - usually an undefined instruction with no EL1 vector table)",
        0x07 => " (trapped SIMD/FP access - CPACR_EL1.FPEN is not set)",
        0x18 => " (trapped MSR/MRS - the guest read a system register this CPU does not implement)",
        0x20 | 0x21 => " (instruction abort - fetch from unmapped memory)",
        0x24 | 0x25 => " (data abort - load/store to unmapped memory)",
        _ => "",
    }
}

/// Upper bound on vCPU exits while waiting for one `HVC`.
///
/// Generous, because idle `WFx` traps and virtual-timer activations both land
/// here and neither is progress. Small enough that a guest stuck in a loop
/// fails in milliseconds instead of hanging the caller.
const EXIT_BUDGET: usize = 512;

/// How long the guest gets to reach its next `HVC` before the host gives up.
///
/// Everything the guest does between traps is a handful of microseconds of
/// X25519, HKDF and ChaCha20 on a dedicated core, so this is four orders of
/// magnitude of headroom. It exists because `hv_vcpu_run` does not return while
/// the guest spins: a guest that panics lands in a bare `loop {}`, which traps
/// on nothing, and without a deadline the calling thread is simply gone.
const GUEST_DEADLINE: Duration = Duration::from_secs(5);

/// What the host sends the guest to prove the channel works before reporting
/// an Apple Hypervisor attestation.
const CHANNEL_PROBE: &[u8] = b"ectoledger-enclave-channel-probe-v1";

/// Forces the vCPU out of `hv_vcpu_run` when the guest overruns its deadline.
///
/// `hv_vcpus_exit` is the only way to interrupt a running vCPU, and it must be
/// called from a different thread than the one blocked in `run`. One long-lived
/// thread per enclave, rather than one per request: arming is a mutex write.
struct Watchdog {
    deadline: Arc<Mutex<Option<Instant>>>,
    fired: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Watchdog {
    fn new(vm: VirtualMachineInstance<GicDisabled>, vcpu: &Vcpu) -> Self {
        let deadline: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        let fired = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));

        let handle = vcpu.get_handle();
        let (d, f, s) = (deadline.clone(), fired.clone(), stop.clone());
        let thread = std::thread::Builder::new()
            .name("ectoledger-enclave-watchdog".to_string())
            .spawn(move || {
                // 20ms granularity: far finer than the deadline, coarse enough
                // that an idle enclave costs nothing measurable.
                while !s.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(20));
                    let expired = matches!(*d.lock().expect("watchdog deadline"), Some(at) if Instant::now() >= at);
                    if expired {
                        *d.lock().expect("watchdog deadline") = None;
                        f.store(true, Ordering::SeqCst);
                        if !handle.is_valid() {
                            continue;
                        }
                        if let Err(e) = vm.vcpus_exit(std::slice::from_ref(&handle)) {
                            tracing::error!("[enclave/apple_hv] vcpus_exit failed: {e:?}");
                        }
                    }
                }
            })
            .ok();

        Self {
            deadline,
            fired,
            stop,
            thread,
        }
    }

    fn arm(&self) {
        self.fired.store(false, Ordering::SeqCst);
        *self.deadline.lock().expect("watchdog deadline") = Some(Instant::now() + GUEST_DEADLINE);
    }

    fn disarm(&self) {
        *self.deadline.lock().expect("watchdog deadline") = None;
    }

    fn expired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// SHA-256 measurement of the embedded unikernel image.
fn measurement() -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(PAYLOAD))
}

/// A booted enclave. Constructed and used only on the worker thread.
///
/// **Field order is drop order, and it is load-bearing here.** Apple's
/// Hypervisor allows one VM per process, and `hv_vm_destroy` only runs when the
/// last `VirtualMachineInstance` drops - the vCPU and the watchdog's clone both
/// hold strong references to the same guard, and neither of them calls
/// `hv_vm_destroy` itself. With `_vm` declared first it dropped first, the
/// count never reached zero from a `VirtualMachineInstance`, and the VM was
/// leaked: the next `VirtualMachine::new()` in the same process failed with
/// "owning resource is busy". So: watchdog joined first, then the vCPU, then
/// the mapping, and `_vm` last.
struct Enclave {
    /// Joined first, so the watchdog stops being able to call `hv_vcpus_exit`
    /// before the vCPU it targets is destroyed.
    watchdog: Watchdog,
    vcpu: Vcpu,
    ipc: SharedMemoryChannel,
    /// Host-side address of the shared IPC page, into `_ram`.
    page: *mut u8,
    /// Backing store for the guest's RAM. Outlives every use of `page`.
    _ram: Memory,
    /// Last: the reference whose drop actually tears the VM down.
    _vm: VirtualMachineInstance<GicDisabled>,
}

impl Enclave {
    /// Host view of the shared page.
    ///
    /// Rebuilt per call rather than stored as a slice, because a struct holding
    /// both `_ram` and a slice borrowed from it would be self-referential.
    ///
    /// # Safety
    /// `page` points `SHARED_PAGE_SIZE` bytes into the mapping owned by `_ram`,
    /// which outlives every borrow returned here, and the guest is not running
    /// while the host holds this (the vCPU only runs inside `run_to_hvc`).
    fn page(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.page, SHARED_PAGE_SIZE) }
    }

    /// Boot the VM, complete the key exchange, and prove the channel carries a
    /// message before claiming a hypervisor-backed attestation.
    fn boot() -> Result<(Self, EnclaveAttestation), String> {
        if PAYLOAD.is_empty() {
            return Err("guard_unikernel.bin payload is empty".to_string());
        }

        let vm = VirtualMachine::new().map_err(|e| format!("VM create: {e:?}"))?;
        let mut ram = vm
            .memory_create(GUEST_RAM_SIZE)
            .map_err(|e| format!("RAM alloc: {e:?}"))?;

        // Load the image and zero the rest, so nothing the guest reads is
        // whatever the allocator last left there.
        unsafe {
            std::ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), ram.host_addr(), PAYLOAD.len());
            std::ptr::write_bytes(
                ram.host_addr().add(PAYLOAD.len()),
                0,
                GUEST_RAM_SIZE - PAYLOAD.len(),
            );
        }
        ram.map(GUEST_RAM_BASE, MemPerms::RWX)
            .map_err(|e| format!("RAM map: {e:?}"))?;

        let page_ptr = unsafe {
            ram.host_addr()
                .add((SHARED_PAGE_IPA - GUEST_RAM_BASE) as usize)
        };
        let page = unsafe { std::slice::from_raw_parts_mut(page_ptr, SHARED_PAGE_SIZE) };

        // Host public key and the guest's secret-key seed, both before boot.
        let ipc = SharedMemoryChannel::new(page);
        SharedMemoryChannel::seed_guest(page)?;

        let vcpu = vm
            .vcpu_create()
            .map_err(|e| format!("vCPU create: {e:?}"))?;
        vcpu.set_reg(Reg::PC, GUEST_RAM_BASE)
            .map_err(|e| format!("Set PC: {e:?}"))?;
        vcpu.set_reg(Reg::CPSR, 0x3C5)
            .map_err(|e| format!("Set CPSR: {e:?}"))?;
        vcpu.set_sys_reg(SysReg::SCTLR_EL1, 0x0)
            .map_err(|e| format!("Set SCTLR_EL1: {e:?}"))?;
        // Enable FP/SIMD at EL1: rustc emits NEON for memory moves, and with
        // CPACR_EL1.FPEN clear those trap and take the guest down.
        vcpu.set_sys_reg(SysReg::CPACR_EL1, 3 << 20)
            .map_err(|e| format!("Set CPACR_EL1: {e:?}"))?;

        let watchdog = Watchdog::new(vm.clone(), &vcpu);
        let mut enclave = Self {
            watchdog,
            vcpu,
            ipc,
            page: page_ptr,
            _ram: ram,
            _vm: vm,
        };

        enclave.run_to_hvc()?;

        // Order of checks is the order the guest does the work, so the first
        // failure names the earliest thing that went wrong.
        if !SharedMemoryChannel::guest_consumed_seed(enclave.page()) {
            return Err(
                "guest did not consume its seed - it never reached key derivation".to_string(),
            );
        }
        if !SharedMemoryChannel::guest_booted(enclave.page()) {
            let status = enclave.page()[ipc::OFF_STATUS];
            return Err(format!(
                "guest trapped without publishing its boot sentinel (status byte {status:#04x}); \
                 it refused to start rather than finishing the handshake"
            ));
        }

        // Read the guest's public key and derive the session key. A failure
        // here is a bug in this repo, not an environment: both sides ship
        // together and the guest has just told us it finished.
        let page_snapshot = enclave.page().to_vec();
        enclave.ipc.handshake(&page_snapshot)?;

        // Prove the key actually agrees. Deriving a key is not evidence that
        // the two sides derived the *same* key: a sentinel placed where it can
        // overlap the host public key can corrupt it before the guest reads
        // it, producing different keys on each side silently - see ipc.rs's
        // "Why the sentinel is not at offset 0". Nothing but a round trip
        // through the channel catches that.
        let echoed = enclave.round_trip(CHANNEL_PROBE)?;
        if echoed != CHANNEL_PROBE {
            return Err(format!(
                "channel probe came back altered: sent {} bytes, received {} that do not match; \
                 host and guest have not agreed on a session key",
                CHANNEL_PROBE.len(),
                echoed.len()
            ));
        }

        let attestation = EnclaveAttestation {
            level: EnclaveLevel::AppleHypervisor,
            measurement_hash: measurement(),
            raw_attestation: None,
        };
        Ok((enclave, attestation))
    }

    /// Resume the guest until it traps with `HVC`.
    ///
    /// Every other exit is either progress-free (an idle `WFx`, a virtual
    /// timer) or a fault. The old version of this loop broke on *any*
    /// `ExitReason::EXCEPTION`, which meant a guest that died on an undefined
    /// instruction was indistinguishable from one that had finished its work
    /// and trapped on purpose - the failure this whole path was built around.
    fn run_to_hvc(&self) -> Result<(), String> {
        self.watchdog.arm();
        let outcome = self.run_to_hvc_inner();
        self.watchdog.disarm();
        outcome
    }

    fn run_to_hvc_inner(&self) -> Result<(), String> {
        for _ in 0..EXIT_BUDGET {
            self.vcpu.run().map_err(|e| format!("vCPU run: {e:?}"))?;
            let exit = self.vcpu.get_exit_info();

            if self.watchdog.expired() {
                let pc = self.vcpu.get_reg(Reg::PC).unwrap_or(0);
                return Err(format!(
                    "guest did not reach its next HVC within {}s and was forced out at \
                     PC {pc:#018x} - it is spinning without trapping, which is what a panic \
                     in the unikernel looks like from here (its panic handler is a bare loop)",
                    GUEST_DEADLINE.as_secs()
                ));
            }

            if exit.reason != ExitReason::EXCEPTION {
                // CANCELED / VTIMER_ACTIVATED / UNKNOWN: nothing to handle, and
                // the guest has not asked us for anything. Resume it.
                continue;
            }

            match classify(exit.exception.syndrome) {
                Trap::Hvc => return Ok(()),
                Trap::Idle => {
                    // A trapped WFx does not advance PC - the preferred return
                    // address is the WFx itself - so resuming without stepping
                    // over it re-executes it forever.
                    let pc = self
                        .vcpu
                        .get_reg(Reg::PC)
                        .map_err(|e| format!("read PC after WFx: {e:?}"))?;
                    self.vcpu
                        .set_reg(Reg::PC, pc + 4)
                        .map_err(|e| format!("step over WFx: {e:?}"))?;
                }
                Trap::Fault(ec) => return Err(self.fault(ec, &exit)),
            }
        }
        Err(format!(
            "guest did not trap with HVC within {EXIT_BUDGET} vCPU exits"
        ))
    }

    /// Describe a guest fault in enough detail to find it without a debugger.
    fn fault(&self, ec: u64, exit: &VcpuExit) -> String {
        let pc = self.vcpu.get_reg(Reg::PC).unwrap_or(0);
        let esr = self.vcpu.get_sys_reg(SysReg::ESR_EL1).unwrap_or(0);
        let elr = self.vcpu.get_sys_reg(SysReg::ELR_EL1).unwrap_or(0);
        let far = self.vcpu.get_sys_reg(SysReg::FAR_EL1).unwrap_or(0);
        let meaning = explain(ec);
        format!(
            "guest faulted instead of trapping with HVC: EC {ec:#04x}{meaning}, \
             ESR_EL2 {:#018x}, guest VA {:#018x}, IPA {:#018x}, \
             PC {pc:#018x}, ESR_EL1 {esr:#018x}, ELR_EL1 {elr:#018x}, FAR_EL1 {far:#018x}",
            exit.exception.syndrome,
            exit.exception.virtual_address,
            exit.exception.physical_address,
        )
    }

    /// Encrypt `plaintext` into the page, run the guest until it answers, and
    /// decrypt what it wrote back.
    fn round_trip(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        // Checked here so an oversize prompt is a clear error rather than a
        // decrypt failure or a guest that refuses the length and says nothing.
        let max = ipc::MAX_CIPHERTEXT - 16;
        if plaintext.len() > max {
            return Err(format!(
                "payload is {} bytes; the shared page holds at most {max}",
                plaintext.len()
            ));
        }

        // Split the borrow: `send` needs the page mutably, and it also needs
        // `self.ipc` mutably for the nonce counter.
        let page_ptr = self.page;
        let page = unsafe { std::slice::from_raw_parts_mut(page_ptr, SHARED_PAGE_SIZE) };
        self.ipc.send(page, plaintext)?;

        self.run_to_hvc()?;

        let page = unsafe { std::slice::from_raw_parts(page_ptr, SHARED_PAGE_SIZE) };
        let status = page[ipc::OFF_STATUS];
        if status != ipc::STATUS_RESPONSE_READY {
            return Err(format!(
                "guest answered with status {status:#04x}, expected \
                 {:#04x} (response ready); it rejected the request rather than serving it",
                ipc::STATUS_RESPONSE_READY
            ));
        }
        self.ipc.receive(page)
    }

    /// Ask the guest to halt, and give it one chance to acknowledge.
    ///
    /// Best-effort by design: the VM is about to be destroyed either way, and a
    /// guest that has already wedged must not stop the host from tearing down.
    fn shutdown(&mut self) {
        let page_ptr = self.page;
        let page = unsafe { std::slice::from_raw_parts_mut(page_ptr, SHARED_PAGE_SIZE) };
        page[ipc::OFF_COMMAND] = ipc::CMD_SHUTDOWN;
        if let Err(e) = self.run_to_hvc() {
            tracing::debug!("[enclave/apple_hv] guest did not acknowledge shutdown: {e}");
        }
    }
}

enum Job {
    Execute {
        payload: Vec<u8>,
        reply: Sender<Result<Vec<u8>, String>>,
    },
    Shutdown {
        reply: Sender<()>,
    },
}

struct Worker {
    /// `Sender` is `Send` but not `Sync`, and `EnclaveRuntime` requires `Sync`.
    /// The mutex also serialises requests, which the single vCPU requires
    /// anyway - two concurrent `execute` calls would interleave writes into one
    /// shared page.
    jobs: Mutex<Sender<Job>>,
    thread: Option<JoinHandle<()>>,
}

/// Own the VM for the lifetime of the enclave and serve jobs against it.
fn serve(ready: Sender<Result<EnclaveAttestation, String>>, jobs: Receiver<Job>) {
    let mut enclave = match Enclave::boot() {
        Ok((enclave, attestation)) => {
            // A receiver that has already hung up means `initialize` gave up on
            // us; tear the VM down rather than leaking it.
            if ready.send(Ok(attestation)).is_err() {
                return;
            }
            enclave
        }
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };

    while let Ok(job) = jobs.recv() {
        match job {
            Job::Execute { payload, reply } => {
                let _ = reply.send(enclave.round_trip(&payload));
            }
            Job::Shutdown { reply } => {
                enclave.shutdown();
                let _ = reply.send(());
                return;
            }
        }
    }
    // The sender was dropped without a Shutdown - `destroy` was never called.
    // Halt the guest anyway before the VM goes away with the thread's stack.
    enclave.shutdown();
}

/// Apple Hypervisor Framework enclave runtime (Level 2).
///
/// Boots a bare-metal aarch64 unikernel, establishes an X25519 +
/// ChaCha20-Poly1305 channel over a shared page, and routes requests through
/// it. Every method is a message to the thread that owns the VM.
pub struct AppleHvEnclaveRuntime {
    worker: Option<Worker>,
    attestation: Option<EnclaveAttestation>,
}

impl Default for AppleHvEnclaveRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl AppleHvEnclaveRuntime {
    pub fn new() -> Self {
        Self {
            worker: None,
            attestation: None,
        }
    }
}

impl EnclaveRuntime for AppleHvEnclaveRuntime {
    /// Boot the enclave, or fail.
    ///
    /// There is no degraded success: a handshake failure is never downgraded
    /// to a `SoftwareHardened` attestation. Silently continuing over an
    /// unencrypted channel after being asked for a hardware-isolated one would
    /// report an isolation guarantee that is not true, and nothing forces a
    /// caller to notice that the level has dropped. On hardware where the
    /// hypervisor works, a failed handshake is a defect in this repository;
    /// where it does not, `VirtualMachine::new` is what fails, and that is a
    /// different error with a different message.
    fn initialize(&mut self) -> Result<EnclaveAttestation, String> {
        if self.worker.is_some() {
            return Err("enclave already initialized".to_string());
        }

        let (ready_tx, ready_rx) = channel();
        let (jobs_tx, jobs_rx) = channel();
        let thread = std::thread::Builder::new()
            .name("ectoledger-enclave".to_string())
            .spawn(move || serve(ready_tx, jobs_rx))
            .map_err(|e| format!("spawn enclave thread: {e}"))?;

        let attestation = match ready_rx.recv() {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => {
                let _ = thread.join();
                return Err(e);
            }
            Err(_) => {
                let _ = thread.join();
                return Err("enclave thread died before reporting boot status".to_string());
            }
        };

        self.worker = Some(Worker {
            jobs: Mutex::new(jobs_tx),
            thread: Some(thread),
        });
        self.attestation = Some(attestation.clone());
        Ok(attestation)
    }

    /// Send bytes into the enclave and return what it sends back.
    ///
    /// The unikernel is an echo responder: it decrypts the request, re-encrypts
    /// the same bytes, and returns them. So the output equals the input - but
    /// it has been through the encrypted channel and the guest's AEAD, which is
    /// the part worth asserting. It is *not* inference; the guest runs no
    /// model, and this returns what the guest actually produced rather than
    /// echoing the request on the host side and calling it an enclave response.
    fn execute(&self, req: EnclaveRequest) -> Result<EnclaveResponse, String> {
        let worker = self
            .worker
            .as_ref()
            .ok_or("enclave not initialized - call initialize() first")?;
        let attestation = self
            .attestation
            .clone()
            .ok_or("enclave initialized without an attestation")?;

        let (reply_tx, reply_rx) = channel();
        {
            let jobs = worker
                .jobs
                .lock()
                .map_err(|_| "enclave request channel poisoned".to_string())?;
            jobs.send(Job::Execute {
                payload: req.prompt,
                reply: reply_tx,
            })
            .map_err(|_| "enclave thread has exited".to_string())?;
        }
        let output = reply_rx
            .recv()
            .map_err(|_| "enclave thread exited without answering".to_string())??;

        Ok(EnclaveResponse {
            output,
            attestation,
        })
    }

    fn level(&self) -> EnclaveLevel {
        EnclaveLevel::AppleHypervisor
    }

    fn destroy(&mut self) -> Result<(), String> {
        self.attestation = None;
        let Some(mut worker) = self.worker.take() else {
            return Ok(());
        };

        // Ask for a clean halt, then wait for the thread so the VM is really
        // gone when this returns. Apple's Hypervisor allows one VM per process,
        // so a caller that initializes again immediately depends on it.
        let (reply_tx, reply_rx) = channel();
        if let Ok(jobs) = worker.jobs.lock() {
            let _ = jobs.send(Job::Shutdown { reply: reply_tx });
        }
        let _ = reply_rx.recv();
        drop(worker.jobs);

        if let Some(thread) = worker.thread.take()
            && thread.join().is_err()
        {
            return Err("enclave thread panicked during shutdown".to_string());
        }
        Ok(())
    }
}

impl Drop for AppleHvEnclaveRuntime {
    fn drop(&mut self) {
        if let Err(e) = self.destroy() {
            tracing::warn!("[enclave/apple_hv] destroy during drop failed: {e}");
        }
    }
}

/// Boot the enclave and tear it straight back down.
///
/// Delegates to the same path `initialize` uses rather than keeping a second
/// copy of the VM setup. The two copies had already drifted - this one read the
/// sentinel at the wrong offset and never looked at the handshake at all - and
/// a boot check that exercises different code from the thing it is checking is
/// worth less than no boot check.
pub fn test_enclave_boot() -> Result<(), String> {
    let mut rt = AppleHvEnclaveRuntime::new();
    rt.initialize()?;
    rt.destroy()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The classification that the old loop did not make.
    ///
    /// `ExitReason::EXCEPTION` covers a deliberate `HVC`, an idle `WFE`, and a
    /// guest dying on an undefined instruction. Breaking out on all three is
    /// how the host came to read a half-written page and call it a booted
    /// enclave, so these are spelled out with the real `ESR_EL2` encodings.
    #[test]
    fn exception_classes_are_told_apart() {
        // ESR_EL2 for HVC64: EC 0x16, IL 1, imm16 0.
        assert_eq!(classify(0x5800_0000), Trap::Hvc);
        // EC 0x01, WFI/WFE trapped.
        assert_eq!(classify(0x0400_0000), Trap::Idle);
        // EC 0x00 - "unknown", which is where an undefined instruction with no
        // EL1 vector table lands. This is the one the guest actually hit.
        assert_eq!(classify(0x0000_0000), Trap::Fault(0x00));
        // EC 0x18, trapped MSR/MRS - reading RNDR on a CPU without FEAT_RNG.
        assert_eq!(classify(0x6000_0000), Trap::Fault(0x18));
        // EC 0x24, data abort from a lower exception level.
        assert_eq!(classify(0x9000_0000), Trap::Fault(0x24));
    }

    /// Bits above 31 must not leak into the class.
    #[test]
    fn only_the_exception_class_field_is_read() {
        // ISS bits set below, ISS2 bits set above: neither is part of EC.
        assert_eq!(classify(0x5800_0000 | 0xFF_FFFF), Trap::Hvc);
        assert_eq!(classify(0x5800_0000 | (0x1F << 32)), Trap::Hvc);
    }

    /// A fault report names a cause for the classes this guest can hit.
    #[test]
    fn faults_that_have_a_likely_cause_say_so() {
        assert!(explain(0x00).contains("undefined instruction"));
        assert!(explain(0x18).contains("system register"));
        assert!(explain(0x24).contains("data abort"));
        // An unexpected class still reports, it just does not guess.
        assert_eq!(explain(0x3f), "");
    }

    /// The probe is not the empty string, and does not fit in a nonce.
    ///
    /// A zero-length probe would round-trip through a broken channel as
    /// happily as a working one - `encrypt("")` and `decrypt` of the result
    /// still succeed - so the check in `boot` would prove nothing.
    #[test]
    fn the_channel_probe_carries_something_to_compare() {
        assert!(
            CHANNEL_PROBE.len() > 16,
            "the probe must be long enough that a mismatch is unambiguous"
        );
        assert!(CHANNEL_PROBE.len() < ipc::MAX_CIPHERTEXT - 16);
    }
}
