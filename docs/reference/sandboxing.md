# Cross-Platform Sandbox Parity Documentation

## Overview

IronVise provides multiple sandboxing mechanisms to isolate untrusted code execution:
- **Linux**: Landlock (LSM) + seccomp-BPF + rlimits
- **macOS**: Seatbelt (`sandbox_init` FFI) - deprecated API but functional; fail-closed by default (`ECTO_SANDBOX_PERMISSIVE=true` opts into advisory fallback)
- **Windows**: Job Objects with UI restrictions
- **Cross-platform**: Docker/Podman containers + Firecracker microVMs

This document outlines the implementation details, security properties, and parity analysis of each platform.

## Platform Support Matrix

| Feature | Linux | macOS | Windows | Docker | Firecracker | Enclave L1 | Enclave L2 | Enclave L3 |
|---------|-------|-------|---------|--------|-------------|------------|------------|------------|
| Filesystem isolation | ✅ Landlock | ⚠️ Seatbelt (ws r/w only) | ⚠️ Job Object | ✅ Read-only | ✅ Guest FS | ❌ | ✅ Guest VM | ✅ Remote TEE |
| Process isolation | ✅ Seccomp | ⚠️ Seatbelt (process-exec allowed) | ✅ Job Object | ✅ Container | ✅ microVM | ❌ | ✅ vCPU | ✅ TEE |
| Resource limits | ✅ rlimits | ❌ not enforced | ⚠️ Job Object | ✅ cgroups | ✅ vCPU/Mem | ❌ | ✅ VM config | ✅ Enclave config |
| Memory confidentiality | ❌ | ❌ | ❌ | ❌ | ⚠️ KVM | ✅ mlock+zeroize | ✅ HV isolation | ✅ HW encryption |
| Attestation | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ Self-report | ✅ vCPU state | ✅ COSE-Sign1 |
| Cross-platform | N/A | N/A | N/A | ✅ Yes | ❌ Linux only | ✅ All | ❌ macOS only | ✅ Linux/Win |

## Detailed Implementation Analysis

### Linux Sandbox (Landlock + seccomp-BPF)

**When enabled**: Compile with `--features sandbox` on Linux

#### Landlock (Read-only Workspace)
- **LSM module** providing MAC (Mandatory Access Control)
- **Rules**: Read-only access to workspace directory tree
- **Fallback**: none by default. A kernel without Landlock (or with it disabled)
  is a sandbox failure and the command is aborted; `ECTO_SANDBOX_PERMISSIVE=true`
  runs it unconfined instead. An older ABI that enforces part of the ruleset
  still runs, confined to what that kernel supports.
- **Code reference**: `crates/sandbox/src/sandbox/linux.rs:apply_landlock()`

```rust
// Landlock V3 ABI
- Read-only access to specified workspace path
- Denies all write operations inside workspace
```

#### seccomp-BPF (Strict Syscall Allowlist)
- **Main process** (`serve`, `audit` and the other database commands): an
  allowlist installed after database setup. It is per-thread: it covers the
  main thread and every thread and child process started after it (the
  guard worker, `run_command` children, SQLite connection threads opened
  later), not the async runtime's worker threads, which exist before it.
  `tests/audit_cli_linux.rs` runs a real `audit` under it.
- **Target**: Guard-worker process (model validation subprocess)
- **Mode**: EPERM on denied syscalls (not KILL, so errors surface)
- **Denied**: ptrace, process_vm_readv, kexec_load, and all others not on allowlist
- **Allowed syscalls**: ~70 syscalls for tokio, HTTP, stdin/stdout JSON protocol
- **Architecture support**: x86_64, aarch64 (silent no-op on others)
- **Install failure is fatal.** If the kernel rejects the main-process filter,
  `serve` exits. It does not continue unsandboxed. `EINVAL` (os error 22) is
  what QEMU user-mode returns for `seccomp`, including an amd64 image run on
  Apple Silicon. The same binary installs the filter on real x86_64.
- **Code reference**: `crates/sandbox/src/sandbox/seccomp.rs:apply_guard_worker_seccomp()`

#### Resource Limits (rlimits)
- **CPU time**: 30 seconds hard limit (RLIMIT_CPU)
- **Address space**: 512 MiB max (RLIMIT_AS)
- **File descriptors**: 64 max (RLIMIT_NOFILE) - prevents FD exhaustion attacks
- **Code reference**: `crates/sandbox/src/sandbox/linux.rs:apply_rlimits()`

**Security properties**:
- ✅ Kernel-enforced isolation (cannot be bypassed from userspace)
- ✅ Multi-layer defense: filesystem + process + resource limits
- ✅ Prevents prompt-injection attacks via binary execution
- ⚠️ Requires Linux kernel ≥ 5.13 (Landlock support)
- ⚠️ Landlock LSM must not be disabled in kernel config

---

### macOS Sandbox (Seatbelt)

**Status**: ⚠️ **SUPPORTED (deprecated API, fail-closed by default)**

#### Implementation:

IronVise calls Apple's `sandbox_init()` C API via FFI to apply a Seatbelt
profile to each child process. While Apple has deprecated the public header,
the underlying XNU sandbox enforcement mechanism is still active and used by
first-party macOS system services.

**Seatbelt profile enforces:**
- Read-only access to system libraries (`/usr/lib`, `/System`, `/Library/Frameworks`)
- Read/write access restricted to the workspace directory only
- Read access to the root directory entry `/` itself (not its contents):
  dyld and libc read it at process start. Without it, on macOS 27 every
  command aborted with SIGABRT before running (fixed 2026-10-08)
- Metadata only (`stat`, never contents) of the workspace's parent folders:
  `ls -la` lists `..` and path resolution walks up, so without it an agent
  listing its own folder exits 1. A parent folder cannot be listed or read
- `(deny network*)` - blocks all network access from child processes
- `(allow process-exec)` - **required** because the profile is installed in the
  `pre_exec` hook, so the pending `exec()` must be permitted; command
  restrictions are instead enforced by the tripwire layer and the executable allowlist
- `(deny signal)` - prevents signal injection

**Fail-closed runtime behaviour:** The FFI binding always compiles so macOS SDK
changes never break the build. At runtime, if `sandbox_init()` fails, the
command is **aborted by default** (fail-closed, matching Linux and Windows). Set
`ECTO_SANDBOX_PERMISSIVE=true` to opt into logging a warning and continuing
with advisory tripwires only.

#### Known limitations:

- `git` (and other Xcode command-line shims in `/usr/bin`) does not run
  under the profile: the shim needs the active developer directory and the
  Xcode or Command Line Tools tree, which the profile does not open. Use a
  Homebrew `git` in `/opt/homebrew/bin`, or run without the sandbox.
- A parent folder of the workspace can be stat'ed but not listed: `ls ..`
  is refused, `ls -la` in the workspace is not.

1. **No per-process network isolation**: Seatbelt `(deny network*)` blocks
   socket creation but the parent process retains full network access
2. **No resource limits**: macOS has no rlimit-equivalent enforcement via Seatbelt
3. **API stability risk**: `sandbox_init()` may be removed in future macOS releases
4. **Landlock/seccomp unavailable**: These are Linux-only; Seatbelt is the macOS equivalent

#### Recommendation for macOS production users:

```bash
# Option 1: Run inside Linux container (recommended)
docker run -it --rm \
  -v /path/to/audit:/audit \
  -e AGENT_LLAMA_URL=http://host.docker.internal:11434 \
  ghcr.io/ectospace/ironvise:latest \
  audit "Your audit goal"

# Option 2: Run inside Lima VM (macOS Docker Desktop alternative)
# or Colima

# Option 3: Accept no kernel-level isolation
# - Document as non-production or dev-only
# - Rely on process isolation + Docker/Podman containers for `run_command`
```

#### Current behavior on macOS:
```rust
pub fn apply_child_sandbox(workspace: &Path) -> Result<(), SandboxError> {
    #[cfg(target_os = "macos")]
    {
        apply_seatbelt(workspace)?;  // sandbox_init FFI
    }
}
```

- Seatbelt profile applied to each child process via Unix `pre_exec` hook
- If `sandbox_init()` fails, aborts the command by default (`ECTO_SANDBOX_PERMISSIVE=true` opts into advisory tripwire fallback)
- Docker/Podman sandboxes are still available for `run_command` intents
- Firecracker is not available (Linux + KVM only)

---

### Windows Sandbox (Job Objects)

**When enabled**: Automatically on Windows (no feature flag required)

#### Job Object Implementation
- **Windows API**: `CreateJobObjectW()` + `AssignProcessToJobObject()`
- **Scope**: Applies to all child processes spawned by IronVise
- **Reference**: `crates/sandbox/src/sandbox/win32.rs:apply_windows_job_object()`

#### Configuration
1. **KILL_ON_JOB_CLOSE**: Ensures child processes are terminated when job handle closes
   - Prevents orphan LLM tool processes
   - Guarantees cleanup on supervisor crash

2. **UI Restrictions** (JOBOBJECT_BASIC_UI_RESTRICTIONS):
   - `UILIMIT_DESKTOP` - no desktop switching
   - `UILIMIT_DISPLAYSETTINGS` - no display mode changes
   - `UILIMIT_EXITWINDOWS` - no log-off/shutdown
   - `UILIMIT_GLOBALATOMS` - no global atom table access
   - `UILIMIT_HANDLES` - no raw handle access
   - `UILIMIT_READCLIPBOARD` - no clipboard theft
   - `UILIMIT_WRITECLIPBOARD` - no clipboard injection
   - `UILIMIT_SYSTEMPARAMETERS` - no system parameter changes

**Security properties**:
- ✅ Guarantees process cleanup (no orphan processes)
- ✅ Prevents UI escalation vectors (clipboard, display settings)
- ⚠️ **Limited filesystem isolation**: Job Objects do not restrict file access; relies on NTFS permissions
- ⚠️ **No syscall filtering**: Cannot prevent dangerous Windows APIs
- ⚠️ **Cooperative model**: Process can still execute most code before job termination

**Limitations vs. Linux**:
| Aspect | Linux | Windows |
|--------|-------|---------|
| Filesystem access control | ✅ Landlock read-only enforcement | ⚠️ NTFS ACLs only (process-controlled) |
| Syscall filtering | ✅ seccomp-BPF blocks dangerous syscalls | ❌ No equivalent (user-mode hook needed) |
| Resource limits | ✅ rlimits (CPU, memory, FDs) | ⚠️ Job Objects support memory/CPU but not enforced uniformly |
| Process isolation | ✅ seccomp + rlimits | ✅ Job Object cleanup guarantee |

---

## Container & MicroVM Sandboxes

### Docker/Podman (Cross-platform)

**Availability**: Linux, macOS (via Docker Desktop), Windows (via WSL2 or native)

**Configuration**: 
```bash
export ECTO_DOCKER_IMAGE=alpine:3.19
export ECTO_DOCKER_MEMORY=256m
export ECTO_DOCKER_CPUS=1
export ECTO_DOCKER_TIMEOUT=30
export ECTO_DOCKER_RUNTIME=auto  # auto-detect docker or podman
```

**Isolation guarantees**:
- ✅ `--network=none` - no network access
- ✅ `--read-only` - immutable root filesystem
- ✅ `--security-opt no-new-privileges` - blocks privilege escalation
- ✅ `--user nobody` - unprivileged execution
- ✅ `--memory` / `--cpus` - resource limits via cgroups

**Use case**: Recommended for dev/test and for macOS production (where native sandboxing is unavailable)

---

### Firecracker (Linux + KVM only)

**Availability**: Linux with KVM support (compile with `--features sandbox-firecracker`)

**Prerequisites**:
- Firecracker binary (≥1.5) at configurable path
- Linux kernel image (`vmlinux`)
- Root filesystem image (`rootfs.ext4`)

**Isolation guarantees** (once a working guest image is supplied - see below):
- ✅ Hardware-level KVM isolation (hypervisor-based)
- ✅ Each `run_command` in ephemeral microVM
- ✅ Guest kernel enforces isolation
- ✅ microVM destroyed after command completes

**Use case**: Maximum security for untrusted prompt injection attacks; suitable for multi-tenant SaaS

> ### ⚠ Neither provisioning script gives you a working tier by default
>
> `scripts/setup-firecracker.sh` installs the Firecracker project's **`hello`
> demo rootfs/kernel** (x86_64 only - there is no aarch64 build upstream, so on
> aarch64 the script installs the binary only and points you at
> `provision-firecracker.sh`). This is a **connectivity / plumbing test image
> only**: it proves KVM, the firecracker binary, the kernel, and the block
> devices are wired together. It boots to a login prompt and contains **no
> IronVise guest agent**, so it will not execute any intent.
>
> `scripts/provision-firecracker.sh` tries the Firecracker project's official
> Ubuntu CI rootfs first, which is a real Linux userspace but **also does not
> implement the IronVise guest protocol** - same limitation as the `hello`
> image. If that download is unavailable or fails checksum verification, it
> falls back to **building its own minimal busybox rootfs** whose init script
> *does* implement the contract below (reads `/dev/vdb`, runs
> `params.command`, writes to the serial console, reboots). Delete an
> already-installed official rootfs and re-run with `--rootfs busybox` to
> force this working fallback directly - a plain re-run tries the official
> rootfs again first, which is up more often than not.
>
> With a non-protocol rootfs the Firecracker tier starts a microVM and then
> produces no output. Because sandbox failures are fail-closed by default, the
> action is **aborted**, not silently run on the host
> (`ECTO_SANDBOX_PERMISSIVE=true` opts into degraded execution).
>
> Both scripts were fixed in 0.8.0 (see
> [CHANGELOG.md](../../CHANGELOG.md)): they now
> download, checksum-verify and install correctly on Linux/KVM. That fix was
> verified on macOS down to the download/checksum/extraction logic
> (`--download-only DIR --arch x86_64|aarch64` on both scripts); actually
> booting a microVM on Linux + KVM hardware was not re-verified here.
>
> If you want working isolation today without building or fetching a guest
> image, use the Docker tier (`ECTO_DOCKER_IMAGE`), which runs with
> `--network=none --read-only --security-opt no-new-privileges`.

### Firecracker guest image contract

The host (`crates/sandbox/src/sandbox/firecracker.rs::run_in_firecracker`) does the
following for each intent, and your guest image must hold up its end:

**What the host provides**

| Device | Contents |
|---|---|
| `/dev/vda` | Your rootfs, attached as the root device |
| `/dev/vdb` | The intent, written as a **raw JSON file image** - not a filesystem, so read the block device directly rather than mounting it |
| `/dev/ttyS0` | Serial console; Firecracker surfaces guest output here as the host process's stdout |

The intent JSON has the shape the executor already validated:

```json
{
  "action": "run_command",
  "params": { "command": "ls -la /workspace" },
  "justification": "…",
  "reasoning": "…"
}
```

**What your guest init must do**

1. **Read** the raw bytes of `/dev/vdb` and strip trailing NUL padding.
2. **Parse** the JSON; handle `action == "run_command"` and take
   `params.command`. Any other action should be treated as unsupported.
3. **Execute** that command inside the guest.
4. **Write** the command's stdout and stderr to `/dev/ttyS0`.
5. **Shut down** (e.g. `reboot -f`) so the ephemeral VM exits and the host
   collects the output. The host applies its own outer timeout
   (`ECTO_FC_TIMEOUT_SECS`) if the guest hangs.

A minimal init is a few lines of shell in an initramfs or an ext4 image whose
`/sbin/init` is a script:

```sh
#!/bin/sh
# Minimal IronVise Firecracker guest init (illustrative).
mount -t proc proc /proc 2>/dev/null
INTENT=$(tr -d '\0' < /dev/vdb)
CMD=$(printf '%s' "$INTENT" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
[ -n "$CMD" ] && sh -c "$CMD" > /dev/ttyS0 2>&1
reboot -f
```

Use a real JSON parser rather than the `sed` above in anything you deploy -
it is shown only to make the shape of the contract concrete. Build the image
with your usual tooling (`mkfs.ext4` over a directory, Buildroot, or
`docker export` piped into an ext4 image).

---

## Confidential AI Enclave Architecture

IronVise provides a three-tier enclave architecture that places AI inference inside a confidentiality boundary invisible to the host OS. Each tier offers increasing hardware isolation and produces attestation evidence embedded in `.elc` certificates.

### Enclave Level 1 - Software Hardened

**Feature flag**: `--features enclave`\
**Platforms**: All (Linux, macOS, Windows)\
**Code**: `crates/host/src/enclave/software.rs`

**Mechanism**:
- `libc::mlock()` pins inference buffers in physical RAM (prevents swap-to-disk)
- All buffers are `zeroize`d on drop (prevents cold-boot recovery)
- Delegates to the existing `LlmBackend` for actual inference

**Security properties**:
- ✅ Prevents secrets leaking to swap / page file
- ✅ Zeroizes memory on teardown
- ⚠️ No process isolation - host OS can still read memory
- ⚠️ Attestation is self-reported (no hardware root of trust)

**Attestation**: SHA-256 of the LLM backend identifier; no raw blob.

---

### Enclave Level 2 - Apple Hypervisor (macOS aarch64)

**Feature flag**: `--features sandbox-apple-enclave`\
**Platforms**: macOS on Apple Silicon only\
**Code**: `crates/host/src/enclave/apple_hv.rs` + `crates/guard_unikernel/`

**Mechanism**:
1. A bare-metal aarch64 unikernel (`guard_unikernel`) is compiled to `aarch64-unknown-none` and stripped to raw machine code via `llvm-objcopy`.
2. The host boots the unikernel inside an Apple Hypervisor Framework VM (`applevisor` crate), on a thread that owns the VM for its whole lifetime - `hv_vcpu_create` binds the vCPU to its creating thread.
3. A 4 KiB shared memory page at guest physical `0x44070000` provides the IPC channel. The layout is documented in `crates/host/src/enclave/ipc.rs`.
4. Before boot the host writes its X25519 public key and a 32-byte CSPRNG seed into the page. The guest derives its own keypair from that seed, wipes the slot, publishes its public key, and only then writes the boot sentinel.
5. X25519 key exchange + ChaCha20-Poly1305 AEAD encrypts all prompt/response data over the shared page.
6. The guest triggers `HVC #0` to signal completion; the host reads the encrypted response. The host distinguishes that `HVC` from a guest fault by the `ESR_EL2` exception class, and gives up on a guest that does not reach one within five seconds.
7. `initialize` sends a probe through the finished channel and checks it comes back intact before reporting the attestation. Both sides deriving *a* key is not evidence that they derived the *same* key.

**Security properties**:
- ✅ Hardware vCPU isolation (Apple Hypervisor Framework)
- ✅ Encrypted IPC - the plaintext is not readable by other processes on the machine, and the shared page holds only ciphertext
- ⚠️ **Not confidential from the host.** The host generates the guest's key seed, so it can reconstruct the session key. That is inherent rather than incidental: the guest has no entropy source (no Apple silicon implements `FEAT_RNG`, so `RNDR` is an undefined instruction), and the host loads the guest image and owns every byte of its RAM regardless. This tier isolates the *guest* from the rest of the machine; it does not hide the guest from the process that booted it.
- ⚠️ Apple Hypervisor has no remote attestation API (local trust only)
- ⚠️ Requires codesigning with `com.apple.security.hypervisor` entitlement

**Attestation**: SHA-256 of the unikernel binary payload. `raw_attestation` is `None` - there is no vCPU register dump or signed report at this tier, and nothing else to embed.

**What the guest does**: it terminates the encrypted channel and echoes. It runs no model. `execute` returns what the guest actually sent back, having gone through the guest's AEAD, rather than echoing on the host side and attaching an attestation to it - but the round trip is the claim, not inference.

**Requirements**:
- macOS 11+ on Apple Silicon (M1/M2/M3/M4)
- Entitlements XML: `entitlements.xml` with `com.apple.security.hypervisor = true`
- Test binary must be codesigned: `codesign -s - --entitlements entitlements.xml --force <binary>`

---

### Enclave Level 3 - Remote Hardware Enclave (Linux / Windows)

**Feature flag**: `--features enclave-remote`\
**Platforms**: Any (connects to remote TEE over HTTPS)\
**Code**: `crates/host/src/enclave/remote.rs`

**Mechanism**:
1. The host generates a fresh random challenge nonce and `POST /enclave/attest`s it (CBOR `{"nonce": bytes}`); the remote enclave returns a COSE-Sign1 attestation document (CBOR-encoded, AWS Nitro NSM format).
2. The host verifies the document before trusting anything in it (`crates/host/src/enclave/nitro_attestation.rs`): the COSE_Sign1 signature (ES384) over the Sig_structure; the certificate chain (`cabundle` root-first, then the signing `certificate`) up to the pinned AWS Nitro root (exact DER match); each certificate's validity at the verification time; the `digest` field is `SHA384`; the document's `nonce` equals the challenge just sent; and, when configured, the PCR0/1/2/8 policy. Any failure is an `initialize()` error - no session is established.
3. Only once verified: extracts the PCR0 measurement and the enclave's session public key from the document.
4. X25519 key exchange with the enclave's (now-trusted) session public key.
5. `POST /enclave/infer` - sends encrypted prompt, receives encrypted response.
6. ChaCha20-Poly1305 AEAD (protocol `ectoledger-enclave-remote-v2`) with one HKDF-SHA256 key per direction (salt = host pubkey ‖ enclave pubkey, info = protocol ‖ `" host->enclave"` or `" enclave->host"`), an AAD that binds direction, counter and both public keys, and a response nonce that must equal the counter of the request it answers.

**Security properties**:
- ✅ Hardware-backed TEE isolation (AWS Nitro)
- ✅ Remote attestation with cryptographic proof of enclave identity (COSE signature + certificate chain to the pinned AWS Nitro root; AMD SEV-SNP / Intel TDX documents are not parsed - this verifier is Nitro-specific)
- ✅ End-to-end encrypted channel (prompt never visible to cloud host)
- ✅ Certificate chain validation against the pinned AWS Nitro root (not a generic CA trust store)
- ✅ Nonce challenge closes the reflected attestation issue: the document nonce must equal the challenge just sent
- ⚠️ Requires trusted remote enclave endpoint
- ⚠️ Network latency for each inference call
- ⚠️ Enclave identity (PCR0/1/2/8) is unchecked unless the corresponding `ECTO_ENCLAVE_REMOTE_PCR*` variable is set
- ⚠️ Not wired into the agent loop (`AgentLoopConfig.enclave` is always `None`)

**Attestation**: PCR0 hash (SHA-384, from the verified document) or SHA-256 of the enclave module ID if PCR0 is absent; raw COSE-Sign1 blob preserved.

**Environment variables**:
```bash
export ECTO_ENCLAVE_REMOTE_URL=https://enclave.example.com
# Optional PCR policy - when set, a mismatching document is refused:
export ECTO_ENCLAVE_REMOTE_PCR0=<hex SHA-384>
export ECTO_ENCLAVE_REMOTE_PCR1=<hex SHA-384>
export ECTO_ENCLAVE_REMOTE_PCR2=<hex SHA-384>
export ECTO_ENCLAVE_REMOTE_PCR8=<hex SHA-384>
```

---

### Enclave Routing Logic

> **Not wired up.** `select_enclave` has no callers, and `AgentLoopConfig::enclave`
> is `None` at every one of its four construction sites - so the cognitive loop
> never routes a prompt through an enclave, whatever features are compiled in.
> The runtimes below are real and tested: `tests/enclave_apple_boot.rs` boots the
> unikernel on Apple Hypervisor, completes an X25519 handshake and round-trips a
> message through the encrypted channel. What does not exist is the wiring from
> configuration to the agent loop. The table describes what the router *would*
> select, and is kept because that selection logic is written and unit-tested,
> not because anything calls it today.

The `EnclaveRouter` (`crates/host/src/enclave/router.rs`) selects the best available tier:

| Priority | Condition | Tier |
|----------|-----------|------|
| 1 | `ECTO_ENCLAVE_REMOTE_URL` set + `enclave-remote` feature | Level 3 - Remote Hardware |
| 2 | macOS aarch64 + `sandbox-apple-enclave` feature | Level 2 - Apple Hypervisor |
| 3 | `enclave` feature enabled | Level 1 - Software Hardened |
| 4 | No enclave feature | No enclave (plain LLM) |

Explicit routing via `EnclaveRoute` enum overrides auto-detection.

---

### IPC Shared Memory Layout

The shared memory page (4 KiB at guest physical `0x44070000`, matching `crates/host/src/enclave/ipc.rs` and `crates/guard_unikernel`) uses the following byte-range layout for encrypted communication between host and guest:

```text
Byte Range      Size   Field                                  Direction
──────────      ────   ─────                                  ─────────
  [0..32)        32    Host X25519 public key                  Host → Guest
 [32..64)        32    Guest X25519 public key                 Guest → Host
 [64..65)         1    Command byte (0x00=idle, 0x01=evaluate,
                         0x02=ack, 0xFF=shutdown)              Host → Guest
 [65..66)         1    Status byte (0x00=booting, 0x01=ready,
                         0x02=done, 0xFE=err, 0xFF=halted)     Guest → Host
 [66..68)         2    Reserved (alignment padding)
 [68..72)         4    Request length (LE u32)                Host → Guest
 [72..76)         4    Response length (LE u32)               Guest → Host
 [76..80)         4    Protocol version (`2`, LE u32)
 [80..112)       32    Guest ephemeral entropy seed           Host → Guest
[112..128)       16    Attestation sentinel `ECTO-ENCLAVE-OK!` Guest → Host
[128..4096)      ..    Payload: Nonce (12B) ‖ AEAD ciphertext (max 3968B)
```

**Byte-range summary** (the two critical ranges the handshake depends on):
- `page[0..32]`  - **host public key**: written by the host *before* booting the guest vCPU.
- `page[32..64]` - **guest public key**: written by the guest immediately after boot; host reads after first `HVC #0`.

**Key derivation**:
1. Host generates ephemeral X25519 keypair, writes public key to `page[0..32]`.
2. Guest generates ephemeral X25519 keypair, writes public key to `page[32..64]`.
3. Both sides compute `shared_secret = X25519(my_secret, their_pubkey)`.
4. Session keys = `HKDF-SHA256(shared_secret, info = "ectoledger-enclave-ipc-v2 host->guest")` and `HKDF-SHA256(shared_secret, info = "ectoledger-enclave-ipc-v2 guest->host")` → one 32-byte ChaCha20-Poly1305 key per direction, each with its own counter (nonce = counter as 8 bytes LE ‖ 4 zero bytes, AAD = protocol ‖ direction ‖ counter), and the receiver rejects any nonce that is not its expected counter.

**ARM memory ordering - `DMB ISH` requirements**:

All reads and writes to the shared memory page **must** be flanked by `DMB ISH` (Data Memory Barrier, Inner Shareable) instructions on aarch64 to prevent ARM weak-memory reordering between the host CPU core and the guest vCPU.

The unikernel (`crates/guard_unikernel/src/main.rs`) implements this via a Rust helper:

```rust
#[inline(always)]
fn dmb_ish() {
    unsafe { core::arch::asm!("dmb ish", options(nostack)) };
}
```

Every shared-page access is wrapped:

```rust
// Writing guest pubkey to page[32..64]:
dmb_ish();
unsafe {
    for (i, &b) in guest_pubkey.as_bytes().iter().enumerate() {
        SHARED_PAGE.add(OFF_GUEST_PUBKEY + i).write_volatile(b);
    }
}
dmb_ish();

// Reading host pubkey from page[0..32]:
dmb_ish();
unsafe {
    for (i, byte) in host_pubkey_bytes.iter_mut().enumerate() {
        *byte = SHARED_PAGE.add(OFF_HOST_PUBKEY + i).read_volatile();
    }
}
dmb_ish();
```

**Ordering is a correctness requirement, not only a barrier requirement.** The
guest publishes its public key *before* the sentinel, and the host treats the
sentinel as "everything else in this page is already there". Writing the
sentinel first - which is what the unikernel used to do, at offset 0, on top of
the host's public key - made a guest that died during key derivation
indistinguishable from one that had finished, and corrupted the very key the
guest was about to read. Barriers do not help with a field that is in the wrong
place.

**Why `DMB ISH` is mandatory:**
- ARM's weak memory model allows stores and loads to be reordered across cores.
- Without barriers, the guest may read stale host pubkey bytes from `page[0..32]`, causing an X25519 key mismatch and silent decryption failure.
- The `ISH` (Inner Shareable) domain is sufficient because host and guest share the same physical memory within the Apple Hypervisor's memory map.
- `volatile` read/write alone is **not enough** - it prevents compiler reordering but not hardware reordering.

---

### Enclave Attestation in `.elc` Certificates

When an enclave is active during a session, the attestation evidence is embedded as an **Enclave Attestation Pillar** in the `.elc` certificate:

```json
{
  "enclave_attestation": {
    "level": "apple_hypervisor",
    "measurement_hash": "a1b2c3d4e5f6…",
    "raw_attestation_hex": "d284…"  // only for hardware enclaves
  }
}
```

- The `enclave_attestation` field is **included** in the Ed25519 signing payload, making it tamper-evident.
- The `raw_attestation_hex` contains the full COSE-Sign1 blob (Level 3) or is `null` (Levels 1 and 2 - neither produces a signed report).
- The `verify-cert` tool displays enclave level, measurement hash, and raw blob size.
- With `--features enclave-remote`, the verifier additionally validates the COSE-Sign1 envelope structure.

---

## Parity Analysis by Use Case

### Use Case: Prevent LLM Prompt Leakage

**Threat**: Host process memory dump reveals plaintext AI prompts containing sensitive audit data

| Platform | Mechanism | Effectiveness |
|----------|-----------|----------------|
| Linux | No memory protection by default | 🚫 Vulnerable |
| macOS | No memory protection by default | 🚫 Vulnerable |
| Windows | No memory protection by default | 🚫 Vulnerable |
| Docker | Container memory visible to host | 🚫 Vulnerable |
| Firecracker | Guest kernel isolation | ⚠️ KVM hypervisor can read guest memory |
| Enclave L1 | mlock + zeroize | ⚠️ Prevents swap leak; host can still read |
| Enclave L2 | Apple HV + encrypted IPC | ✅ Prompt encrypted in shared memory |
| Enclave L3 | Hardware TEE + COSE-Sign1 | ✅ Prompt encrypted end-to-end |

**Recommendation**: Use Enclave Level 2 (macOS) or Level 3 (Linux/Windows) for sessions handling sensitive data.

### Use Case: Prevent Token Extraction via `run_command`

**Threat**: Agent runs `echo $SECRET_API_KEY` via untrusted `run_command` intent

| Platform | Mechanism | Effectiveness |
|----------|-----------|----------------|
| Linux | Landlock hides files, seccomp blocks filesystem calls | ✅ Blocks |
| macOS | None (Docker recommended) | 🚫 Vulnerable |
| Windows | Job Object (no filesystem isolation) | 🚫 Vulnerable (if secret in env var) |
| Docker | Read-only FS + `--network=none` | ✅ Blocks |
| Firecracker | Guest kernel isolation | ✅ Blocks |

**Recommendation**: 
- Linux production: Use native Landlock + seccomp
- macOS production: Run inside Linux container
- Windows production: Use Docker or validate env var filtering

### Use Case: Prevent Prompt Injection via Binary PATH

**Threat**: Attacker injects `PATH=/tmp/evil run_command 'ls'` to execute malicious binary

| Platform | Mechanism | Effectiveness |
|----------|-----------|----------------|
| Linux | Landlock read-only workspace, seccomp allowlist | ✅ Blocks |
| macOS | None (Docker recommended) | 🚫 Vulnerable |
| Windows | Job Object + process isolation | ⚠️ Blocks if binary not on native PATH |
| Docker | Read-only FS | ✅ Blocks |
| Firecracker | Guest kernel isolation | ✅ Blocks |

### Use Case: Prevent Resource Exhaustion

**Threat**: Malicious command forks bomb or exhausts memory

| Platform | Mechanism | Effectiveness |
|----------|-----------|----------------|
| Linux | rlimits (CPU, memory, FDs) | ✅ Stops at 30s CPU or 512 MiB |
| macOS | None | 🚫 Vulnerable |
| Windows | Job Object (memory limits supported but not enforced uniformly) | ⚠️ Partial |
| Docker | cgroups (memory, CPU) | ✅ Stops at configured limit |
| Firecracker | vCPU/memory limits | ✅ Enforced by hypervisor |

---

## Configuration Recommendations

### Development Environment
```bash
# macOS or Windows dev
export ECTO_DOCKER_IMAGE=alpine:3.19
export ECTO_DOCKER_RUNTIME=auto
# Runs audit inside lightweight container for basic isolation
```

### Production: Linux
```bash
# Native Linux with kernel sandbox
cargo build --release --features sandbox
./ironvise audit "Your goal" \
  --policy audit_policy.toml
# Landlock + seccomp + rlimits apply automatically
```

### Production: macOS
```bash
# Run inside container
docker run -v /audit-workspace:/audit \
  ghcr.io/ectospace/ironvise:latest \
  audit "Your goal" --policy audit_policy.toml
# Container provides filesystem and process isolation
```

### Production: Windows
```bash
# Option 1: Docker Desktop (recommended)
docker run -v C:\audit-workspace:C:\audit `
  ghcr.io/ectospace/ironvise:latest `
  audit "Your goal" --policy audit_policy.toml

# Option 2: Native (limited isolation via Job Objects)
ironvise.exe audit "Your goal" `
  --policy audit_policy.toml
# Job Object applies UI restrictions and cleanup guarantee
```

### Production: Maximum Security (any platform)
```bash
# Run inside Firecracker (Linux only)
cargo build --release --features sandbox,sandbox-firecracker
export ECTO_FC_BINARY=/usr/local/bin/firecracker
export ECTO_FC_KERNEL=/opt/ectoledger/vmlinux
export ECTO_FC_ROOTFS=/opt/ectoledger/rootfs.ext4
./ironvise audit "Your goal"
# Each run_command executes in ephemeral KVM microVM
```

---

## Security Guarantee Summary

### Linux (with `--features sandbox`)
✅ **Principle of least privilege**: Workspace read-only, syscalls allowlisted, resources limited\
✅ **Multi-layer defense**: Filesystem + process + resource levels\
✅ **Kernel-enforced**: Cannot bypass from userspace\
📝 **Assumption**: Kernel LSM and seccomp compiled in; Landlock ABI V3+ supported

### macOS
✅ **Native Seatbelt kernel sandbox** (`sandbox_init` FFI): workspace-only file access, `(deny network*)`, `(deny signal)` - applied to each child via the `pre_exec` hook\
⚠️ **process-exec allowed / no resource limits**: `(allow process-exec)` is required in `pre_exec`; command restrictions rely on the tripwire layer + executable allowlist. Fail-closed if `sandbox_init` fails (`ECTO_SANDBOX_PERMISSIVE=true` opts into advisory fallback)\
✅ **Docker container option**: Provides additional filesystem + process isolation\
📝 **Recommendation**: Seatbelt is active by default; containers are recommended for stronger isolation in production

### Windows
⚠️ **Partial isolation**: Process cleanup, UI restrictions\
❌ **No filesystem isolation**: Relies on NTFS permissions\
❌ **No syscall filtering**: Cannot prevent dangerous Windows APIs\
✅ **Docker option**: Provides filesystem + resource isolation\
📝 **Recommendation**: Use Docker for production; native sandbox is advisory-only

### Docker (all platforms)
✅ **Cross-platform consistency**\
✅ **Read-only FS + network isolation**\
✅ **Resource limits (cgroups)**\
⚠️ **Container escape possible** (kernel vulnerability)\
📝 **Use case**: Recommended default for macOS/Windows production

### Firecracker (Linux only)
✅ **Hardware-level isolation (KVM)**\
✅ **Ephemeral microVM per command**\
✅ **Strongest isolation available**\
⚠️ **Complex setup** (kernel, rootfs, firecracker binary)\
📝 **Use case**: Maximum security for multi-tenant or adversarial scenarios

---

## Testing Cross-Platform Parity

### Linux Test: Verify Landlock + seccomp active
```bash
# Check if sandbox feature is compiled in
strings target/release/ironvise | grep -q "Landlock" && echo "✅ Landlock support compiled"

# Run audit and check logs (requires RUST_LOG=debug)
RUST_LOG=debug cargo run --features sandbox -- audit "test goal" 2>&1 | grep -E "Landlock|seccomp|rlimit"
```

### Windows Test: Verify Job Object applied
```powershell
# Job Objects are process-internal (no direct CLI visibility)
# Verify behavior: Create `run_command` that tries to switch desktops or modify system parameters
# Should fail silently or return restricted error
```

### Docker Test: Verify container isolation
```bash
# Inside container, should be read-only:
docker run --rm alpine:3.19 touch /test.txt
# Should fail: "Read-only file system"

# Should have no network:
docker run --network=none --rm alpine:3.19 ping 8.8.8.8
# Should timeout or fail
```

### Firecracker Test: Verify microVM isolation
```bash
# microVM should be destroyed after command
# Check /tmp for leftover sockets or images - should be none
ls -la /tmp | grep firecracker
# Should return nothing if cleanup is working
```

### Enclave Test: IPC crypto round-trip
```bash
# Runs without Apple Hypervisor - pure crypto verification
cargo test --features enclave -p ectoledger --lib -- enclave::ipc::tests
# Should pass: round_trip_encrypt_decrypt
```

### Enclave Test: Apple Hypervisor boot (macOS Apple Silicon only)
```bash
# Requires codesigning - the test binary must have the hypervisor entitlement.
# Step 1: Build without running
cargo test --features sandbox-apple-enclave --no-run

# Step 2: Codesign the test binary (find the latest one)
BIN=$(ls -t target/debug/deps/enclave_apple_boot-* | grep -v '\.' | head -1)
codesign -s - --entitlements entitlements.xml --force "$BIN"

# Step 3: Run
"$BIN" --nocapture
# Should pass: enclave_apple_boot, enclave_runtime_lifecycle
```

### Enclave Test: Remote attestation crypto
```bash
# Runs without a remote enclave - tests COSE-Sign1 parsing and session key derivation
cargo test --features enclave-remote -p ectoledger --lib -- enclave::remote::tests
# Should pass: parse_attestation_round_trip, session_key_derivation, destroy_clears_state
```
