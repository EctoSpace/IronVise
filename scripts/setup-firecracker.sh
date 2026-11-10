#!/usr/bin/env bash
# IronVise - Firecracker microVM provisioning script
#
# Downloads and installs the Firecracker binary, a compatible Linux kernel
# image, and a minimal rootfs to the locations expected by the IronVise
# runtime. After running this script, exporting the printed environment
# variables is all that is needed to enable the sandbox.
#
# Supported platforms: Linux x86_64 and aarch64 (the Firecracker binary).
# The bundled "hello" demo kernel/rootfs (see below) is x86_64-only upstream;
# on aarch64 this script installs the binary and tells you to use
# scripts/provision-firecracker.sh for a per-arch kernel + rootfs.
# Requires:    curl, tar, sha256sum (standard on all major Linux distros).
# Run as:      bash scripts/setup-firecracker.sh
# Run as root: sudo bash scripts/setup-firecracker.sh   (for system-wide paths)
#
# Testing without root/KVM/Linux (e.g. from macOS CI):
#   bash scripts/setup-firecracker.sh --download-only DIR --arch x86_64
#   bash scripts/setup-firecracker.sh --download-only DIR --arch aarch64
# This exercises the download + checksum + extraction logic into DIR without
# touching system paths, without requiring /dev/kvm, and without running any
# downloaded binary.

set -euo pipefail

usage() {
  echo "Usage: $0 [--download-only DIR --arch x86_64|aarch64]"
}

DOWNLOAD_ONLY=""
ARCH_OVERRIDE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --download-only)
      [[ $# -ge 2 ]] || { echo "error: --download-only needs a directory" >&2; exit 2; }
      DOWNLOAD_ONLY="$2"
      shift 2
      ;;
    --arch)
      [[ $# -ge 2 ]] || { echo "error: --arch needs x86_64 or aarch64" >&2; exit 2; }
      ARCH_OVERRIDE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

# Check all required tools are present before creating any files or directories.

_missing=()
for _cmd in curl tar; do
  command -v "${_cmd}" >/dev/null 2>&1 || _missing+=("${_cmd}")
done

# sha256sum (Linux coreutils) or shasum (macOS) - either satisfies the requirement.
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  _missing+=("sha256sum or shasum")
fi

if [[ ${#_missing[@]} -gt 0 ]]; then
  echo "✗  Missing required tools: ${_missing[*]}" >&2
  echo "   Install them with your package manager, e.g.:" >&2
  echo "     Debian/Ubuntu : sudo apt-get install curl tar coreutils" >&2
  echo "     RHEL/Fedora   : sudo dnf install curl tar coreutils" >&2
  exit 1
fi

# sha256sum is provided by 'coreutils' on Linux; on macOS it is 'shasum -a 256'.
# Normalise so the rest of the script can call sha256sum unconditionally.
if ! command -v sha256sum >/dev/null 2>&1; then
  if command -v shasum >/dev/null 2>&1; then
    sha256sum() { shasum -a 256 "$@"; }
    export -f sha256sum
  else
    echo "✗  Neither sha256sum nor shasum is available." >&2
    exit 1
  fi
fi

echo "✓  All required tools found (curl, tar, sha256sum)."

# Compare a file's SHA-256 against an expected value by computing and
# comparing strings directly, rather than relying on "sha256sum --check":
# macOS ships its own /sbin/sha256sum (BSD, no --check/--status support) that
# shadows the GNU-compatible tool this script otherwise falls back to, so a
# --check-based approach silently misbehaves there. Plain comparison works
# with any sha256sum-compatible command on any platform.
verify_sha256() {
  local file="$1" expected="$2" label="$3" actual
  actual="$(sha256sum "${file}" | awk '{print $1}')"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "FAILED" >&2
    echo "✗  SHA-256 mismatch for ${label}." >&2
    echo "   Expected: ${expected}" >&2
    echo "   Actual:   ${actual}" >&2
    return 1
  fi
  return 0
}

FC_VERSION="1.17.0"

# Firecracker publishes one checksum file per release asset (not a combined
# SHA256SUMS at the release root): "<asset>.sha256.txt", containing a single
# "<sha256>  <asset>" line. We verify downloads against that file AND against
# the values pinned below, computed independently by downloading both tgz
# assets of Firecracker v1.17.0 and hashing them on 2026-10-24. If upstream
# ever republishes the same filename with different bytes, the two checks
# will disagree and the script aborts instead of trusting a single source.
# shellcheck disable=SC2034 # read indirectly below via `eval "...=\${FC_SHA256_${FC_ARCH}}"`
FC_SHA256_x86_64="06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
# shellcheck disable=SC2034
FC_SHA256_aarch64="e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256"

# SHA-256 of the extracted firecracker-v1.17.0-<arch> binary itself (from the
# tarball's own internal SHA256SUMS, transitively trusted once the tgz-level
# hash above is verified). Used to make re-runs idempotent: if the installed
# binary already has this hash, we skip re-downloading.
# shellcheck disable=SC2034 # read indirectly via `eval "...=\${FC_BIN_SHA256_${FC_ARCH}}"`
FC_BIN_SHA256_x86_64="99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5"
# shellcheck disable=SC2034
FC_BIN_SHA256_aarch64="fe726e0b43c04363ac07e358be4dee982c3947c65ed3ae10c770fef5e1cd756c"

# ⚠ The Firecracker project's "hello" DEMO rootfs. This is a connectivity /
# plumbing test image ONLY: it boots to a login prompt and contains NO guest
# agent, so it CANNOT execute IronVise intents. See the banner printed at the
# end of this script and docs/reference/sandboxing.md for the guest protocol you must
# implement to get a working microVM tier.
# Source: https://s3.amazonaws.com/spec.ccfc.min/img/hello/
# NOTE: these two demo images exist only for x86_64 upstream; there is no
# aarch64 "hello" bundle. On aarch64 this script skips them (see below) and
# points you at scripts/provision-firecracker.sh instead.
# Checksums below were re-verified against the live artifacts on 2026-10-24.
ROOTFS_URL="https://s3.amazonaws.com/spec.ccfc.min/img/hello/fsfiles/hello-rootfs.ext4"
ROOTFS_SHA256="786f0612582cadcee4c8ad46e30e4cc93dff9a3c0b4ede3f3c597b4c241dd547"

# Kernel from the same demo bundle (5.10-based, minimal config). x86_64 only.
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/img/hello/kernel/hello-vmlinux.bin"
KERNEL_SHA256="882fa465c43ab7d92e31bd4167da3ad6a82cb9230f9b0016176df597c6014cef"

if [[ -n "${DOWNLOAD_ONLY}" ]]; then
  [[ -n "${ARCH_OVERRIDE}" ]] || { echo "error: --download-only requires --arch x86_64|aarch64" >&2; exit 2; }
  FC_ARCH="${ARCH_OVERRIDE}"
  case "${FC_ARCH}" in
    x86_64|aarch64) ;;
    *) echo "✗  Unsupported --arch: ${FC_ARCH}. Use x86_64 or aarch64." >&2; exit 1 ;;
  esac
  FC_BINARY_DIR="${DOWNLOAD_ONLY}"
  ASSETS_DIR="${DOWNLOAD_ONLY}"
  echo "ℹ  --download-only mode: installing into ${DOWNLOAD_ONLY} for arch ${FC_ARCH}."
  echo "   Skipping the Linux / KVM / root gates - this does not touch system paths"
  echo "   and does not execute any downloaded binary."
else
  FC_BINARY_DIR="/usr/local/bin"
  ASSETS_DIR="/opt/ectoledger"

  if [[ "${EUID}" -ne 0 ]]; then
    FC_BINARY_DIR="${HOME}/.local/bin"
    ASSETS_DIR="${HOME}/.local/opt/ectoledger"
    echo "ℹ  Running as non-root; installing to ${HOME}/.local (no sudo required)."
    echo "   To install system-wide, re-run: sudo bash scripts/setup-firecracker.sh"
  fi

  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "✗  Firecracker requires Linux. Refusing to continue on $(uname -s)." >&2
    echo "   To test the download/checksum/extraction logic on this machine," >&2
    echo "   use: bash $0 --download-only DIR --arch x86_64|aarch64" >&2
    exit 1
  fi

  ARCH="$(uname -m)"
  case "${ARCH}" in
    x86_64)   FC_ARCH="x86_64" ;;
    aarch64)  FC_ARCH="aarch64" ;;
    *)
      echo "✗  Unsupported architecture: ${ARCH}. Firecracker supports x86_64 and aarch64 only." >&2
      exit 1
      ;;
  esac
  echo "Architecture: ${ARCH}"

  if [[ ! -e /dev/kvm ]]; then
    echo "✗  /dev/kvm not found. Firecracker requires hardware virtualisation" >&2
    echo "   (Intel VT-x / AMD-V / ARM VHE) exposed as /dev/kvm. Refusing to install" >&2
    echo "   a sandbox tier that cannot run on this host." >&2
    echo "   On AWS EC2, use a bare-metal (.metal) instance type, or enable nested" >&2
    echo "   virtualisation on your hypervisor." >&2
    echo "   To test the download/checksum/extraction logic without KVM, use:" >&2
    echo "   bash $0 --download-only DIR --arch x86_64|aarch64" >&2
    exit 1
  fi
fi

mkdir -p "${FC_BINARY_DIR}" "${ASSETS_DIR}"

# --- Firecracker binary -----------------------------------------------------

eval "FC_PINNED_SHA256=\${FC_SHA256_${FC_ARCH}}"
eval "FC_BIN_PINNED_SHA256=\${FC_BIN_SHA256_${FC_ARCH}}"

FC_DEST="${FC_BINARY_DIR}/firecracker"
if [[ -f "${FC_DEST}" ]] && [[ "$(sha256sum "${FC_DEST}" | awk '{print $1}')" == "${FC_BIN_PINNED_SHA256}" ]]; then
  echo "✓  Firecracker v${FC_VERSION} (${FC_ARCH}) already installed at ${FC_DEST} - skipping download."
else
  FC_TGZ_NAME="firecracker-v${FC_VERSION}-${FC_ARCH}.tgz"
  FC_URL="https://github.com/firecracker-microvm/firecracker/releases/download/v${FC_VERSION}/${FC_TGZ_NAME}"
  FC_TMP="$(mktemp -d)/firecracker-download"
  mkdir -p "${FC_TMP}"
  trap 'rm -rf "${FC_TMP}"' EXIT

  echo ""
  echo "Downloading Firecracker v${FC_VERSION} (${FC_ARCH})…"
  echo "  URL: ${FC_URL}"

  curl -fsSL --retry 3 --retry-delay 2 \
    -o "${FC_TMP}/${FC_TGZ_NAME}" \
    "${FC_URL}"

  echo "  Verifying checksum against upstream's per-asset checksum file…"
  SHA256_TXT_URL="${FC_URL}.sha256.txt"
  curl -fsSL --retry 3 --retry-delay 2 \
    -o "${FC_TMP}/${FC_TGZ_NAME}.sha256.txt" \
    "${SHA256_TXT_URL}" || {
      echo "✗  Could not download ${FC_TGZ_NAME}.sha256.txt from GitHub - cannot verify binary." >&2
      echo "   URL attempted: ${SHA256_TXT_URL}" >&2
      exit 1
    }
  UPSTREAM_SHA256="$(awk '{print $1}' "${FC_TMP}/${FC_TGZ_NAME}.sha256.txt")"
  if [[ -z "${UPSTREAM_SHA256}" ]]; then
    echo "✗  Could not parse a checksum out of ${FC_TGZ_NAME}.sha256.txt." >&2
    exit 1
  fi

  ACTUAL_SHA="$(sha256sum "${FC_TMP}/${FC_TGZ_NAME}" | awk '{print $1}')"

  if [[ "${ACTUAL_SHA}" != "${UPSTREAM_SHA256}" ]]; then
    echo "✗  Checksum mismatch against upstream's ${FC_TGZ_NAME}.sha256.txt - aborting." >&2
    echo "   Expected (upstream): ${UPSTREAM_SHA256}" >&2
    echo "   Actual:              ${ACTUAL_SHA}" >&2
    exit 1
  fi
  if [[ "${ACTUAL_SHA}" != "${FC_PINNED_SHA256}" ]]; then
    echo "✗  Checksum mismatch against the value pinned in this script - aborting." >&2
    echo "   This means the upstream file changed since 2026-10-24, which could" >&2
    echo "   indicate a compromised or republished release. Verify manually at:" >&2
    echo "   ${FC_URL}" >&2
    echo "   Pinned:  ${FC_PINNED_SHA256}" >&2
    echo "   Actual:  ${ACTUAL_SHA}" >&2
    exit 1
  fi
  echo "  ✓ Checksum verified (matches upstream's .sha256.txt and the value pinned in this script)."

  echo "  Extracting…"
  tar -xzf "${FC_TMP}/${FC_TGZ_NAME}" -C "${FC_TMP}"

  # The tarball contains release-v<ver>-<arch>/firecracker-v<ver>-<arch>
  # (both the directory AND the binary are version-qualified - there is no
  # bare "firecracker" file in the archive).
  FC_BINARY_SRC="${FC_TMP}/release-v${FC_VERSION}-${FC_ARCH}/firecracker-v${FC_VERSION}-${FC_ARCH}"
  if [[ ! -f "${FC_BINARY_SRC}" ]]; then
    echo "✗  Expected binary not found at ${FC_BINARY_SRC}." >&2
    echo "   Archive contents:" >&2
    tar -tzf "${FC_TMP}/${FC_TGZ_NAME}" | sed 's/^/     /' >&2
    exit 1
  fi

  install -m 0755 "${FC_BINARY_SRC}" "${FC_DEST}"
  echo "  ✓ Firecracker binary installed to: ${FC_DEST}"

  rm -rf "${FC_TMP}"
  trap - EXIT
fi

# --- Kernel + rootfs (x86_64-only "hello" demo bundle) ----------------------

if [[ "${FC_ARCH}" != "x86_64" ]]; then
  echo ""
  echo "ℹ  Skipping the kernel/rootfs demo bundle: it is published by upstream for"
  echo "   x86_64 only (no aarch64 build exists at ${KERNEL_URL%/*}/)."
  echo "   Use scripts/provision-firecracker.sh to fetch a per-arch kernel + rootfs"
  echo "   for aarch64, or supply your own at the paths below."
  echo ""
  echo "   export ECTO_FC_BINARY=\"${FC_BINARY_DIR}/firecracker\""
  echo "   export ECTO_FC_KERNEL=\"${ASSETS_DIR}/vmlinux\""
  echo "   export ECTO_FC_ROOTFS=\"${ASSETS_DIR}/rootfs.ext4\""
  exit 0
fi

echo ""
if [[ -f "${ASSETS_DIR}/vmlinux" ]] && verify_sha256 "${ASSETS_DIR}/vmlinux" "${KERNEL_SHA256}" "kernel image" 2>/dev/null; then
  echo "✓  Kernel image already installed and verified at ${ASSETS_DIR}/vmlinux - skipping download."
else
  echo "Downloading vmlinux kernel image…"
  echo "  URL: ${KERNEL_URL}"
  KERNEL_TMP="$(mktemp)"
  curl -fsSL --retry 3 --retry-delay 2 -o "${KERNEL_TMP}" "${KERNEL_URL}"
  echo -n "  Verifying kernel checksum… "
  if ! verify_sha256 "${KERNEL_TMP}" "${KERNEL_SHA256}" "kernel image"; then
    rm -f "${KERNEL_TMP}"
    exit 1
  fi
  echo "OK"
  install -m 0644 "${KERNEL_TMP}" "${ASSETS_DIR}/vmlinux"
  rm -f "${KERNEL_TMP}"
  echo "  ✓ Kernel image installed to: ${ASSETS_DIR}/vmlinux"
fi

echo ""
if [[ -f "${ASSETS_DIR}/rootfs.ext4" ]] && verify_sha256 "${ASSETS_DIR}/rootfs.ext4" "${ROOTFS_SHA256}" "rootfs image" 2>/dev/null; then
  echo "✓  Rootfs image already installed and verified at ${ASSETS_DIR}/rootfs.ext4 - skipping download."
else
  echo "Downloading rootfs image…"
  echo "  URL: ${ROOTFS_URL}"
  ROOTFS_TMP="$(mktemp)"
  curl -fsSL --retry 3 --retry-delay 2 -o "${ROOTFS_TMP}" "${ROOTFS_URL}"
  echo -n "  Verifying rootfs checksum… "
  if ! verify_sha256 "${ROOTFS_TMP}" "${ROOTFS_SHA256}" "rootfs image"; then
    rm -f "${ROOTFS_TMP}"
    exit 1
  fi
  echo "OK"
  install -m 0644 "${ROOTFS_TMP}" "${ASSETS_DIR}/rootfs.ext4"
  rm -f "${ROOTFS_TMP}"
  echo "  ✓ rootfs image installed to: ${ASSETS_DIR}/rootfs.ext4"
fi

if [[ -n "${DOWNLOAD_ONLY}" ]]; then
  echo ""
  echo "✓  --download-only complete. Artifacts verified and placed in ${DOWNLOAD_ONLY}."
  exit 0
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo " Firecracker v${FC_VERSION} installation complete."
echo ""
echo " To enable the Firecracker sandbox in IronVise, export the following"
echo " environment variables before starting the agent:"
echo ""
echo "   export ECTO_FC_BINARY=\"${FC_BINARY_DIR}/firecracker\""
echo "   export ECTO_FC_KERNEL=\"${ASSETS_DIR}/vmlinux\""
echo "   export ECTO_FC_ROOTFS=\"${ASSETS_DIR}/rootfs.ext4\""
echo "   export ECTO_FC_VCPUS=1"
echo "   export ECTO_FC_MEM_MIB=128"
echo "   export ECTO_FC_TIMEOUT_SECS=30"
echo ""
echo " Then run the agent with the sandbox-firecracker feature:"
echo "   cargo run --features sandbox-firecracker -- audit \"<your goal>\""
echo ""
echo " To persist these settings, add the exports to your shell profile"
echo " (~/.bashrc, ~/.zshrc, or /etc/environment for system-wide scope)."
echo "═══════════════════════════════════════════════════════════════════════"
echo ""
echo "╔═════════════════════════════════════════════════════════════════════╗"
echo "║  READ THIS: the rootfs just installed CANNOT run agent intents.     ║"
echo "╚═════════════════════════════════════════════════════════════════════╝"
echo ""
echo " The image downloaded above is the Firecracker project's 'hello' DEMO"
echo " rootfs. It is a CONNECTIVITY / PLUMBING TEST ONLY: it proves that KVM,"
echo " the firecracker binary, the kernel, and the block devices are wired up"
echo " correctly. It boots to a login prompt and contains NO IronVise guest"
echo " agent, so it will NOT execute any intent you send it."
echo ""
echo " With this rootfs the Firecracker tier will start a microVM and then"
echo " fail to produce output. Because sandbox failures are fail-closed by"
echo " default, the action is ABORTED rather than silently run on the host"
echo " (set ECTO_SANDBOX_PERMISSIVE=true to allow degraded execution)."
echo ""
echo " To get a WORKING microVM tier you must supply your own rootfs whose"
echo " init implements this protocol:"
echo ""
echo "   1. READ    the intent JSON from /dev/vdb (second block device, raw -"
echo "              it is a plain file image, not a filesystem)."
echo "   2. PARSE   .action (\"run_command\") and .params.command."
echo "   3. EXECUTE that command inside the guest."
echo "   4. WRITE   stdout and stderr to the serial console (/dev/ttyS0),"
echo "              which Firecracker surfaces as the host process's stdout."
echo "   5. SHUT DOWN so the ephemeral VM exits and the host collects output."
echo ""
echo " scripts/provision-firecracker.sh builds exactly such a rootfs (a busybox"
echo " init implementing this contract) when the official Ubuntu rootfs is"
echo " unavailable, or you can build your own and point ECTO_FC_ROOTFS at it."
echo ""
echo " See docs/reference/sandboxing.md § 'Firecracker guest image contract' for the"
echo " full protocol, and use --network=none Docker (ECTO_DOCKER_IMAGE) if you"
echo " want working isolation today without building a guest image."
echo ""
