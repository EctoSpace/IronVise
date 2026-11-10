#!/usr/bin/env bash
#  IronVise - Firecracker microVM Provisioning Script
#
#  Downloads the Firecracker binary, a minimal Linux kernel, and a busybox
#  rootfs, then configures the environment so the IronVise `sandbox-firecracker`
#  feature can isolate `run_command` intents inside ephemeral microVMs.
#
#  Prerequisites:
#    - Linux with KVM support (/dev/kvm must exist)
#    - curl, unzip/tar
#    - Root or sudo access (for /dev/kvm permissions and /opt/ectoledger/ setup)
#
#  Usage:
#    sudo ./scripts/provision-firecracker.sh [--prefix /opt/ectoledger]
#    ./scripts/provision-firecracker.sh --print-prefix [--prefix DIR]
#
#  A bare positional DIR is accepted in place of --prefix DIR.
#  --print-prefix prints the resolved install prefix and exits without
#  touching the system.
#
#  --rootfs auto|official|busybox controls which rootfs gets installed:
#  auto (default) tries the official Ubuntu CI rootfs and falls back to the
#  working busybox one if that's unavailable; official only tries the Ubuntu
#  rootfs (which does NOT implement the IronVise guest protocol - see the
#  note printed at the end of a run); busybox always builds the working one
#  directly, skipping the official download.
#
#  Testing without root/KVM/Linux (e.g. from macOS CI):
#    ./scripts/provision-firecracker.sh --download-only DIR --arch x86_64
#    ./scripts/provision-firecracker.sh --download-only DIR --arch aarch64
#  This exercises the download + checksum + extraction logic into DIR without
#  touching system paths, without requiring /dev/kvm or root, and without
#  running any downloaded binary. It skips the busybox/mkfs.ext4 rootfs
#  fallback, which needs Linux-only tools.
#
#  After running, rebuild IronVise with:
#    cargo build --release --features sandbox-firecracker
#  Then set these environment variables before starting the server:
#    export ECTO_FC_BINARY=/opt/ectoledger/firecracker
#    export ECTO_FC_KERNEL=/opt/ectoledger/vmlinux
#    export ECTO_FC_ROOTFS=/opt/ectoledger/rootfs.ext4
set -euo pipefail

# Firecracker release to download (see https://github.com/firecracker-microvm/firecracker/releases)
FC_VERSION="${FC_VERSION:-v1.17.0}"

# SHA-256 checksums for supply-chain integrity verification. All values below
# were computed independently on 2026-10-24 by downloading each artifact and
# hashing it; the Firecracker binary hashes are cross-checked at runtime
# against upstream's own published "<asset>.sha256.txt" file for that release
# (see the "Downloading Firecracker" step) - the two must agree or the script
# aborts. Update every value here when bumping FC_VERSION.
#
# Firecracker binary release tarball (one upstream checksum file per asset,
# fetched and cross-checked below; this is the pinned fallback/second check):
FC_SHA256_x86_64="${FC_SHA256_x86_64:-06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558}"
FC_SHA256_aarch64="${FC_SHA256_aarch64:-e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256}"
# SHA-256 of the *extracted* firecracker-<ver>-<arch> binary (from the
# tarball's own internal SHA256SUMS, transitively trusted once the tgz-level
# hash above is verified). Used only to make re-runs idempotent: if the
# installed binary already has this hash, we skip re-downloading the tgz.
FC_BIN_SHA256_x86_64="${FC_BIN_SHA256_x86_64:-99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5}"
FC_BIN_SHA256_aarch64="${FC_BIN_SHA256_aarch64:-fe726e0b43c04363ac07e358be4dee982c3947c65ed3ae10c770fef5e1cd756c}"
# Primary kernel: firecracker-ci/v1.10/<arch>/vmlinux-5.10.223 (the CI bucket
# has no checksum file of its own; this is CI storage, not a release channel
# - keys can be deleted by upstream, as happened to the previously hardcoded
# vmlinux-5.10.225, which 404s. A pinned hash guards against the key being
# silently replaced with different bytes, but not against it disappearing;
# that's what the fallback URL below is for).
KERNEL_SHA256_x86_64="${KERNEL_SHA256_x86_64:-22847375721aceea63d934c28f2dfce4670b6f52ec904fae19f5145a970c1e65}"
KERNEL_SHA256_aarch64="${KERNEL_SHA256_aarch64:-eb5d95ac8a67f7a86acf0cb35625633713ad5170b56de8617808d0e18bb832ec}"
# Fallback kernel: img/quickstart_guide/<arch>/kernels/vmlinux.bin
KERNEL_FALLBACK_SHA256_x86_64="${KERNEL_FALLBACK_SHA256_x86_64:-ea5e7d5cf494a8c4ba043259812fc018b44880d70bcbbfc4d57d2760631b1cd6}"
KERNEL_FALLBACK_SHA256_aarch64="${KERNEL_FALLBACK_SHA256_aarch64:-e2d7c3d6cc123de9e6052d1f434ca7b47635a1f630d63f7fcc1b7164958375e4}"
# Official rootfs: firecracker-ci/v1.10/<arch>/ubuntu-22.04.ext4 - same CI
# storage caveat as the kernel above.
ROOTFS_SHA256_x86_64="${ROOTFS_SHA256_x86_64:-040927105bd01b19e7b02cd5da5a9552b428a7f84bd5ffc22ebfce4ddf258a07}"
ROOTFS_SHA256_aarch64="${ROOTFS_SHA256_aarch64:-b7a8c7578812f907ad7f72ddea9b57a5d15f461b51bd3e1933b5ad5c8eb1d708}"

usage() {
  echo "Usage: $0 [--prefix DIR | DIR] [--print-prefix] [--rootfs auto|official|busybox] [--download-only DIR --arch x86_64|aarch64]"
}

# Install prefix - all artefacts are placed here
INSTALL_PREFIX="/opt/ectoledger"
PREFIX_SET=0
PRINT_PREFIX=0
DOWNLOAD_ONLY=0
ARCH_OVERRIDE=""
# auto (default): try the official Ubuntu CI rootfs, fall back to building a
# busybox rootfs if that download is unavailable or fails verification.
# official: only try the Ubuntu rootfs (fails if it can't be fetched).
# busybox: skip the official rootfs entirely and always build the working
# busybox one (the only rootfs here that implements the IronVise guest
# protocol - see the note printed at the end of this script).
ROOTFS_MODE="auto"

set_prefix() {
  if [[ "$PREFIX_SET" -eq 1 ]]; then
    echo "error: install prefix given more than once" >&2
    usage >&2
    exit 2
  fi
  if [[ -z "$1" ]]; then
    echo "error: install prefix must not be empty" >&2
    usage >&2
    exit 2
  fi
  INSTALL_PREFIX="$1"
  PREFIX_SET=1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      if [[ $# -lt 2 ]]; then
        echo "error: --prefix needs a directory" >&2
        usage >&2
        exit 2
      fi
      set_prefix "$2"
      shift 2
      ;;
    --prefix=*)
      set_prefix "${1#--prefix=}"
      shift
      ;;
    --print-prefix)
      PRINT_PREFIX=1
      shift
      ;;
    --download-only)
      if [[ $# -lt 2 ]]; then
        echo "error: --download-only needs a directory" >&2
        usage >&2
        exit 2
      fi
      set_prefix "$2"
      DOWNLOAD_ONLY=1
      shift 2
      ;;
    --arch)
      if [[ $# -lt 2 ]]; then
        echo "error: --arch needs x86_64 or aarch64" >&2
        usage >&2
        exit 2
      fi
      ARCH_OVERRIDE="$2"
      shift 2
      ;;
    --rootfs)
      if [[ $# -lt 2 ]]; then
        echo "error: --rootfs needs auto, official, or busybox" >&2
        usage >&2
        exit 2
      fi
      case "$2" in
        auto|official|busybox) ROOTFS_MODE="$2" ;;
        *)
          echo "error: --rootfs must be auto, official, or busybox (got: $2)" >&2
          usage >&2
          exit 2
          ;;
      esac
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      # Older invocations passed the prefix as the only positional argument.
      set_prefix "$1"
      shift
      ;;
  esac
done

if [[ "$PRINT_PREFIX" -eq 1 ]]; then
  echo "$INSTALL_PREFIX"
  exit 0
fi

RESET="\033[0m"
BOLD="\033[1m"
RED="\033[0;31m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"

info()    { echo -e "  ${CYAN}▶${RESET} $*"; }
success() { echo -e "  ${GREEN}✔${RESET} $*"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
error()   { echo -e "  ${RED}✘${RESET}  $*" >&2; }
step()    { echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

verify_sha256() {
  local file="$1" expected="$2" label="$3"
  local actual
  if command -v sha256sum &>/dev/null; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum &>/dev/null; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    error "Neither sha256sum nor shasum found - cannot verify $label integrity."
    exit 1
  fi
  if [[ "$actual" != "$expected" ]]; then
    error "SHA-256 checksum mismatch for $label!"
    error "  Expected: $expected"
    error "  Got:      $actual"
    error "The downloaded file may be corrupted or tampered with. Aborting."
    rm -f "$file"
    return 1
  fi
  success "SHA-256 verified for $label"
}

# Gate on the OS before the architecture, so a non-Linux host (where
# `uname -m` may not even produce a Linux-style arch name, e.g. macOS
# "arm64" instead of "aarch64") gets the accurate "requires Linux" refusal
# rather than a confusing "unsupported architecture".
if [[ "$DOWNLOAD_ONLY" -ne 1 ]] && [[ "$(uname -s)" != "Linux" ]]; then
  error "Firecracker requires Linux. Refusing to continue on $(uname -s)."
  error "To test the download/checksum/extraction logic on this machine, use:"
  error "  $0 --download-only DIR --arch x86_64|aarch64"
  exit 1
fi

if [[ -n "$ARCH_OVERRIDE" ]]; then
  ARCH="$ARCH_OVERRIDE"
else
  ARCH="$(uname -m)"
fi
case "$ARCH" in
  x86_64)  FC_ARCH="x86_64" ;;
  aarch64) FC_ARCH="aarch64" ;;
  *)
    error "Unsupported architecture: $ARCH. Firecracker supports x86_64 and aarch64 only."
    [[ "$DOWNLOAD_ONLY" -eq 1 ]] && error "Pass --arch x86_64 or --arch aarch64 explicitly."
    exit 1
    ;;
esac

echo ""
echo -e "${BOLD}${CYAN}  IronVise - Firecracker microVM Provisioner${RESET}"
echo -e "  Version: ${FC_VERSION}  Architecture: ${FC_ARCH}  Prefix: ${INSTALL_PREFIX}"
echo ""

if [[ "$DOWNLOAD_ONLY" -eq 1 ]]; then
  warn "--download-only mode: skipping the Linux / KVM / root gates."
  warn "This does not touch system paths and does not execute any downloaded binary."
else
  step "Checking KVM"

  if [[ ! -e /dev/kvm ]]; then
    error "/dev/kvm not found. Firecracker requires hardware virtualisation (KVM)."
    error "Enable nested virtualisation in your hypervisor, or use a bare-metal Linux host."
    exit 1
  fi

  if [[ ! -r /dev/kvm ]] || [[ ! -w /dev/kvm ]]; then
    # When invoked via sudo, $USER is typically "root"; the user who needs
    # kvm-group access is the one who ran sudo, i.e. $SUDO_USER.
    KVM_USER="${SUDO_USER:-$USER}"
    warn "/dev/kvm exists but is not accessible to ${KVM_USER}."
    info "Adding ${KVM_USER} to the 'kvm' group…"
    if id -nG "$KVM_USER" | grep -qw kvm; then
      warn "Already in 'kvm' group - a logout/login may be required to apply."
    else
      if command -v usermod &>/dev/null; then
        usermod -aG kvm "$KVM_USER"
        success "Added ${KVM_USER} to the 'kvm' group. Log out and back in, then re-run this script."
      else
        error "Could not add user to 'kvm' group automatically. Run: sudo usermod -aG kvm $KVM_USER"
        exit 1
      fi
      exit 0
    fi
  else
    success "/dev/kvm is accessible"
  fi
fi

step "Creating install directory"
mkdir -p "$INSTALL_PREFIX"
success "Directory ready: $INSTALL_PREFIX"

step "Downloading Firecracker ${FC_VERSION}"

FC_BINARY="${INSTALL_PREFIX}/firecracker"
fc_expected_hash=""
eval "fc_expected_hash=\$FC_SHA256_${FC_ARCH}"
fc_bin_expected_hash=""
eval "fc_bin_expected_hash=\$FC_BIN_SHA256_${FC_ARCH}"

if [[ -f "$FC_BINARY" ]] && verify_sha256 "$FC_BINARY" "$fc_bin_expected_hash" "installed Firecracker binary" 2>/dev/null; then
  if [[ "$DOWNLOAD_ONLY" -eq 1 ]]; then
    # Never execute a downloaded binary, even for a --version probe - this
    # mode is used to test the download/verify/install logic on non-Linux
    # hosts where the binary can't run anyway.
    success "Firecracker ${FC_VERSION} (${FC_ARCH}) already installed and verified."
  else
    EXISTING_VER="$("$FC_BINARY" --version 2>/dev/null | head -1 || echo unknown)"
    success "Firecracker already installed and verified: $EXISTING_VER"
  fi
else
  RELEASE_ASSET="firecracker-${FC_VERSION}-${FC_ARCH}.tgz"
  RELEASE_URL="https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/${RELEASE_ASSET}"
  TMP_TGZ="$(mktemp -t firecracker-XXXX.tgz)"
  TMP_DIR="$(mktemp -d)"
  info "Downloading: $RELEASE_URL"
  curl --fail --location --progress-bar --output "$TMP_TGZ" "$RELEASE_URL"

  # Firecracker publishes one checksum file per release asset, named
  # "<asset>.sha256.txt" (there is no combined SHA256SUMS at the release
  # root). Verify against both that upstream file and the value pinned
  # above - if they disagree, upstream changed the asset since this script
  # was last updated, and we fail loudly rather than pick one source.
  SHA256_TXT_URL="${RELEASE_URL}.sha256.txt"
  TMP_SHA_TXT="$(mktemp)"
  info "Fetching upstream checksum: $SHA256_TXT_URL"
  if curl --fail --location --silent --output "$TMP_SHA_TXT" "$SHA256_TXT_URL"; then
    upstream_hash="$(awk '{print $1}' "$TMP_SHA_TXT")"
    if [[ "$upstream_hash" != "$fc_expected_hash" ]]; then
      error "Upstream checksum for ${RELEASE_ASSET} ($upstream_hash) does not match"
      error "the value pinned in this script ($fc_expected_hash)."
      error "Upstream may have republished the release. Verify manually before proceeding:"
      error "  ${RELEASE_URL}"
      rm -f "$TMP_SHA_TXT"
      exit 1
    fi
  else
    warn "Could not fetch ${SHA256_TXT_URL}; verifying against the pinned checksum only."
  fi
  rm -f "$TMP_SHA_TXT"

  verify_sha256 "$TMP_TGZ" "$fc_expected_hash" "Firecracker ${FC_VERSION} (${FC_ARCH}) release tarball"

  info "Extracting binary…"
  tar -xzf "$TMP_TGZ" -C "$TMP_DIR"
  # The archive layout is release-<ver>-<arch>/firecracker-<ver>-<arch>
  # (both the directory and the binary are version-qualified).
  FC_BIN_SRC="${TMP_DIR}/release-${FC_VERSION}-${FC_ARCH}/firecracker-${FC_VERSION}-${FC_ARCH}"
  if [[ ! -f "$FC_BIN_SRC" ]]; then
    # Fall back to a basename search in case the layout changes again.
    FC_BIN_SRC="$(find "$TMP_DIR" -name "firecracker-${FC_VERSION}-${FC_ARCH}" -type f | head -1)"
  fi
  if [[ -z "$FC_BIN_SRC" || ! -f "$FC_BIN_SRC" ]]; then
    error "Could not locate the Firecracker binary in the downloaded archive."
    error "Archive contents:"
    tar -tzf "$TMP_TGZ" | sed 's/^/    /' >&2
    rm -rf "$TMP_TGZ" "$TMP_DIR"
    exit 1
  fi
  install -m 0755 "$FC_BIN_SRC" "$FC_BINARY"
  rm -rf "$TMP_TGZ" "$TMP_DIR"
  success "Firecracker installed → ${FC_BINARY}"
fi

step "Downloading minimal Linux kernel"

KERNEL_PATH="${INSTALL_PREFIX}/vmlinux"
kernel_expected_hash=""
eval "kernel_expected_hash=\$KERNEL_SHA256_${FC_ARCH}"
kernel_fallback_hash=""
eval "kernel_fallback_hash=\$KERNEL_FALLBACK_SHA256_${FC_ARCH}"

if [[ -f "$KERNEL_PATH" ]] && { verify_sha256 "$KERNEL_PATH" "$kernel_expected_hash" "kernel" 2>/dev/null \
      || verify_sha256 "$KERNEL_PATH" "$kernel_fallback_hash" "kernel" 2>/dev/null; }; then
  success "Kernel already present and verified: ${KERNEL_PATH}"
else
  # Use the Firecracker project's pre-built minimal kernel images. This is
  # CI build storage, not a release channel: keys can be deleted or rotated
  # without notice (the previously hardcoded vmlinux-5.10.225 was deleted
  # upstream - see the comment above the pinned hashes), so a primary URL
  # with a fallback, both checksum-verified, is the best available guarantee.
  KERNEL_TMP="$(mktemp)"
  KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/${FC_ARCH}/vmlinux-5.10.223"
  info "Downloading kernel: $KERNEL_URL"
  if curl --fail --location --progress-bar --output "$KERNEL_TMP" "$KERNEL_URL" \
      && verify_sha256 "$KERNEL_TMP" "$kernel_expected_hash" "kernel (primary)"; then
    :
  else
    warn "Primary kernel unavailable or failed verification. Trying fallback…"
    KERNEL_URL_FB="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/${FC_ARCH}/kernels/vmlinux.bin"
    info "Downloading kernel: $KERNEL_URL_FB"
    curl --fail --location --progress-bar --output "$KERNEL_TMP" "$KERNEL_URL_FB" || {
      error "Could not download the kernel image. Check your internet connection."
      error "You can also supply your own kernel at ${KERNEL_PATH}."
      rm -f "$KERNEL_TMP"
      exit 1
    }
    verify_sha256 "$KERNEL_TMP" "$kernel_fallback_hash" "kernel (fallback)" || { rm -f "$KERNEL_TMP"; exit 1; }
  fi
  install -m 0644 "$KERNEL_TMP" "$KERNEL_PATH"
  rm -f "$KERNEL_TMP"
  success "Kernel installed → ${KERNEL_PATH}"
fi

step "Provisioning rootfs ext4 image"

ROOTFS_PATH="${INSTALL_PREFIX}/rootfs.ext4"
rootfs_expected_hash=""
eval "rootfs_expected_hash=\$ROOTFS_SHA256_${FC_ARCH}"

# Builds the minimal busybox rootfs - the only rootfs this script can
# produce that implements the IronVise guest protocol (see the note at
# the end of this script). Needs Linux-only tools (mkfs.ext4, loop mounts).
build_busybox_rootfs() {
  if ! command -v mkfs.ext4 &>/dev/null; then
    error "mkfs.ext4 not found. Install e2fsprogs: apt install e2fsprogs"
    exit 1
  fi
  if ! command -v busybox &>/dev/null; then
    error "busybox not found. Install it: apt install busybox-static"
    exit 1
  fi
  # Require jq for reliable JSON parsing in the guest init script
  if ! command -v jq &>/dev/null; then
    error "jq not found. Install it before proceeding."
    exit 1
  fi

  TMP_ROOTFS="$(mktemp -d)"
  mkdir -p "${TMP_ROOTFS}"/{bin,sbin,etc,proc,sys,dev,tmp,opt/ectoledger}

  cp "$(command -v busybox)" "${TMP_ROOTFS}/bin/busybox"
  cp "$(command -v jq)" "${TMP_ROOTFS}/bin/jq"
  for tool in sh cat ls mount echo sleep reboot; do
    ln -sf /bin/busybox "${TMP_ROOTFS}/bin/${tool}"
  done
  # Guest init: reads the intent from /dev/vdb, runs the command, writes
  # the result to the serial console. Matches the host contract documented
  # in docs/reference/sandboxing.md "Firecracker guest image contract" and
  # implemented in crates/sandbox/src/sandbox/firecracker.rs: the intent is
  # {"action": "run_command", "params": {"command": "<shell command>"}, ...}
  # - a single command string, not an argv array.
  cat > "${TMP_ROOTFS}/sbin/init" <<'INIT_SCRIPT'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev 2>/dev/null || true

# Read the intent JSON from the second block device (/dev/vdb, a raw file
# image, not a filesystem) and strip the trailing NUL padding the host pads
# it with.
INTENT=$(tr -d '\0' < /dev/vdb)

ACTION=$(printf '%s' "$INTENT" | jq -r '.action // empty' 2>/dev/null)
CMD=$(printf '%s' "$INTENT" | jq -r '.params.command // empty' 2>/dev/null)

if [ "$ACTION" != "run_command" ] || [ -z "$CMD" ]; then
  echo '{"error":"unsupported or missing action/params.command in intent"}'
  reboot -f
fi

echo '{"status":"running"}'
# Run as a single shell command string, per the documented guest contract -
# not as an argv array.
sh -c "$CMD" 2>&1
echo '{"status":"complete"}'
reboot -f
INIT_SCRIPT
  chmod +x "${TMP_ROOTFS}/sbin/init"

  # Create and populate ext4 image (64 MiB)
  dd if=/dev/zero bs=1M count=64 of="$ROOTFS_PATH" status=none
  mkfs.ext4 -q -F -L ectoledger-rootfs "$ROOTFS_PATH"

  TMP_MOUNT="$(mktemp -d)"
  mount -o loop "$ROOTFS_PATH" "$TMP_MOUNT"
  cp -a "${TMP_ROOTFS}/." "$TMP_MOUNT/"
  umount "$TMP_MOUNT"
  rmdir "$TMP_MOUNT"
  rm -rf "$TMP_ROOTFS"
  success "Minimal busybox rootfs created → ${ROOTFS_PATH}"
}

# Downloads and verifies the official Ubuntu CI rootfs. Returns non-zero
# (and cleans up its temp file) on any download or checksum failure, without
# exiting, so callers can fall back to build_busybox_rootfs.
download_official_rootfs() {
  local rootfs_url="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/${FC_ARCH}/ubuntu-22.04.ext4"
  local rootfs_tmp
  rootfs_tmp="$(mktemp)"
  info "Downloading rootfs: $rootfs_url"
  if curl --fail --location --progress-bar --output "$rootfs_tmp" "$rootfs_url" \
      && verify_sha256 "$rootfs_tmp" "$rootfs_expected_hash" "rootfs"; then
    install -m 0644 "$rootfs_tmp" "$ROOTFS_PATH"
    rm -f "$rootfs_tmp"
    success "Rootfs installed → ${ROOTFS_PATH}"
    return 0
  fi
  rm -f "$rootfs_tmp"
  return 1
}

if [[ -f "$ROOTFS_PATH" ]]; then
  success "Rootfs already present: ${ROOTFS_PATH}"
elif [[ "$ROOTFS_MODE" == "busybox" ]]; then
  if [[ "$DOWNLOAD_ONLY" -eq 1 ]]; then
    error "--rootfs busybox needs Linux-only tools (mkfs.ext4, loop mounts)"
    error "not available in --download-only mode."
    exit 1
  fi
  info "--rootfs busybox: building the working busybox rootfs directly."
  build_busybox_rootfs
elif [[ "$ROOTFS_MODE" == "official" ]]; then
  download_official_rootfs || {
    error "Official rootfs unavailable or failed verification, and --rootfs"
    error "official was given (no busybox fallback). Try --rootfs busybox"
    error "or --rootfs auto instead."
    exit 1
  }
elif [[ "$DOWNLOAD_ONLY" -eq 1 ]]; then
  # auto mode: the busybox fallback below needs Linux-only tools (loop
  # mounts, mkfs.ext4) and is not exercised here.
  download_official_rootfs || exit 1
else
  # auto mode: try the official rootfs first, build the working busybox one
  # if that's unavailable or fails verification.
  download_official_rootfs || {
    warn "Official rootfs unavailable or failed verification. Building a minimal busybox rootfs locally…"
    build_busybox_rootfs
  }
fi

if [[ "$DOWNLOAD_ONLY" -eq 1 ]]; then
  echo ""
  success "--download-only complete. Artifacts verified and placed in ${INSTALL_PREFIX}."
  exit 0
fi

step "Environment configuration"

ENV_SNIPPET="${INSTALL_PREFIX}/ectoledger-firecracker.env"
cat > "$ENV_SNIPPET" <<ENVEOF
# ─── IronVise Firecracker microVM configuration ───────────────────────────────
# Source this file or add these variables to your shell / .env before starting
# the IronVise server with --features sandbox-firecracker:
#
#   source ${ENV_SNIPPET}
#   cargo run --release --features sandbox-firecracker -- serve
#
export ECTO_FC_BINARY=${FC_BINARY}
export ECTO_FC_KERNEL=${KERNEL_PATH}
export ECTO_FC_ROOTFS=${ROOTFS_PATH}
export ECTO_FC_VCPUS=1
export ECTO_FC_MEM_MIB=128
export ECTO_FC_TIMEOUT_SECS=30
ENVEOF

success "Environment snippet written → ${ENV_SNIPPET}"

echo ""
echo -e "${BOLD}${GREEN}  ✔  Firecracker provisioning complete!${RESET}"
echo ""
echo -e "  ${BOLD}Firecracker binary:${RESET}  ${FC_BINARY}"
echo -e "  ${BOLD}Kernel image:${RESET}        ${KERNEL_PATH}"
echo -e "  ${BOLD}Root filesystem:${RESET}     ${ROOTFS_PATH}"
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo -e "  1. Source the environment file:"
echo -e "     ${CYAN}source ${ENV_SNIPPET}${RESET}"
echo ""
echo -e "  2. Rebuild IronVise with the firecracker feature:"
echo -e "     ${CYAN}cargo build --release --features sandbox-firecracker${RESET}"
echo ""
echo -e "  3. Start the server:"
echo -e "     ${CYAN}./target/release/ironvise serve${RESET}"
echo ""
echo -e "  ${BOLD}${YELLOW}Note:${RESET} if the rootfs above came from the official Ubuntu image"
echo -e "  (rather than the busybox fallback this script builds), it does NOT"
echo -e "  implement the IronVise guest protocol (read /dev/vdb, run"
echo -e "  params.command, write to ttyS0, shut down) - it is a generic Ubuntu"
echo -e "  userspace and will not execute agent intents. Delete ${ROOTFS_PATH} and"
echo -e "  re-run with ${CYAN}--rootfs busybox${RESET} to force the working busybox rootfs"
echo -e "  instead (plain re-run tries the official rootfs again, which is up"
echo -e "  more often than not), or supply your own image implementing the"
echo -e "  contract in docs/reference/sandboxing.md § 'Firecracker guest image contract'."
echo ""
echo -e "  See the README for full documentation on the Firecracker sandbox."
echo ""
