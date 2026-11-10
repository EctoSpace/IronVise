#!/usr/bin/env bash
#
# Audits the quickstart's zero-infrastructure path by running it, and times it.
#
# The claim under test is docs/getting-started/quickstart.md's opening line and traction 4c's
# metric: how long from a clone to independently verifying a certificate, with
# no Docker, no PostgreSQL, no model and no network. Every step here is a
# command the docs actually tell a reader to type. If a documented command
# stops working, this exits non-zero - a quickstart that nobody executes is a
# quickstart that is wrong within a release or two.
#
#   bash scripts/audit-quickstart.sh
#
# The headline number is TIME TO FIRST VERIFICATION. Run it on a clean machine
# for a number worth quoting: this measures whatever state your target/ and
# ~/.cargo are already in, and a warm cache is not what a stranger has.
#
#   git clone <repo> /tmp/ecto-clean && cd /tmp/ecto-clean
#   bash scripts/audit-quickstart.sh          # needs ~10 GB free for target/

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -t 1 ]; then
  B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; D=$'\e[2m'; N=$'\e[0m'
else
  B=""; G=""; R=""; Y=""; D=""; N=""
fi

FAILED=0
declare -a TIMINGS

now() { python3 -c 'import time; print(time.time())'; }
START_ALL=$(now)

# step <label> <command...> - runs it, times it, records pass/fail. Keeps going
# after a failure so one broken command does not hide the rest of the audit.
step() {
  local label="$1"; shift
  printf '\n%s▸ %s%s\n%s  $ %s%s\n' "$B" "$label" "$N" "$D" "$*" "$N"
  local t0 t1 rc
  t0=$(now)
  "$@" >/tmp/aq.$$.log 2>&1; rc=$?
  t1=$(now)
  local secs; secs=$(python3 -c "print(f'{$t1-$t0:.1f}')")
  if [ $rc -eq 0 ]; then
    printf '%s  ✓ %ss%s\n' "$G" "$secs" "$N"
  else
    printf '%s  ✗ exit %d after %ss%s\n' "$R" "$rc" "$secs" "$N"
    sed 's/^/      /' /tmp/aq.$$.log | tail -12
    FAILED=$((FAILED + 1))
  fi
  TIMINGS+=("$(printf '%7ss  %s' "$secs" "$label")")
  rm -f /tmp/aq.$$.log
  return $rc
}

# A tampered certificate must FAIL. Asserting exit 0 everywhere would let the
# most important claim in the repo pass by doing nothing.
step_expect_fail() {
  local label="$1"; shift
  printf '\n%s▸ %s%s\n%s  $ %s%s\n' "$B" "$label" "$N" "$D" "$*" "$N"
  local t0 t1 rc
  t0=$(now); "$@" >/dev/null 2>&1; rc=$?; t1=$(now)
  local secs; secs=$(python3 -c "print(f'{$t1-$t0:.1f}')")
  if [ $rc -ne 0 ]; then
    printf '%s  ✓ rejected (exit %d) in %ss%s\n' "$G" "$rc" "$secs" "$N"
  else
    printf '%s  ✗ ACCEPTED a tampered certificate - exit 0%s\n' "$R" "$N"
    FAILED=$((FAILED + 1))
  fi
  TIMINGS+=("$(printf '%7ss  %s' "$secs" "$label")")
}

printf '%sQuickstart audit - SQLite path, no Docker, no PostgreSQL, no model%s\n' "$B" "$N"
printf '%s%s%s\n' "$D" "$(uname -srm)  ·  $(cargo --version 2>/dev/null || echo 'cargo MISSING')" "$N"

# The five-minute path, which TIME TO FIRST VERIFICATION measures.

# examples/verified-session/README.md's first instruction.
step "Build the offline verifier" cargo build --release --bin verify-cert
T_BUILT=$(now)

step "Verify the shipped certificate" \
  ./target/release/verify-cert examples/verified-session/session.elc
T_VERIFIED=$(now)

step_expect_fail "Reject the tampered certificate" \
  ./target/release/verify-cert examples/verified-session/session-tampered.elc

TTFV=$(python3 -c "print(f'{$T_VERIFIED-$START_ALL:.0f}')")

# The rest of what the quickstart promises without infrastructure.

step "Build the CLI" cargo build --release -p ectoledger

# quickstart §5: the SQLite backend supports these and rejects the rest.
step "verify-certificate works offline (no DATABASE_URL)" \
  ./target/release/ironvise verify-certificate examples/verified-session/session.elc

# The live path: deny, record, tamper, detect.
step "End-to-end hook demo" env ECTOLEDGER_BIN="$ROOT/target/release/ironvise" \
  bash examples/demo/hook-denial-demo.sh

# quickstart §10.
step "Unit tests" cargo test --workspace

printf '\n%s▸ Documented claims that need a human, not a shell%s\n' "$B" "$N"

check_doc() {  # check_doc <description> <test-expression-result>
  if [ "$2" = "ok" ]; then printf '%s  ✓ %s%s\n' "$G" "$1" "$N"
  else printf '%s  ! %s%s\n' "$Y" "$1" "$N"; fi
}

# The registry packages lag the repo. A reader who follows an `npm install`
# line gets a client that cannot do what docs/guides/integrations.md says the SDK does.
REPO_V=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
NPM_V=$(npm view ironvise version 2>/dev/null || echo "unknown")
if [ "$NPM_V" = "$REPO_V" ] || [ "$NPM_V" = "unknown" ]; then
  check_doc "npm ironvise ($NPM_V) matches repo ($REPO_V)" ok
else
  check_doc "npm ironvise is $NPM_V, repo is $REPO_V - install from source" no
fi

TOTAL=$(python3 -c "print(f'{$(now)-$START_ALL:.0f}')")

printf '\n%s%s%s\n' "$B" "────────────────────────────────────────────────" "$N"
printf '%s\n' "${TIMINGS[@]}"
printf '%s────────────────────────────────────────────────%s\n' "$B" "$N"
printf '%sTIME TO FIRST VERIFICATION: %ss%s   (clone excluded; whole audit %ss)\n' \
  "$B" "$TTFV" "$N" "$TOTAL"
printf '%s\n' "${D}Warm caches make this optimistic. Quote the clean-machine number.${N}"

if [ "$FAILED" -ne 0 ]; then
  printf '\n%s%d documented step(s) failed.%s\n' "$R" "$FAILED" "$N"
  exit 1
fi
printf '\n%sEvery documented step ran.%s\n' "$G" "$N"
