#!/usr/bin/env bash
# Sanitizer & Miri gate — catch UB the compiler can't. For a C-to-Rust port the
# FFI/unsafe layer is the residual risk surface; these tools interrogate it:
#   * Miri            — UB in the pure/unsafe Rust (OOB, use-after-free, invalid
#                       aligns, data races in `unsafe`). Runs the test suite.
#                       Miri IS Rust's undefined-behavior detector.
#   * ASan/TSan       — the same classes at the real FFI boundary, where Miri
#                       cannot follow (needs nightly -Zsanitizer). TSan for
#                       threaded code (the lsof-rs hang class — worker threads
#                       over shared handles).
# (PLAYBOOK Phase 4 gate 4; SECURITY-CHECKLIST "no UB at the FFI boundary".)
#
# THERE IS NO `undefined` SANITIZER IN RUSTC. This script used to map `ubsan` to
# `-Zsanitizer=undefined`, and `all` included it, so `ubsan` — and `all`, which
# is the DEFAULT mode — could never pass on any codebase however clean. Verified
# here, not assumed:
#
#     $ rustc +nightly -Zsanitizer=undefined --emit=metadata x.rs; echo $?
#     error: incorrect value `undefined` for unstable option `sanitizer` -
#       comma separated list of sanitizers: `address`, `cfi`, `dataflow`,
#       `hwaddress`, `kcfi`, `kernel-address`, `kernel-hwaddress`, `leak`,
#       `memory`, `memtag`, `safestack`, `shadow-call-stack`, `thread`, or
#       'realtime' was expected
#     1
#
# A gate that can never go green teaches its users to skip it, and a skipped
# control is a broken control — as bad as one that can never fail (LESSONS #051),
# and this one was found by the gate-mutation sweep's first run here (LESSONS #053).
# `ubsan` now delegates to Miri, which is the tool that actually answers the
# question, and `--check` carries a NEGATIVE FIXTURE pinning the validator
# against `undefined`, the exact value that shipped. `--check` validating only
# bash syntax is why this survived: it printed `self-test: OK` over a mode that
# had never once run (LESSONS #036).
#
# Usage:
#   run_sanitizers.sh [miri|asan|ubsan|tsan|all] [CRATE_DIR] [-- <cargo args>]
#   run_sanitizers.sh --check      # smoke: validate script + report tool avail
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
have() { command -v "$1" >/dev/null 2>&1; }

# The values rustc's `-Zsanitizer` actually accepts. The crown verdict of this
# gate: a mode that maps to anything outside this list is refused up front
# instead of failing forever at build time.
RUSTC_SANITIZERS="address cfi dataflow hwaddress kcfi kernel-address kernel-hwaddress leak memory memtag safestack shadow-call-stack thread realtime"
is_valid_san() {
  case " $RUSTC_SANITIZERS " in
    *" $1 "*) return 0;;
    *) return 1;;
  esac
}

if [[ "${1:-}" == "--check" ]]; then
  bash -n "$0" && echo "PASS  script syntax ok"
  # POSITIVE fixture: the sanitizers this script actually dispatches to.
  for s in address thread; do
    is_valid_san "$s" || { echo "FAIL  is_valid_san rejects a real sanitizer: $s"; exit 1; }
  done
  echo "PASS  is_valid_san accepts address/thread"
  # NEGATIVE fixture — the whole point. `undefined` is the value that shipped
  # here and could never pass; if this check ever goes quiet, the gate has
  # regressed to one that cannot go green.
  if is_valid_san undefined; then
    echo "FAIL  is_valid_san accepts 'undefined' — rustc does not; this gate could never pass"
    exit 1
  fi
  echo "PASS  is_valid_san rejects 'undefined' (rustc has no UB sanitizer; miri is)"
  # Cross-check the hardcoded list against a live nightly rustc when there is
  # one, so the list cannot silently drift from the compiler.
  if have rustc && rustup toolchain list 2>/dev/null | grep -q nightly; then
    tmp="$(mktemp -d)"; printf 'fn main(){}\n' > "$tmp/probe.rs"
    if rustc +nightly -Zsanitizer=address --emit=metadata --out-dir "$tmp" "$tmp/probe.rs" >/dev/null 2>&1; then
      echo "PASS  live nightly rustc accepts -Zsanitizer=address"
    else
      echo "note: live nightly rustc rejected -Zsanitizer=address (host/target support)"
    fi
    if rustc +nightly -Zsanitizer=undefined --emit=metadata --out-dir "$tmp" "$tmp/probe.rs" >/dev/null 2>&1; then
      echo "FAIL  live nightly rustc ACCEPTED -Zsanitizer=undefined — update RUSTC_SANITIZERS"
      rm -rf "$tmp"; exit 1
    fi
    echo "PASS  live nightly rustc rejects -Zsanitizer=undefined"
    rm -rf "$tmp"
  else
    echo "note: no nightly toolchain — RUSTC_SANITIZERS not cross-checked against rustc"
  fi
  if have rustup; then
    rustup component list 2>/dev/null | grep -q "miri" && echo "note: miri component known to rustup" || echo "note: install miri:  rustup +nightly component add miri"
  else
    echo "note: rustup not installed (needed for miri/nightly sanitizers)"
  fi
  echo "self-test: OK"
  exit 0
fi

MODE="${1:-all}"; DIR="${2:-.}"
# Everything after `--` is passed through to cargo, so a port can scope the run
# (`-p core`, `--test foo`) instead of forking this script.
CARGO_ARGS=()
if [[ "${3:-}" == "--" ]]; then shift 3; CARGO_ARGS=("$@"); fi
cd "$DIR"
TRIPLE="$(rustc -vV 2>/dev/null | awk '/host:/{print $2}')"
rc=0

run_miri() {
  if have cargo && rustup toolchain list 2>/dev/null | grep -q nightly; then
    echo ">> cargo +nightly miri test"
    cargo +nightly miri test "${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"}" || rc=1
  else
    echo "!! miri needs nightly:  rustup toolchain install nightly && rustup +nightly component add miri" >&2
    rc=1
  fi
}

run_san() {
  local san="$1"
  if ! is_valid_san "$san"; then
    echo "!! rustc has no '$san' sanitizer (accepted: $RUSTC_SANITIZERS)" >&2
    rc=1
    return
  fi
  if rustup toolchain list 2>/dev/null | grep -q nightly; then
    echo ">> cargo +nightly test with -Zsanitizer=$san"
    RUSTFLAGS="-Zsanitizer=$san" RUSTDOCFLAGS="-Zsanitizer=$san" \
      cargo +nightly test -Zbuild-std --target "$TRIPLE" "${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"}" || rc=1
  else
    echo "!! $san sanitizer needs the nightly toolchain + -Zbuild-std" >&2
    rc=1
  fi
}

case "$MODE" in
  miri)  run_miri;;
  asan)  run_san address;;
  # Rust's UB detector is Miri, not a `-Zsanitizer` mode. Kept as a mode name so
  # existing callers and docs keep working, and so nobody re-adds `undefined`.
  ubsan) echo ">> 'ubsan': rustc has no undefined-behavior sanitizer; miri is Rust's UB detector"
         run_miri;;
  tsan)  run_san thread;;
  all)   run_miri; run_san address;;
  *) echo "usage: $0 [miri|asan|ubsan|tsan|all] [CRATE_DIR] [-- <cargo args>] | --check" >&2; exit 2;;
esac
exit "$rc"
