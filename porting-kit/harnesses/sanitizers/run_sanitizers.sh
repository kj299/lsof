#!/usr/bin/env bash
# Sanitizer & Miri gate — catch UB the compiler can't. For a C-to-Rust port the
# FFI/unsafe layer is the residual risk surface; these tools interrogate it:
#   * Miri            — UB in the pure/unsafe Rust (OOB, use-after-free, invalid
#                       aligns, data races in `unsafe`). Runs the test suite.
#   * ASan/UBSan      — the same classes at the real FFI boundary (needs nightly
#                       -Zsanitizer). TSan for threaded code (the winlsof hang
#                       class — worker threads over shared handles).
# (PLAYBOOK Phase 4 gate 4; SECURITY-CHECKLIST "no UB at the FFI boundary".)
#
# Usage:
#   run_sanitizers.sh [miri|asan|ubsan|tsan|all] [CRATE_DIR]
#   run_sanitizers.sh --check      # smoke: validate script + report tool avail
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
have() { command -v "$1" >/dev/null 2>&1; }

if [[ "${1:-}" == "--check" ]]; then
  bash -n "$0" && echo "PASS  script syntax ok"
  if have rustup; then
    rustup component list 2>/dev/null | grep -q "miri" && echo "note: miri component known to rustup" || echo "note: install miri:  rustup +nightly component add miri"
  else
    echo "note: rustup not installed (needed for miri/nightly sanitizers)"
  fi
  echo "self-test: OK"
  exit 0
fi

MODE="${1:-all}"; DIR="${2:-.}"
cd "$DIR"
TRIPLE="$(rustc -vV 2>/dev/null | awk '/host:/{print $2}')"
rc=0

run_miri() {
  if have cargo && rustup toolchain list 2>/dev/null | grep -q nightly; then
    echo ">> cargo +nightly miri test"
    cargo +nightly miri test || rc=1
  else
    echo "!! miri needs nightly:  rustup toolchain install nightly && rustup +nightly component add miri" >&2
    rc=1
  fi
}

run_san() {
  local san="$1"
  if rustup toolchain list 2>/dev/null | grep -q nightly; then
    echo ">> cargo +nightly test with -Zsanitizer=$san"
    RUSTFLAGS="-Zsanitizer=$san" RUSTDOCFLAGS="-Zsanitizer=$san" \
      cargo +nightly test -Zbuild-std --target "$TRIPLE" || rc=1
  else
    echo "!! $san sanitizer needs the nightly toolchain + -Zbuild-std" >&2
    rc=1
  fi
}

case "$MODE" in
  miri)  run_miri;;
  asan)  run_san address;;
  ubsan) run_san undefined;;
  tsan)  run_san thread;;
  all)   run_miri; run_san address; run_san undefined;;
  *) echo "usage: $0 [miri|asan|ubsan|tsan|all] [CRATE_DIR] | --check" >&2; exit 2;;
esac
exit "$rc"
