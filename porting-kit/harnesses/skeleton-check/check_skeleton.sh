#!/usr/bin/env bash
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Re-cited: #9->#044, #25->#052.
# Skeleton gate — the shipped skeleton must PASS the gates it configures. It sets
# strict workspace lints ([workspace.lints]: arithmetic_side_effects,
# cast_possible_truncation, the unsafe docs) and the kit's CI runs `cargo fmt
# --check` + `cargo clippy --all-targets -- -D warnings` + build + test. If the
# skeleton itself fails those, every port that copies it starts RED (LESSONS #044:
# a template must pass the gates it ships). Nothing caught this before because
# `make check-kit` was toolchain-free and never built the skeleton.
#
# This gate is toolchain-OPTIONAL so check-kit still runs with only python3+bash:
# with no cargo it prints SKIP and exits 0; with cargo it runs the real checks.
# The skeleton has no external dependencies, so the build/test is offline.
#
# Usage:
#   check_skeleton.sh [SKELETON_DIR]   # real gate when cargo is present, else SKIP
#   check_skeleton.sh --check          # smoke: validate this script; report cargo
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
have() { command -v "$1" >/dev/null 2>&1; }
DEFAULT_SKEL="$HERE/../../skeleton"

# THE verdict: is DIR a skeleton this gate can actually run against? Extracted
# so `--check` can exercise it against a known-BAD path too (LESSONS #052): the
# happy path alone proves nothing about whether the check would ever refuse.
skel_present() { test -d "$1" && test -f "$1/Cargo.toml"; }

if [[ "${1:-}" == "--check" ]]; then
  ok=1
  bash -n "$0" && echo "PASS  script syntax ok"
  if skel_present "$DEFAULT_SKEL"; then
    echo "PASS  skeleton dir present"
  else
    echo "FAIL  skeleton dir missing/incomplete: $DEFAULT_SKEL" >&2; ok=0
  fi
  # Negative fixture — the pin: an empty dir and a nonexistent one must both be
  # refused, or "skeleton dir present" is a sentence that can never be false.
  _empty="$(mktemp -d)"
  if skel_present "$_empty" || skel_present "$DEFAULT_SKEL/definitely-not-here"; then
    echo "FAIL  validator calls an empty / nonexistent directory a skeleton" >&2; ok=0
  else
    echo "PASS  validator refuses an empty and a nonexistent skeleton dir"
  fi
  rmdir "$_empty" 2>/dev/null || true
  [[ "$ok" == "1" ]] || { echo "self-test: FAILED"; exit 1; }
  if have cargo; then echo "note: cargo present — the skeleton gate runs the real fmt/clippy/build/test"
  else echo "note: cargo absent — the skeleton gate will SKIP (install a Rust toolchain to run it)"; fi
  echo "self-test: OK"
  exit 0
fi

SKEL="${1:-$DEFAULT_SKEL}"
if ! have cargo; then
  echo "SKIP  skeleton gate: no cargo on PATH (install a Rust toolchain to run it)"
  exit 0
fi
cd "$SKEL"
echo ">> cargo fmt --all -- --check";                cargo fmt --all -- --check
echo ">> cargo clippy --all-targets -- -D warnings"; cargo clippy --all-targets -- -D warnings
echo ">> cargo build --release";                     cargo build --release
echo ">> cargo test --all";                          cargo test --all
echo "PASS  skeleton passes the gates it ships"
