#!/usr/bin/env bash
# Fuzz-target scaffolder — generate a cargo-fuzz target skeleton for a newly
# ported module's public parse/input API. Fuzzing the input surface is where a
# C-to-Rust rewrite proves it removed the memory-safety bugs: any panic/crash on
# untrusted input is a release blocker (PLAYBOOK Phase 4, gate 3).
#
# Usage:
#   gen_fuzz_target.sh <module_name> [--crate CRATE] [--out DIR]
#   gen_fuzz_target.sh --check          # smoke test: generate to a temp dir, verify
#
# Produces DIR/fuzz_targets/<module_name>.rs from the template, and prints the
# one-time setup (cargo install cargo-fuzz; cargo fuzz init) if not already done.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$HERE/fuzz_target.template.rs"

emit() {
  local module="$1" crate="$2" out="$3"
  mkdir -p "$out/fuzz_targets"
  sed -e "s/__MODULE__/$module/g" -e "s/__CRATE__/$crate/g" \
      "$TEMPLATE" > "$out/fuzz_targets/${module}.rs"
  echo "wrote $out/fuzz_targets/${module}.rs"
}

if [[ "${1:-}" == "--check" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  emit "parser" "mycrate" "$tmp" >/dev/null
  test -f "$tmp/fuzz_targets/parser.rs" || { echo "FAIL: no target generated"; exit 1; }
  grep -q "fuzz_target!" "$tmp/fuzz_targets/parser.rs" || { echo "FAIL: template not expanded"; exit 1; }
  grep -q "mycrate" "$tmp/fuzz_targets/parser.rs" || { echo "FAIL: crate not substituted"; exit 1; }
  echo "PASS  fuzz scaffolder generates a valid target"
  echo "self-test: OK"
  exit 0
fi

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <module_name> [--crate CRATE] [--out DIR]  |  $0 --check" >&2
  exit 2
fi

MODULE="$1"; shift
CRATE="mycrate"; OUT="fuzz"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --crate) CRATE="$2"; shift 2;;
    --out)   OUT="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

emit "$MODULE" "$CRATE" "$OUT"
cat <<EOF

Next steps (one-time, if not already set up):
  cargo install cargo-fuzz
  cargo fuzz init                       # if this crate has no fuzz/ yet
  cargo fuzz run $MODULE -- -max_total_time=60     # smoke
  cargo fuzz run $MODULE                            # deep (nightly / CI schedule)
Seed the corpus with real inputs and any crash reproducers you find.
EOF
