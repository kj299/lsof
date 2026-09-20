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

# The crown verdict, extracted so it can be neutralized and so the self-test can
# aim a NEGATIVE fixture at it. It was three inline `grep -q ... || exit 1` lines
# inside --check, which only ever saw a correctly generated target: deleting the
# checks changed nothing the self-test observed, so they were pinned by nothing
# (LESSONS #052). Found by the sweep's first run in this kit (LESSONS #053).
valid_target() {
  local f="$1" crate="$2"
  test -f "$f" || return 1
  grep -q "fuzz_target!" "$f" || return 1
  grep -q "$crate" "$f" || return 1
  return 0
}

if [[ "${1:-}" == "--check" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  emit "parser" "mycrate" "$tmp" >/dev/null
  valid_target "$tmp/fuzz_targets/parser.rs" "mycrate" || {
    echo "FAIL: generated target is not valid (missing, unexpanded, or crate not substituted)"; exit 1; }
  echo "PASS  fuzz scaffolder generates a valid target"

  # NEGATIVE fixtures: each thing valid_target is supposed to catch, actually
  # present, so the predicate has to refuse rather than merely not-object.
  if valid_target "$tmp/fuzz_targets/nonexistent.rs" "mycrate"; then
    echo "FAIL: a missing target file counts as valid"; exit 1; fi
  echo "PASS  a missing target file is refused"

  printf 'fn main() {}\n' > "$tmp/unexpanded.rs"
  if valid_target "$tmp/unexpanded.rs" "mycrate"; then
    echo "FAIL: a file with no fuzz_target! counts as valid"; exit 1; fi
  echo "PASS  an unexpanded template is refused"

  if valid_target "$tmp/fuzz_targets/parser.rs" "some_other_crate"; then
    echo "FAIL: an unsubstituted crate name counts as valid"; exit 1; fi
  echo "PASS  a target naming the wrong crate is refused"

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
