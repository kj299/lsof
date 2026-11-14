#!/usr/bin/env bash
# Supply-chain gate — dependencies are part of your memory-safety story. Runs
# cargo-audit (known RUSTSEC advisories) and cargo-deny (advisories + license +
# source/ban policy). A vulnerable or unvetted dependency undoes a careful port.
# (PLAYBOOK cross-cutting controls; SECURITY-CHECKLIST "supply chain".)
#
# Usage:
#   run_supply_chain.sh [CRATE_DIR]     # run the real gate (needs the tools)
#   run_supply_chain.sh --check         # smoke: validate this script + config,
#                                       # report tool availability; fails if the
#                                       # script does not parse or the config is gone
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

have() { command -v "$1" >/dev/null 2>&1; }

# The crown verdict, extracted so mutation can bite and so a negative fixture can
# aim at it. It was `test -f ... && echo PASS` inline: under `set -e` a failing
# left-hand side of `&&` does not exit, so a MISSING policy file printed nothing
# at all and the check went on to say `self-test: OK`. The gate that guards the
# dependency policy passed when the policy was gone (LESSONS #052, and #036's
# fail-open shape), found by the sweep's first run here (LESSONS #053).
have_deny_template() { test -f "$1/deny.template.toml"; }

if [[ "${1:-}" == "--check" ]]; then
  # `bash -n "$0" && echo PASS` could not fail this check: under `set -e` a
  # failing command inside an `&&` list does not stop the script (LESSONS #082).
  if bash -n "$0"; then echo "PASS  script syntax ok"
  else echo "FAIL  this script does not parse"; exit 1; fi
  if ! have_deny_template "$HERE"; then
    echo "FAIL  deny.template.toml missing — the cargo-deny policy this gate applies is gone"
    exit 1
  fi
  echo "PASS  deny.template.toml present"
  # NEGATIVE fixture: an empty directory must be refused, or "present" is a
  # statement about nothing.
  _empty="$(mktemp -d)"
  if have_deny_template "$_empty"; then
    echo "FAIL  an empty config dir reports the deny policy as present"; rm -rf "$_empty"; exit 1
  fi
  rm -rf "$_empty"
  echo "PASS  a missing deny.template.toml is refused"
  # tomllib validate the deny config if python is around
  if have python3; then
    python3 - "$HERE/deny.template.toml" <<'PY'
import sys, tomllib
tomllib.load(open(sys.argv[1], "rb"))
print("PASS  deny.template.toml parses")
PY
  fi
  # tomllib proves only that the file is TOML. cargo-deny is the parser that
  # matters: until 2026-11-14 the template said `wildcard-dependencies`, a key
  # cargo-deny rejects outright, and every check above passed it, with cargo-deny
  # installed and never asked (LESSONS #089; the primary line's entry 065 found
  # it in that copy). So where cargo and cargo-deny exist, load the template the
  # way the gate does, against a one-crate fixture, and require a copy with a
  # misspelt key to be REFUSED, or the load proves nothing.
  if have cargo && have cargo-deny; then
    _fx="$(mktemp -d)"
    mkdir -p "$_fx/src"
    printf '[package]\nname = "fx"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\npublish = false\n' > "$_fx/Cargo.toml"
    : > "$_fx/src/lib.rs"
    if ! ( cd "$_fx" && { cargo generate-lockfile -q --offline 2>/dev/null || cargo generate-lockfile -q; } ); then
      echo "FAIL  could not make the fixture crate cargo-deny runs against"; rm -rf "$_fx"; exit 1
    fi
    if ! ( cd "$_fx" && cargo deny --config "$HERE/deny.template.toml" check bans licenses sources >/dev/null 2>&1 ); then
      echo "FAIL  cargo-deny rejects deny.template.toml (or a clean crate fails it)"; rm -rf "$_fx"; exit 1
    fi
    echo "PASS  cargo-deny loads deny.template.toml and a clean crate passes it"
    sed 's/^wildcards = /wildcard-dependencies = /' "$HERE/deny.template.toml" > "$_fx/bad.toml"
    if ( cd "$_fx" && cargo deny --config "$_fx/bad.toml" check bans >/dev/null 2>&1 ); then
      echo "FAIL  cargo-deny accepted a template with an unknown key — the load above proves nothing"
      rm -rf "$_fx"; exit 1
    fi
    echo "PASS  cargo-deny refuses a template with an unknown key"
    rm -rf "$_fx"
  else
    echo "note: cargo or cargo-deny absent — deny.template.toml was NOT loaded by the tool that reads it"
  fi
  for t in cargo cargo-audit cargo-deny; do
    if have "$t"; then echo "note: $t available"; else echo "note: $t NOT installed (install for the real gate)"; fi
  done
  echo "self-test: OK"
  exit 0
fi

DIR="${1:-.}"
cd "$DIR"
rc=0

if have cargo-audit; then
  echo ">> cargo audit"
  cargo audit || rc=1
else
  echo "!! cargo-audit not installed:  cargo install cargo-audit" >&2
  rc=1
fi

if have cargo-deny; then
  echo ">> cargo deny check"
  # Use the kit's policy unless the crate ships its own deny.toml.
  if [[ -f deny.toml ]]; then
    cargo deny check || rc=1
  else
    cargo deny --config "$HERE/deny.template.toml" check || rc=1
  fi
else
  echo "!! cargo-deny not installed:  cargo install cargo-deny" >&2
  rc=1
fi

exit "$rc"
