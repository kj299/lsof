#!/usr/bin/env bash
# Supply-chain gate — dependencies are part of your memory-safety story. Runs
# cargo-audit (known RUSTSEC advisories) and cargo-deny (advisories + license +
# source/ban policy). A vulnerable or unvetted dependency undoes a careful port.
# (PLAYBOOK cross-cutting controls; SECURITY-CHECKLIST "supply chain".)
#
# Usage:
#   run_supply_chain.sh [CRATE_DIR]     # run the real gate (needs the tools)
#   run_supply_chain.sh --check         # smoke: validate this script + config,
#                                       # report tool availability, never fail
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

have() { command -v "$1" >/dev/null 2>&1; }

# The crown verdict, extracted so mutation can bite and so a negative fixture can
# aim at it. It was `test -f ... && echo PASS` inline: under `set -e` a failing
# left-hand side of `&&` does not exit, so a MISSING policy file printed nothing
# at all and the check went on to say `self-test: OK`. The gate that guards the
# dependency policy passed when the policy was gone (LESSONS #051, and #036's
# fail-open shape).
have_deny_template() { test -f "$1/deny.template.toml"; }

if [[ "${1:-}" == "--check" ]]; then
  bash -n "$0" && echo "PASS  script syntax ok"
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
