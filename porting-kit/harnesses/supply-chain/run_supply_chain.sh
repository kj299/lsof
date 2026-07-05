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

if [[ "${1:-}" == "--check" ]]; then
  bash -n "$0" && echo "PASS  script syntax ok"
  test -f "$HERE/deny.template.toml" && echo "PASS  deny.template.toml present"
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
