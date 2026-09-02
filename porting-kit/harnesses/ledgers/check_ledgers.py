#!/usr/bin/env python3
"""Ledger presence gate — do the artifacts the playbook *asserts* actually exist?

LESSONS #019: after 21 PRs and three releases, lsof-rs had never created three
artifacts the PLAYBOOK names as exit criteria — `progress.json`, `DIVERGENCES.md`,
and a fuzz target per parse module — and its CI had no sanitizer job although
the control table says "CI". Every gate was green, because no gate looked for
them. A control that is asserted but never checked does not exist. This makes
the assertion a failing build.

Checks (each can be waived by name with --allow, which must carry a reason):
  progress     a progress file (progress.json) under the port root
  divergences  a divergence ledger (DIVERGENCES.md, or differential/ledger.json)
  fuzz         at least one cargo-fuzz target (fuzz/fuzz_targets/*.rs)
  sanitizers   a CI workflow mentioning miri, asan or ubsan

Usage:
  check_ledgers.py PORT_ROOT [--ci-dir .github/workflows]
                   [--allow NAME=REASON ...] [--json] [--self-test]

Exit: 0 = every unwaived ledger present; 1 = something missing (named);
2 = usage error. A waiver without a reason is refused — that is the whole point.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import tempfile

CHECKS = ("progress", "divergences", "fuzz", "sanitizers")


def find_ledgers(root: str, ci_dir: str) -> dict[str, list[str]]:
    """-> {check: [paths found]}; an empty list is a missing ledger."""
    found: dict[str, list[str]] = {c: [] for c in CHECKS}
    for p in glob.glob(os.path.join(root, "**", "progress.json"), recursive=True):
        if "/target/" not in p and "/node_modules/" not in p:
            found["progress"].append(p)
    for pat in ("DIVERGENCES.md", os.path.join("differential", "ledger.json")):
        found["divergences"] += glob.glob(os.path.join(root, "**", pat), recursive=True)
    found["fuzz"] += glob.glob(os.path.join(root, "**", "fuzz", "fuzz_targets", "*.rs"), recursive=True)
    san = re.compile(r"\b(miri|asan|ubsan|tsan|sanitizer)", re.I)
    for wf in glob.glob(os.path.join(ci_dir, "*.y*ml")):
        try:
            if san.search(open(wf, encoding="utf-8", errors="replace").read()):
                found["sanitizers"].append(wf)
        except OSError:
            pass
    return found


def parse_allow(items: list[str]) -> dict[str, str]:
    allow: dict[str, str] = {}
    for it in items:
        name, sep, reason = it.partition("=")
        if name not in CHECKS:
            sys.exit(f"error: unknown ledger {name!r}; choose from {', '.join(CHECKS)}")
        if not sep or not reason.strip():
            sys.exit(f"error: --allow {name} needs a reason: --allow {name}=WHY")
        allow[name] = reason.strip()
    return allow


def run(root: str, ci_dir: str, allow: dict[str, str], as_json: bool) -> int:
    found = find_ledgers(root, ci_dir)
    missing = [c for c in CHECKS if not found[c] and c not in allow]
    report = {
        "root": root,
        "present": {c: found[c] for c in CHECKS if found[c]},
        "waived": allow,
        "missing": missing,
    }
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        for c in CHECKS:
            if found[c]:
                print(f"present  {c:<12} {found[c][0]}" + (f" (+{len(found[c])-1})" if len(found[c]) > 1 else ""))
            elif c in allow:
                print(f"waived   {c:<12} — {allow[c]}")
            else:
                print(f"MISSING  {c:<12} (the playbook names this as an exit criterion)")
        print(f"\nledgers: {len(CHECKS)}  present: {len(report['present'])}  waived: {len(allow)}  MISSING: {len(missing)}")
    return 1 if missing else 0


def self_test() -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name)
        ok = ok and cond

    with tempfile.TemporaryDirectory() as td:
        port = os.path.join(td, "port")
        ci = os.path.join(td, "wf")
        os.makedirs(os.path.join(port, "fuzz", "fuzz_targets"))
        os.makedirs(ci)
        # Empty port: everything missing.
        check("empty port: all four missing", run(port, ci, {}, as_json=True) == 1)
        found = find_ledgers(port, ci)
        check("empty port reports each by name", all(not found[c] for c in CHECKS))
        # Add them one at a time.
        open(os.path.join(port, "progress.json"), "w").write("{}")
        open(os.path.join(port, "DIVERGENCES.md"), "w").write("# ledger\n")
        open(os.path.join(port, "fuzz", "fuzz_targets", "parse.rs"), "w").write("")
        check("three of four present still fails (sanitizers)", run(port, ci, {}, True) == 1)
        open(os.path.join(ci, "ci.yml"), "w").write("jobs:\n  miri:\n    run: cargo miri test\n")
        check("all four present passes", run(port, ci, {}, True) == 0)
        # Waivers need reasons.
        os.remove(os.path.join(port, "progress.json"))
        check("missing again fails", run(port, ci, {}, True) == 1)
        check("reasoned waiver passes", run(port, ci, {"progress": "tracked in the issue board"}, True) == 0)
        try:
            parse_allow(["progress"])
            check("reasonless --allow refused", False)
        except SystemExit:
            check("reasonless --allow refused", True)
        try:
            parse_allow(["bogus=x"])
            check("unknown ledger name refused", False)
        except SystemExit:
            check("unknown ledger name refused", True)
        # The alternate divergence-ledger location counts.
        os.remove(os.path.join(port, "DIVERGENCES.md"))
        os.makedirs(os.path.join(port, "differential"))
        open(os.path.join(port, "differential", "ledger.json"), "w").write("[]")
        open(os.path.join(port, "progress.json"), "w").write("{}")
        check("differential/ledger.json accepted as the divergence ledger", run(port, ci, {}, True) == 0)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", help="the port's root directory")
    ap.add_argument("--ci-dir", default=".github/workflows", help="where CI workflows live (default .github/workflows)")
    ap.add_argument("--allow", action="append", default=[], metavar="NAME=REASON", help="waive one ledger, with a reason")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.root:
        ap.error("PORT_ROOT is required (or --self-test)")
    if not os.path.isdir(a.root):
        sys.exit(f"error: not a directory: {a.root}")
    return run(a.root, a.ci_dir, parse_allow(a.allow), a.json)


if __name__ == "__main__":
    sys.exit(main())
