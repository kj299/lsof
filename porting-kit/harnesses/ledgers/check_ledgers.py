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
  sanitizers   a CI workflow that RUNS miri, asan or ubsan (a mention in a
               comment or a step name does not count -- see executable_text)

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
    for wf in glob.glob(os.path.join(ci_dir, "*.y*ml")):
        try:
            text = open(wf, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if SAN.search(executable_text(text)):
            found["sanitizers"].append(wf)
    return found


# `sanitizer` carries no leading word boundary: the canonical way to turn one on
# in Rust is `RUSTFLAGS: -Zsanitizer=address`, and `\b` cannot match between the
# `Z` and the `s`, so the original pattern was blind to exactly the flag the
# ledger exists to find. The shorter, more ambiguous tokens keep their boundary.
SAN = re.compile(r"\b(miri|asan|ubsan|tsan)|sanitizer", re.I)

# `- key: value`, capturing the key and whatever follows it.
_KEYVAL = re.compile(r"^\s*-?\s*([A-Za-z_][\w.-]*)\s*:\s*(.*)$")
_BLOCK_SCALAR = {"|", ">", "|-", ">-", "|+", ">+"}


def _strip_comment(line: str) -> str:
    """Drop a YAML end-of-line comment. A `#` inside quotes is not a comment."""
    out: list[str] = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            out.append(ch)
        elif ch == "#" and (not out or out[-1].isspace()):
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def executable_text(text: str) -> str:
    """The parts of a workflow that CONFIGURE OR RUN something.

    The sanitizers ledger asks whether CI runs a sanitizer. Searching the raw
    file answers a different question — whether the file *says the word* — and
    the two came apart in practice (LESSONS #29; LESSONS #31): a workflow added in
    PR #83 mentioned the tools in a header comment while explaining that it ran
    none of them, and that alone satisfied this ledger for a job that runs no
    sanitizer at all.

    So three kinds of text are excluded, because none of them runs anything:

      * comments;
      * `name:` values — a step called "ledgers exist (… sanitizer job)" is a
        label, and lsof-rs-ci.yml has exactly that one;
      * bare mapping keys — a job called `miri:` is a label too.

    What is kept is values (`run:`, `env:`, `with:`, `uses:` …) and the bodies
    of block scalars, which is where `cargo … miri test` and
    `RUSTFLAGS: -Zsanitizer=address` actually live.

    Deliberately conservative: a line inside a `run:` script that happens to
    look like `name: x` is dropped too. That can only cause a false *negative* —
    a gate that asks for more evidence — which is the safe direction for a
    control whose whole failure mode was accepting too little.
    """
    keep: list[str] = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        m = _KEYVAL.match(line)
        if not m:
            keep.append(line)          # block-scalar body, list item, continuation
            continue
        key, val = m.group(1), m.group(2).strip()
        if key.lower() == "name":
            continue                   # a human-readable label
        if not val or val in _BLOCK_SCALAR:
            continue                   # a bare key, or a block-scalar introducer
        keep.append(val)
    return "\n".join(keep)


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

        # The sanitizers ledger must answer "does CI RUN one", not "does the
        # file say the word". Each case below is a shape that occurs in a real
        # workflow in this repository.
        def only_wf(body: str) -> list[str]:
            for stale in glob.glob(os.path.join(ci, "*.y*ml")):
                os.remove(stale)
            open(os.path.join(ci, "w.yml"), "w").write(body)
            return find_ledgers(port, ci)["sanitizers"]

        check("comment-only mention is NOT evidence", not only_wf(
            "name: decoy\n"
            "# runs no miri, no asan and no sanitizer of any kind\n"
            "jobs:\n  n:\n    steps:\n      - run: echo hi\n"))
        check("step-name-only mention is NOT evidence", not only_wf(
            "jobs:\n  n:\n    steps:\n"
            "      - name: ledgers exist (progress, fuzz target, sanitizer job)\n"
            "        run: echo hi\n"))
        check("a job KEY named miri is NOT evidence", not only_wf(
            "jobs:\n  miri:\n    steps:\n      - run: echo hi\n"))
        check("a run: command IS evidence", bool(only_wf(
            "jobs:\n  j:\n    steps:\n      - run: cargo +nightly miri test\n")))
        check("a run: block-scalar body IS evidence", bool(only_wf(
            "jobs:\n  j:\n    steps:\n      - run: |\n"
            "          ls clang_rt.asan_dynamic-x86_64.dll\n")))
        check("an env: value IS evidence", bool(only_wf(
            "jobs:\n  j:\n    steps:\n      - env:\n"
            "          RUSTFLAGS: -Zsanitizer=address\n        run: cargo build\n")))
        check("a with: value IS evidence", bool(only_wf(
            "jobs:\n  j:\n    steps:\n      - uses: dtolnay/rust-toolchain@master\n"
            "        with:\n          components: miri\n")))
        check("a quoted # is not treated as a comment", bool(only_wf(
            'jobs:\n  j:\n    steps:\n      - run: echo "miri # not a comment"\n')))
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
