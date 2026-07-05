#!/usr/bin/env python3
"""Unsafe-audit harness — every `unsafe {}` block and `unsafe impl` must carry a
`// SAFETY:` justification. Hard-fails (exit 1) on any undocumented block.

This is the control the winlsof retrospective wished for: it counted 144 grep
hits of "unsafe" but only 91 `// SAFETY:` comments, unable to tell real blocks
from the word appearing in comments/strings. This tool tokenizes just enough to
ignore comments and string literals, so it counts *real* blocks — the same scope
as clippy's `undocumented_unsafe_blocks` lint, usable without a nightly toolchain
and embeddable in the progress tracker via --json.

Scope: `unsafe { ... }` blocks and `unsafe impl` items. `unsafe fn`/`unsafe
trait`/`unsafe extern` *declarations* are documented via a `/// # Safety` doc
section (clippy's `missing_safety_doc`) and are intentionally out of scope here —
delegate those to clippy. That delegation is only real if clippy is wired to
enforce it: the CI template (`ci/porting-ci.template.yml`) and the skeleton
`[workspace.lints]` now enable `clippy::missing_safety_doc` +
`clippy::undocumented_unsafe_blocks` (LESSONS #3). This harness is the
*toolchain-free* half — it runs anywhere (no nightly/clippy) and is the hard
gate for blocks; clippy is the belt-and-suspenders that also covers `unsafe fn`.

Usage:
  audit_unsafe.py PATH [PATH ...] [--window N] [--warn] [--json] [--quiet]
  audit_unsafe.py --self-test

Exit: 0 = all documented (or --warn); 1 = undocumented blocks found; 2 = usage.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

SAFETY_MARK = "SAFETY:"


def _mask(src: str) -> str:
    """Return src with comment and string-literal *contents* replaced by spaces,
    preserving every byte offset and newline. Real code keeps its characters, so
    a subsequent search for the `unsafe` keyword can't match inside a comment or
    string. Handles //, /* */ (nested), "..." with escapes, char/lifetime ',
    and raw strings r"...", r#"..."#."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        two = src[i : i + 2]
        # line comment
        if two == "//":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        # block comment (nestable in Rust)
        if two == "/*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth:
                if src[i : i + 2] == "/*":
                    depth += 1
                    out.append("  ")
                    i += 2
                elif src[i : i + 2] == "*/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if src[i] == "\n" else " ")
                    i += 1
            continue
        # raw string  r"..."  r#"..."#  (and br"...")
        if c in "rb" and i + 1 < n:
            j = i
            if src[j] == "b":
                j += 1
            if j < n and src[j] == "r":
                k = j + 1
                hashes = 0
                while k < n and src[k] == "#":
                    hashes += 1
                    k += 1
                if k < n and src[k] == '"':
                    # keep the prefix + opening quote as-is (offsets), mask body
                    for p in range(i, k + 1):
                        out.append(src[p])
                    k += 1
                    close = '"' + "#" * hashes
                    while k < n and src[k : k + len(close)] != close:
                        out.append("\n" if src[k] == "\n" else " ")
                        k += 1
                    out.append(close)
                    i = k + len(close)
                    continue
        # normal string
        if c == '"':
            out.append('"')
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append('"')
                i += 1
            continue
        # char literal or lifetime: 'a'  '\n'  'static  — only a real char
        # literal can hide an `unsafe`-like sequence; lifetimes can't, so only
        # mask when it looks like 'x' or '\x'.
        if c == "'":
            if i + 2 < n and src[i + 1] == "\\":
                out.append("'  ")
                i += 2
                while i < n and src[i] != "'":
                    out.append(" ")
                    i += 1
                if i < n:
                    out.append("'")
                    i += 1
                continue
            if i + 2 < n and src[i + 2] == "'":
                out.append("' '")
                i += 3
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _is_word_boundary(s: str, start: int, end: int) -> bool:
    before = s[start - 1] if start > 0 else " "
    after = s[end] if end < len(s) else " "
    ok = lambda ch: not (ch.isalnum() or ch == "_")
    return ok(before) and ok(after)


def find_unsafe_blocks(src: str):
    """Yield (line_no, kind) for each real `unsafe {` block or `unsafe impl`."""
    masked = _mask(src)
    idx = 0
    while True:
        pos = masked.find("unsafe", idx)
        if pos < 0:
            return
        idx = pos + 6
        if not _is_word_boundary(masked, pos, pos + 6):
            continue
        # what follows the keyword (skip whitespace)?
        j = pos + 6
        while j < len(masked) and masked[j] in " \t\r\n":
            j += 1
        rest = masked[j : j + 6]
        line_no = src.count("\n", 0, pos) + 1
        if masked[j : j + 1] == "{":
            yield (line_no, "block")
        elif rest.startswith("impl"):
            yield (line_no, "impl")
        # `unsafe fn/trait/extern` → out of scope (clippy missing_safety_doc)


def has_safety_comment(lines, line_no: int, window: int) -> bool:
    """True if a `// SAFETY:` (or `/* SAFETY: */`) documents the block on
    `line_no`. Accepts a trailing marker on the block's own line, or a marker on
    the contiguous run of comment / attribute / blank lines *immediately* above
    it. The scan stops at the first real code line, so one block's SAFETY comment
    cannot bleed onto a following block, and gives up after `window` lines."""
    # trailing `// SAFETY:` on the block's own line
    own = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    if SAFETY_MARK in own and ("//" in own or "/*" in own):
        return True
    scanned = 0
    for idx in range(line_no - 2, -1, -1):  # walk upward from the line above
        if scanned >= window:
            break
        scanned += 1
        stripped = lines[idx].strip()
        if not stripped:
            continue  # blank line: keep scanning the run
        if stripped.startswith(("#[", "#!")):
            continue  # attribute between comment and block: keep scanning
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            if SAFETY_MARK in stripped:
                return True
            continue  # some other comment line: keep scanning
        break  # first real code line: the run is over, not documented
    return False


def audit_text(src: str, window: int):
    lines = src.splitlines()
    documented, undocumented = [], []
    for line_no, kind in find_unsafe_blocks(src):
        (documented if has_safety_comment(lines, line_no, window) else undocumented).append(
            (line_no, kind)
        )
    return documented, undocumented


def iter_rs_files(paths):
    for p in paths:
        if os.path.isfile(p) and p.endswith(".rs"):
            yield p
        elif os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                if "target" in root.split(os.sep):
                    continue
                for f in files:
                    if f.endswith(".rs"):
                        yield os.path.join(root, f)


def run(paths, window, warn, as_json, quiet):
    total_doc = total_undoc = 0
    findings = []
    for path in sorted(set(iter_rs_files(paths))):
        try:
            src = open(path, encoding="utf-8", errors="replace").read()
        except OSError as e:
            print(f"warn: cannot read {path}: {e}", file=sys.stderr)
            continue
        doc, undoc = audit_text(src, window)
        total_doc += len(doc)
        total_undoc += len(undoc)
        for line_no, kind in undoc:
            findings.append({"file": path, "line": line_no, "kind": kind})

    if as_json:
        print(json.dumps({
            "documented": total_doc,
            "undocumented": total_undoc,
            "findings": findings,
        }, indent=2))
    elif not quiet:
        for f in findings:
            print(f"UNDOCUMENTED unsafe {f['kind']}: {f['file']}:{f['line']}  (needs // SAFETY:)")
        total = total_doc + total_undoc
        print(f"\nunsafe blocks: {total}  documented: {total_doc}  undocumented: {total_undoc}")

    if total_undoc and not warn:
        return 1
    return 0


SELF_TEST_SRC = r'''
// SAFETY: this one is fine
unsafe { do_thing(); }

unsafe { undocumented(); }        // should be flagged

let s = "unsafe { not_real() }";  // in a string, must be ignored
// unsafe { also_not_real() }     // in a comment, must be ignored

// SAFETY: impl invariant holds
unsafe impl Send for Foo {}

unsafe fn declared() {}           // out of scope (needs # Safety doc, not here)
'''


def self_test():
    doc, undoc = audit_text(SELF_TEST_SRC, window=3)
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    check("1 documented block + 1 documented impl", len(doc) == 2)
    check("exactly 1 undocumented block", len(undoc) == 1)
    check("undocumented is the block on line 5", undoc and undoc[0][1] == "block")
    check("string/comment `unsafe` ignored (no extra findings)", len(doc) + len(undoc) == 3)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="files or directories to audit")
    ap.add_argument("--window", type=int, default=6, help="max comment/blank/attr lines to scan above a block for // SAFETY: (default 6)")
    ap.add_argument("--warn", action="store_true", help="report but exit 0 (advisory mode)")
    ap.add_argument("--json", action="store_true", help="machine-readable output for the progress tracker")
    ap.add_argument("--quiet", action="store_true", help="suppress per-finding lines")
    ap.add_argument("--self-test", action="store_true", help="run the built-in fixture test")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.paths:
        ap.print_usage(sys.stderr)
        print("error: give at least one PATH, or --self-test", file=sys.stderr)
        return 2
    return run(args.paths, args.window, args.warn, args.json, args.quiet)


if __name__ == "__main__":
    sys.exit(main())
