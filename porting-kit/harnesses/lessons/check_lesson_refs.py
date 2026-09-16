#!/usr/bin/env python3
"""Lesson cross-reference check — every cited lesson must exist, and be cited once.

`PLAYBOOK.md`, the prompts and the skills all cite lessons in prose, as
`LESSONS #NN`. Nothing verified those citations resolved, and the failure that
motivated this check was silent for three days: commit 15d7a03 deleted the
heading line of `## 022.` from an append-only file while leaving its body, which
spliced entry 022's text onto the end of entry 021 and left PLAYBOOK's Phase 5
citation `(LESSONS #22)` pointing at nothing. No harness, and no markdown link
audit, could see it — a `[text](target)` link checker only parses link syntax,
and a prose citation is not a link.

Two properties are checked:

  1. **every `LESSONS #NN` citation resolves** to a `## NNN.` entry heading in
     LESSONS.md — catches a lost, renumbered or never-written entry;
  2. **entry numbers are unique and contiguous from 001** — catches the other
     half of the same accident, where a heading vanishes and its body silently
     joins its predecessor.

Citations wrap across lines in the real files ("(LESSONS\\n  #22)"), so the scan
normalizes whitespace before matching. Leading zeros are optional in a citation
(`#22` and `#022` both resolve to entry 022), because both spellings are already
in the kit.

Usage:  check_lesson_refs.py [KIT_ROOT]   (defaults to the kit this file is in)
        check_lesson_refs.py --self-test
"""
from __future__ import annotations

import os
import re
import sys

# A prose citation. Whitespace is normalized first, so this also matches a
# citation broken across a line, which is exactly how the #22 one was written.
CITE_RE = re.compile(r"LESSONS\s+#(\d{1,3})")
# An entry heading: "## 022. <title>" at the start of a line.
ENTRY_RE = re.compile(r"^## (\d{3})\.", re.M)

SCAN_EXTS = (".md", ".py", ".sh", ".yml", ".yaml", ".toml", ".rs")
SKIP_DIRS = {".git", "target", "node_modules", "__pycache__"}


def entry_numbers(lessons_path):
    text = open(lessons_path, encoding="utf-8").read()
    return [int(n) for n in ENTRY_RE.findall(text)]


def scan_citations(kit_root, lessons_path):
    """Yield (relpath, lineno, number) for each citation outside LESSONS.md itself.

    LESSONS.md is skipped as a *source* of citations: entries legitimately refer
    to each other, and an entry citing a neighbour is not a kit-integrity claim.
    """
    for dirpath, dirnames, filenames in os.walk(kit_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(SCAN_EXTS):
                continue
            path = os.path.join(dirpath, fn)
            if os.path.abspath(path) == os.path.abspath(lessons_path):
                continue
            try:
                text = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if "LESSONS" not in text:
                continue
            # Flatten whitespace so a citation wrapped across lines still
            # matches, keeping a per-character map back to the original line so
            # the reported location is the citation's own, not a guess.
            flat, lines = _flatten(text)
            for m in CITE_RE.finditer(flat):
                yield (os.path.relpath(path, kit_root),
                       lines[m.start()],
                       int(m.group(1)))


def _flatten(text):
    """Collapse whitespace runs to one space; return (flat, line_of_each_char).

    A run of whitespace is emitted as a single space carrying the line number of
    its *first* character, so a citation broken after "LESSONS" is reported on
    the line where it starts.
    """
    out, lines = [], []
    lineno = 1
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            start_line = lineno
            while i < n and text[i].isspace():
                if text[i] == "\n":
                    lineno += 1
                i += 1
            out.append(" ")
            lines.append(start_line)
        else:
            out.append(ch)
            lines.append(lineno)
            i += 1
    return "".join(out), lines


def run(kit_root):
    lessons = os.path.join(kit_root, "LESSONS.md")
    if not os.path.isfile(lessons):
        print(f"FAIL  no LESSONS.md at {lessons}")
        return 1

    nums = entry_numbers(lessons)
    problems = []

    dupes = sorted({n for n in nums if nums.count(n) > 1})
    for n in dupes:
        problems.append(f"LESSONS.md: entry {n:03d} appears {nums.count(n)} times")

    if nums:
        expected = list(range(1, max(nums) + 1))
        for n in expected:
            if n not in nums:
                problems.append(
                    f"LESSONS.md: entry {n:03d} is missing "
                    f"(entries run 001..{max(nums):03d})")

    known = set(nums)
    cited = 0
    for relpath, lineno, num in scan_citations(kit_root, lessons):
        cited += 1
        if num not in known:
            problems.append(
                f"{relpath}:{lineno}: cites LESSONS #{num} — no such entry")

    for p in problems:
        print("PROBLEM:", p)
    print(f"\n{len(nums)} entr(ies), {cited} citation(s), {len(problems)} problem(s)")
    return 1 if problems else 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    entries = "# LESSONS\n\n## 001. a\n\nbody\n\n## 002. b\n\nbody\n"

    with tempfile.TemporaryDirectory() as root:
        open(os.path.join(root, "LESSONS.md"), "w").write(entries)
        open(os.path.join(root, "PLAYBOOK.md"), "w").write(
            "cite (LESSONS #1) and (LESSONS #002).\n")
        check("resolving citations pass", run(root) == 0)

    with tempfile.TemporaryDirectory() as root:
        open(os.path.join(root, "LESSONS.md"), "w").write(entries)
        # the real-world shape: the citation is split across a line break
        open(os.path.join(root, "PLAYBOOK.md"), "w").write(
            "a lesson about releases (LESSONS\n  #22): and the rest.\n")
        check("dangling citation is caught", run(root) == 1)

    with tempfile.TemporaryDirectory() as root:
        # the #22 accident itself: a heading is lost, so 002 vanishes
        open(os.path.join(root, "LESSONS.md"), "w").write(
            "# LESSONS\n\n## 001. a\n\nbody\n\n## 003. c\n\nbody\n")
        open(os.path.join(root, "PLAYBOOK.md"), "w").write("no citations here\n")
        check("missing entry number is caught", run(root) == 1)

    with tempfile.TemporaryDirectory() as root:
        open(os.path.join(root, "LESSONS.md"), "w").write(
            entries + "\n## 002. duplicate\n\nbody\n")
        open(os.path.join(root, "PLAYBOOK.md"), "w").write("no citations here\n")
        check("duplicate entry number is caught", run(root) == 1)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--self-test":
        return _self_test()
    if argv:
        kit_root = argv[0]
    else:
        # harnesses/lessons/ -> harnesses/ -> porting-kit/
        kit_root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
    return run(kit_root)


if __name__ == "__main__":
    sys.exit(main())
