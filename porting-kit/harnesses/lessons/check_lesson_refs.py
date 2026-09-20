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

**A citation is often a list or a range, and reading only its first number is
the same class of bug this file was written to catch.** `LESSONS #6, #8` claims
two entries exist; `LESSONS #6–#10` claims five. The original scan matched
`LESSONS\\s+#(\\d{1,3})` and stopped, so it checked one of them and silently
discarded the rest — 19 of the kit's citations were invisible to it, a quarter
of the 79 it believed it was checking, and it reported `0 problems` on prose
citing an entry that did not exist. Lists
(`,` `/` `&` `and`) and ranges (`-` `–` `—`) are now expanded to the full set of
numbers they claim; see CONT_RE for where the boundary is drawn and why it is
drawn tighter for a range than for a list.

Usage:  check_lesson_refs.py [KIT_ROOT]   (defaults to the kit this file is in)
        check_lesson_refs.py --self-test
"""
from __future__ import annotations

import os
import re
import sys

# The head of a prose citation. Whitespace is normalized first, so this also
# matches a citation broken across a line, which is exactly how the #22 one was
# written.
CITE_RE = re.compile(r"LESSONS\s+#(\d{1,3})")

# One more number tacked onto that citation. A citation in the kit is often a
# LIST or a RANGE, and reading only the head is how this checker reported
# "0 problems" on `(LESSONS #29, #31)` where #31 did not exist:
#
#     LESSONS #6, #8        LESSONS #017, #019, #021      a list
#     LESSONS #9/#13                                      a list, slashed
#     LESSONS #6–#10        LESSONS #017–#021             a RANGE: 6,7,8,9,10
#
# The two branches are deliberately not symmetric about whitespace:
#
#   * a LIST separator may be padded (`#6, #8`), because that is how prose is
#     written;
#   * a RANGE dash may NOT be (`#6–#10`), because this repo writes em-dashes as
#     sentence punctuation everywhere. Were a padded dash a range, the ordinary
#     sentence "LESSONS #26 — #5 says otherwise" would become a backwards range
#     #5..#26 and this gate would fail on correct prose. Every range actually
#     written in the kit is unpadded, so the strict form costs nothing real.
#
# What must NOT continue a citation is a number introduced by a word:
# `LESSONS #19, PR #86` stops at #19, because `PR` is not a separator.
CONT_RE = re.compile(r"(?:\s*([,/&]|and)\s*|([-–—]))#(\d{1,3})")

# A range wider than this is a typo, not a citation. Expanding it would bury the
# real problem under a hundred "no such entry" lines, so it is reported as one.
MAX_RANGE = 50

# An entry heading: "## 022. <title>" at the start of a line.
ENTRY_RE = re.compile(r"^## (\d{3})\.", re.M)

SCAN_EXTS = (".md", ".py", ".sh", ".yml", ".yaml", ".toml", ".rs")
SKIP_DIRS = {".git", "target", "node_modules", "__pycache__"}


def entry_numbers(lessons_path):
    text = open(lessons_path, encoding="utf-8").read()
    return [int(n) for n in ENTRY_RE.findall(text)]


def expand(flat, head):
    """Expand one citation into every entry number it claims.

    Returns (members, errors); each is a list of (offset_into_flat, payload) so
    the caller can report a bad list member on ITS OWN line rather than on the
    line the citation started.
    """
    members = [(head.start(), int(head.group(1)))]
    errors = []
    prev = int(head.group(1))
    pos = head.end()
    while True:
        cont = CONT_RE.match(flat, pos)
        if not cont:
            break
        num, off = int(cont.group(3)), cont.start(3)
        if cont.group(2):                       # a dash: prev..num inclusive
            if num < prev:
                errors.append((off, f"cites LESSONS #{prev}–#{num} — "
                                    f"a range that runs backwards"))
            elif num - prev > MAX_RANGE:
                errors.append((off, f"cites LESSONS #{prev}–#{num} — a range of "
                                    f"{num - prev + 1} entries; that is a typo, "
                                    f"not a citation"))
            else:
                members.extend((off, n) for n in range(prev + 1, num + 1))
        else:                                   # a comma, slash, & or "and"
            members.append((off, num))
        prev = num
        pos = cont.end()
    return members, errors


def scan_citations(kit_root, lessons_path):
    """Yield (relpath, lineno, number, error) per number cited outside LESSONS.md.

    Exactly one of `number` and `error` is set: a citation that parses yields its
    number, a malformed range yields the complaint.

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
            rel = os.path.relpath(path, kit_root)
            for m in CITE_RE.finditer(flat):
                members, errors = expand(flat, m)
                for off, num in members:
                    yield (rel, lines[off], num, None)
                for off, msg in errors:
                    yield (rel, lines[off], None, msg)


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
    for relpath, lineno, num, err in scan_citations(kit_root, lessons):
        if err is not None:
            problems.append(f"{relpath}:{lineno}: {err}")
            continue
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

    # --- citation lists and ranges -------------------------------------------
    # The strings below are the ten multi-number citations that actually appear
    # in this kit, not invented shapes: if the parser handles these it handles
    # the corpus it is deployed against.
    def cited(text):
        flat, _ = _flatten(text)
        out, errs = [], []
        for m in CITE_RE.finditer(flat):
            mem, err = expand(flat, m)
            out.extend(n for _, n in mem)
            errs.extend(msg for _, msg in err)
        return out, errs

    check("comma list reads every member",
          cited("(LESSONS #6, #8)")[0] == [6, 8])
    check("three-member list reads all three",
          cited("(LESSONS #017, #019, #021)")[0] == [17, 19, 21])
    check("slashed pair reads both",
          cited("(LESSONS #9/#13)")[0] == [9, 13])
    check("range expands to every entry it claims",
          cited("(LESSONS #6–#10)")[0] == [6, 7, 8, 9, 10])
    check("range with leading zeros expands",
          cited("(LESSONS #017–#021)")[0] == [17, 18, 19, 20, 21])
    check("ASCII-hyphen range expands",
          cited("(LESSONS #2-#4)")[0] == [2, 3, 4])
    check("'and' joins a citation",
          cited("(LESSONS #6 and #8)")[0] == [6, 8])

    # Both halves of the boundary. A gate that over-reads prose is a gate people
    # route around, so these matter as much as the cases above.
    check("a number introduced by a word does NOT continue the citation",
          cited("(LESSONS #19, PR #86 fixed it)")[0] == [19])
    check("a padded dash is sentence punctuation, not a range",
          cited("LESSONS #26 — #5 says otherwise")[0] == [26])
    check("a following sentence does not continue the citation",
          cited("see LESSONS #19. #86 is a PR")[0] == [19])

    # The next two fixtures are MALFORMED on purpose, and this file is itself
    # part of the corpus the check scans (it is a .py inside the kit). A bad
    # citation written here as a literal would therefore be a genuine finding
    # against the kit: the harness would fail on its own test data. Assembling
    # the keyword at run time keeps the fixture out of the corpus while parsing
    # identically. The VALID fixtures above stay literal on purpose — they
    # resolve, so they cost nothing and remain greppable. (The one in CONT_RE's
    # comment is load-bearing too: were the padded-dash rule wrong, this gate
    # would flag a backwards range in that comment.)
    kw = "LESSONS"
    check("a backwards range is reported, not expanded",
          cited(f"({kw} #9–#2)") == ([9], [f"cites {kw} #9–#2 — "
                                           f"a range that runs backwards"]))
    wide_nums, wide_errs = cited(f"({kw} #1–#900)")
    check("an absurd range is one problem, not 900",
          wide_nums == [1] and len(wide_errs) == 1)

    # End to end: the exact failure that motivated this change. Before it, this
    # ran clean.
    with tempfile.TemporaryDirectory() as root:
        open(os.path.join(root, "LESSONS.md"), "w").write(entries)
        open(os.path.join(root, "PLAYBOOK.md"), "w").write(
            "both exist (LESSONS #1, #2).\n")
        check("list whose members all exist passes", run(root) == 0)

    with tempfile.TemporaryDirectory() as root:
        open(os.path.join(root, "LESSONS.md"), "w").write(entries)
        open(os.path.join(root, "PLAYBOOK.md"), "w").write(
            "the #29/#31 shape (LESSONS #1, #22).\n")
        check("dangling SECOND member of a list is caught", run(root) == 1)

    with tempfile.TemporaryDirectory() as root:
        open(os.path.join(root, "LESSONS.md"), "w").write(entries)
        open(os.path.join(root, "PLAYBOOK.md"), "w").write(
            "a range reaching past the last entry (LESSONS #1–#5).\n")
        check("range member past the last entry is caught", run(root) == 1)

    with tempfile.TemporaryDirectory() as root:
        open(os.path.join(root, "LESSONS.md"), "w").write(entries)
        open(os.path.join(root, "PLAYBOOK.md"), "w").write(
            "citing a PR alongside a lesson (LESSONS #1, PR #904).\n")
        check("PR number beside a citation does not fail the gate",
              run(root) == 0)

    # A dangling member must be reported on ITS OWN line, not the citation's.
    with tempfile.TemporaryDirectory() as root:
        open(os.path.join(root, "LESSONS.md"), "w").write(entries)
        open(os.path.join(root, "PLAYBOOK.md"), "w").write(
            "line one\nline two\na wrapped list (LESSONS #1,\n  #22).\n")
        hits = [(ln, n) for _, ln, n, _ in
                scan_citations(root, os.path.join(root, "LESSONS.md"))]
        check("a wrapped list member is reported on its own line",
              (3, 1) in hits and (4, 22) in hits)

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
