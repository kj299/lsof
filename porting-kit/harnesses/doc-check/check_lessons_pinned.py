#!/usr/bin/env python3
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Re-cited: #6->#036, #13->#033, #14->#037, #18->#039, #19->#040;
#          #26 by title (no entry in this log).
# Local: #058 (this kit's own first run of it).
"""Lessons-pinned check — the smoke tests must track the lessons. Every LESSONS
entry that amends kit CODE (a harness, a workflow, an example runner) must be
cited in that file — and the kit's convention is that the citation sits next to
the self-test check that PINS the lesson, so `make check-kit` is the lessons'
regression suite.

Why (LESSONS #033): a lesson recorded in LESSONS.md is history, not a control —
two logged lessons recurred in code written after them. The one thing that makes
a lesson durable is a pinned check in a harness self-test. This gate makes the
LESSONS↔smoke-test linkage mechanical in both directions:
  * a NEW lesson claiming `Section amended: harnesses/foo.py` fails check-kit
    until foo.py actually cites `LESSONS #N` (added, by convention, at the
    pinned check / the changed logic);
  * a REWRITE of foo.py that drops the lesson's citation (usually by deleting
    the pinned logic) fails check-kit until the lesson is re-pinned.

Mechanics (conservative, format-driven):
  * Parse LESSONS.md entries (`## NNN. <title>`) and each entry's
    `- **Section amended:**` field (the format's required final field).
  * From that field, extract kit CODE paths: `harnesses/`, `skills/`,
    `skeleton/`, `examples/`, `ports/`, or `.github/` files ending in
    .py/.sh/.yml.
    Prose, doc (.md), and bare-basename mentions are not obligations.
  * For each such path that still exists, require a line containing `LESSONS`
    and the token `#<n>` (e.g. `(LESSONS #036)`), any leading zeros ignored.
  * A path that no longer exists is skipped with a note: LESSONS is append-only
    history, and history is allowed to age across renames.

**A `Section amended` path is resolved against `--also-scan` roots too**, and
that is not a convenience. A vendored kit sits at `porting-kit/` inside its host
repo, and the paths lessons amend most often after the harnesses themselves are
`.github/workflows/*.yml` — which live in the HOST, one level up. Resolving only
against KIT_ROOT, this gate found six such paths missing and filed them under
"aged path(s) skipped" — a phrase that reads like benign history. All six were
live files; four of the six were genuinely unpinned. **A skip counter is a place
a gate hides** (LESSONS #058), and this is LESSONS #033 in a second harness: a
claim written outside the kit is the same claim, and the walk has to reach it.
`aged` and `resolved outside the kit` are reported separately for that reason —
one number covering both is how the four stayed invisible.

Usage:  check_lessons_pinned.py [KIT_ROOT] [--also-scan DIR]...
            KIT_ROOT defaults to this file's ../../. --also-scan may repeat; a
            path is tried against KIT_ROOT first, then each extra root in turn.
        check_lessons_pinned.py --self-test
Exit: 0 = every amended code file cites its lesson; 1 = a lesson is unpinned.
"""
from __future__ import annotations

import os
import re
import sys

ENTRY_RE = re.compile(r"(?m)^## (\d{3})\. ")
# An IMPORTED entry's amendments happened in the lineage it came from, not here:
# its `Section amended` names that kit's files, several of which do not exist in
# this one. Attributing them locally would be a false claim, so such an entry
# writes `- **Section amended (source lineage):**` instead.
#
# That variant used to be exempt by ACCIDENT — AMENDED_RE matches the plain field
# exactly, so the parenthesised one was simply never seen, and anyone could
# silence this gate by renaming the field. It is a designed exemption now:
# counted, reported, and allowed ONLY on an entry that carries `Imported:`. A
# native lesson may not attribute its own amendments somewhere else.
IMPORTED_RE = re.compile(r"^\s*-\s+\*\*Imported:\*\*", re.M)
AMENDED_ELSEWHERE_RE = re.compile(
    r"- \*\*Section amended \(source lineage\):\*\*(.*?)(?=^-\s\*\*|^##\s|\Z)",
    re.S | re.M)

AMENDED_RE = re.compile(r"- \*\*Section amended:\*\*(.*?)(?=^-\s\*\*|^##\s|\Z)",
                        re.S | re.M)
# `ports/` is in the list because a real port's own gate scripts and corpus
# generators ARE kit code a lesson can amend — the cJSON retrospective found
# LESSONS #040 naming `ports/cjson/oracle/gen_corpus.py` and this gate silently
# ignoring it, because the prefix list predated the existence of `ports/`. A
# path this regex doesn't recognize is checked by nothing and reports nothing:
# the same not-looking-at-it failure as a 0-of-0 audit (LESSONS #039).
# `.rs`/`.c`/`.h` joined the extension list with the source lineage's "a gate
# judges only the surface the driver exposes", which has no entry here: a lesson can amend
# a port's Rust or its C driver directly (module 8's fix lives in dom.rs), and
# until then those links were silently unenforced — the extension-list twin of
# the prefix-list gap above.
CODE_PATH_RE = re.compile(
    r"(?:harnesses|skills|skeleton|examples|ports|\.github)/[A-Za-z0-9_./-]+"
    r"\.(?:py|sh|yml|rs|c|h)\b")


def parse_lessons(text):
    """Yield (lesson_number, entry_body) for each `## NNN.` entry."""
    marks = [(m.start(), int(m.group(1))) for m in ENTRY_RE.finditer(text)]
    for i, (pos, num) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        yield num, text[pos:end]


def amended_code_paths(entry_body):
    """Code paths named in the entry's `Section amended:` field (deduped).

    A long `Section amended` list is markdown-wrapped, and a wrap can fall
    mid-path right after a `/` (`harnesses/cando/\\n  cando_diff.py`). Left as-is
    the extractor matches neither half and SILENTLY skips that file — a fail-open
    in the very gate that enforces fail-closed pinning (LESSONS #037, a #036
    recurrence). Rejoin any whitespace that immediately follows a `/` before
    extracting, so a wrapped path is checked, not dropped."""
    paths = []
    for m in AMENDED_RE.finditer(entry_body):
        paths.extend(_paths_in(m.group(1)))
    return list(dict.fromkeys(paths))


def _paths_in(field):
    """Code paths in one `Section amended` field, with wrapped paths rejoined."""
    return CODE_PATH_RE.findall(re.sub(r"/\s+", "/", field))


def cites(file_text, n):
    """True if some line mentions LESSONS together with the token #<n>."""
    tok = re.compile(rf"#0*{n}\b")
    return any("LESSONS" in line and tok.search(line)
               for line in file_text.splitlines())


def resolve(roots, rel):
    """(full path, root it was found under) for `rel`, or (None, None).

    Tried against each root in order, KIT_ROOT first — so a host-repo file a
    lesson amends (`.github/workflows/…`) resolves instead of being written off
    as aged, while a kit file still wins over a same-named host file."""
    for r in roots:
        full = os.path.join(r, rel)
        if os.path.exists(full):
            return full, r
    return None, None


def run(kit_root, also=()):
    lessons_path = os.path.join(kit_root, "LESSONS.md")
    if not os.path.isfile(lessons_path):
        print(f"error: no LESSONS.md at {kit_root}", file=sys.stderr)
        return 1
    # A mistyped --also-scan must not look like a clean run: it would silently
    # restore the fail-open the flag exists to close (LESSONS #033's own rule).
    for d in also:
        if not os.path.isdir(d):
            print(f"FAIL  --also-scan {d}: no such directory")
            return 1
    roots = [kit_root, *also]
    text = open(lessons_path, encoding="utf-8").read()
    problems, checked, aged, elsewhere, outside = [], 0, 0, 0, 0
    for num, body in parse_lessons(text):
        m = AMENDED_ELSEWHERE_RE.search(body)
        if m:
            if not IMPORTED_RE.search(body):
                problems.append(
                    f"LESSONS #{num} uses `Section amended (source lineage)` but is "
                    f"not an imported entry — a native lesson's amendments happened "
                    f"HERE, and attributing them elsewhere silences this gate")
            else:
                elsewhere += len([x for x in _paths_in(m.group(1))])
        for rel in amended_code_paths(body):
            full, found_in = resolve(roots, rel)
            if full is None:
                aged += 1  # append-only history is allowed to age past renames
                continue
            if found_in != kit_root:
                outside += 1
            checked += 1
            if not cites(open(full, encoding="utf-8").read(), num):
                problems.append(
                    f"LESSONS #{num} amends {rel}, but {rel} does not cite "
                    f"`LESSONS #{num}` — re-pin the lesson (cite it at the "
                    f"self-test check / changed logic)")
    for p in problems:
        print("UNPINNED: " + p)
    note = f" ({aged} aged path(s) skipped)" if aged else ""
    if outside:
        note += f", {outside} resolved outside the kit"
    if elsewhere:
        note += f", {elsewhere} attributed to the source lineage"
    print(f"{checked} lesson→code link(s) checked, {len(problems)} unpinned{note}")
    return 1 if problems else 0


def _self_test():
    # Fixture lesson numbers, assembled rather than written literally. They are
    # test DATA — a fake log with a fake entry citing a fake file — not claims
    # about THIS log, and `check_lesson_refs`/`check_imports` scan this file, so
    # a literal citation here would read as a claim either way it lands. (The
    # first draft of this very comment used one as its example and tripped
    # the check it was describing.)
    F7, F8, F11, F12, F13, F14 = "7", "8", "11", "12", "13", "14"
    # Assembled WHOLE, digits and all: an earlier draft wrote `#0{F15}`, which
    # leaves the literal `#0` in this file's source and reads to the citation
    # scanner as a claim that entry 0 exists. Leave no digit of a fixture
    # number in the source text.
    F15 = "0" + "1" + "5"

    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "harnesses", "x"))
        good = os.path.join(root, "harnesses", "x", "good.py")
        open(good, "w").write(f"# pinned here (LESSONS #{F7})\ncheck('...')\n")
        open(os.path.join(root, "LESSONS.md"), "w").write(
            "## 007. a lesson\n- **What happened:** ...\n"
            "- **Kit change:** ...\n"
            "- **Section amended:** harnesses/x/good.py (self-test); PLAYBOOK · X.\n")
        check("cited lesson→harness link passes", run(root) == 0)

        # a second lesson amends a file that does NOT cite it → fail
        bad = os.path.join(root, "harnesses", "x", "bad.sh")
        open(bad, "w").write("#!/bin/sh\necho no citation here\n")
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 008. another\n- **Section amended:** harnesses/x/bad.sh.\n")
        check("uncited lesson→harness link is caught", run(root) == 1)

        # citing the WRONG number must not satisfy the link
        open(bad, "w").write(f"#!/bin/sh\n# (LESSONS #{F7}) wrong entry\n")
        check("citing a different lesson number still fails", run(root) == 1)
        open(bad, "w").write(f"#!/bin/sh\n# pinned (LESSONS #{F8})\n")
        check("correct citation clears it", run(root) == 0)

        # a renamed/removed path is aged history, not a failure (append-only)
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 009. old\n- **Section amended:** harnesses/gone/renamed.py.\n")
        check("an amended path that no longer exists is skipped", run(root) == 0)

        # prose/doc mentions outside `Section amended` create no obligation
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 010. prose\n- **What happened:** touched harnesses/x/bad.sh\n"
                    "- **Section amended:** PLAYBOOK · Phase 2 only.\n")
        check("prose mentions outside Section-amended are ignored", run(root) == 0)

        # LESSONS #039/#040: a prefix the extractor doesn't know is checked by
        # NOTHING — `ports/` was missing until a real port's lesson named a file
        # there and the gate silently ignored it.
        os.makedirs(os.path.join(root, "ports", "p"))
        pf = os.path.join(root, "ports", "p", "gate.sh")
        open(pf, "w").write("#!/bin/sh\necho no citation\n")
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 012. ports path\n- **Section amended:** ports/p/gate.sh.\n")
        check("a ports/ path is checked like any other kit code", run(root) == 1)
        open(pf, "w").write(f"#!/bin/sh\n# pinned (LESSONS #{F12})\n")
        check("citing it clears the ports/ link", run(root) == 0)

        # LESSONS #037: a path a markdown line-wrap split after a `/` must still be
        # extracted and enforced — else the gate silently skips it (fail-open).
        wrapped = os.path.join(root, "harnesses", "x", "wrapped.py")
        open(wrapped, "w").write("#!/usr/bin/env python3\nprint('no citation')\n")
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 011. wrapped path\n- **Section amended:** harnesses/x/\n"
                    "  wrapped.py (the changed logic).\n")
        check("a line-wrapped amended path is still checked (not skipped)", run(root) == 1)
        open(wrapped, "w").write(f"#!/usr/bin/env python3\n# pinned (LESSONS #{F11})\n")
        check("citing it clears the wrapped-path link", run(root) == 0)

        # The source lineage's "a gate judges only the surface the driver
        # exposes" (no entry here): a lesson can amend a port's RUST or C source —
        # an extension the regex doesn't know is the extension-list twin of the
        # ports/ prefix gap: named, checked by nothing, reported as nothing.
        rs = os.path.join(root, "ports", "p", "dom.rs")
        open(rs, "w").write("// no citation yet\n")
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 013. rust path\n- **Section amended:** ports/p/dom.rs.\n")
        check("a .rs amended path is checked like any other kit code",
              run(root) == 1)
        open(rs, "w").write(f"// pinned (LESSONS #{F13})\n")
        check("citing it clears the .rs link", run(root) == 0)
        cfile = os.path.join(root, "ports", "p", "driver.c")
        open(cfile, "w").write("/* no citation */\n")
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 014. c path\n- **Section amended:** ports/p/driver.c.\n")
        check("a .c amended path is checked too", run(root) == 1)
        open(cfile, "w").write(f"/* pinned (LESSONS #{F14}) */\n")
        check("citing it clears the .c link", run(root) == 0)

        # LESSONS #033, a second time and in a second harness: the kit is
        # VENDORED, so the workflows a lesson amends live in the HOST repo. A
        # path resolved only against KIT_ROOT is filed as "aged" — and six of
        # this log's were, all six live files, four of them genuinely unpinned.
        # Pinned in both directions: without --also-scan the host file is
        # silently skipped (still true, and the reason the flag must be wired),
        # with it the uncited link FAILS.
        with tempfile.TemporaryDirectory() as hostdir:
            os.makedirs(os.path.join(hostdir, ".github", "workflows"))
            wf = os.path.join(hostdir, ".github", "workflows", "ci.yml")
            open(wf, "w").write("name: ci\njobs: {}\n")
            with open(os.path.join(root, "LESSONS.md"), "a") as f:
                f.write(f"\n## {F15}. host workflow\n"
                        "- **Section amended:** .github/workflows/ci.yml.\n")
            check("a host-repo path is SKIPPED without --also-scan (the fail-open)",
                  run(root) == 0)
            check("--also-scan reaches it, and an uncited host file fails",
                  run(root, [hostdir]) == 1)
            open(wf, "w").write(f"name: ci\n# pinned (LESSONS #{F15})\njobs: {{}}\n")
            check("citing it in the host file clears the link",
                  run(root, [hostdir]) == 0)
            # a mistyped root must be loud, not a silent return to the fail-open
            check("a mistyped --also-scan fails rather than scanning nothing",
                  run(root, [os.path.join(hostdir, "no-such-dir")]) == 1)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--self-test":
        return _self_test()
    here = os.path.dirname(os.path.abspath(__file__))
    kit_root, also, i = None, [], 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--also-scan":
            i += 1
            if i >= len(argv):
                print("FAIL  --also-scan needs a directory")
                return 1
            also.append(argv[i])
        elif arg.startswith("--also-scan="):
            also.append(arg.split("=", 1)[1])
        elif arg.startswith("-"):
            print(f"FAIL  unknown option {arg}")
            return 1
        elif kit_root is None:
            kit_root = arg
        else:
            print(f"FAIL  unexpected argument {arg} (one KIT_ROOT only; "
                  f"use --also-scan for extra roots)")
            return 1
        i += 1
    if kit_root is None:
        kit_root = os.path.dirname(os.path.dirname(here))
    return run(kit_root, also)


if __name__ == "__main__":
    sys.exit(main())
