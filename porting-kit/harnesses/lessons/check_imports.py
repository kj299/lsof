#!/usr/bin/env python3
"""Imported-lesson integrity — a re-cited cross-reference must name what it cites.

This kit's LESSONS.md is append-only, and so is the one in every sibling lineage
it was forked into. That makes the logs **collide**: they share a prefix and then
diverge, so the same number means a different lesson on each side. Importing an
entry across lineages therefore requires rewriting every `#N` inside its body to
this log's numbering — and a number that is merely *wrong* still resolves, so
`check_lesson_refs.py` passes it. That check answers "does #14 exist?"; the
question here is "is #14 the lesson this sentence means?", which no amount of
looking at the destination log alone can answer.

It was not hypothetical. The first import into this log carried
`(LESSONS #036/#14/#18/#20)`: the head was re-cited and the three continuation
members were not, so the sentence silently pointed at three unrelated entries and
every gate stayed green. Two more entries carried a bare `#8` and `#6` from the
source lineage.

The fix travels with the import. An imported entry records what each source
citation was re-cited TO, **and the title it had** — so the claim is checkable
here, offline, without the source log:

    ## 043. Some lesson

    - **Imported:** from the c2rust-port lineage of this kit, where it is #008.
    - **Re-cited:** source #6 -> #036 "Gates fail open on \"nothing ran\"";
      source #15 -> by title "An inherited environment constraint is a dated
      observation, not a fact"

This checker then enforces two things per imported entry:

  1. **Resolution.** Every re-cited destination `#NNN` exists, and its heading
     title matches the title the import recorded. A re-cite to the wrong entry
     fails here even though the number resolves.
  2. **Completeness.** Every lesson cross-reference in the body is accounted for
     — either re-cited above, or the entry's own number. A number carried over
     verbatim from the source lineage is exactly what this catches, and it is the
     failure that motivated the file.

A `by title` mapping is the escape hatch for a source lesson with no counterpart
here: it asserts there is no local number, so no number is invented.

## Imported FILES, not just imported entries

A harness or skill brought across from a sibling lineage has the same hazard and
no heading to hang a mapping on, so it carries a one-line marker instead:

    # KIT-IMPORT: from the c2rust-port lineage.
    # Re-cited: #1->#001, #4->#004, #6->#036, #8->#043; #36 by title.

Every `LESSONS #N` in that file — expanded through the same list/range rules
`check_lesson_refs` uses, so `#036, #14` and `#001/#6` are seen as TWO citations
each — must land in that marker's destination set. That expansion is the point:
the two survivors found while porting `diff-fuzz` were both continuation members
(`LESSONS #036, #14` and `LESSONS #001/#6`), invisible to a `LESSONS #14` grep
and green under every existing check, because #14 and #6 do exist here.

Usage:  check_imports.py [LESSONS.md]     (default: the kit this file is in)
        check_imports.py --self-test

Exit: 0 = every imported entry's re-citations resolve and are complete, and every
      KIT-IMPORT file's citations land in its declared destination set.
"""
from __future__ import annotations

import os
import re
import sys

ENTRY_RE = re.compile(r"^## (\d{3})\.\s*(.+?)\s*$", re.M)
IMPORTED_RE = re.compile(r"^\s*-\s+\*\*Imported:\*\*", re.M)
RECITED_RE = re.compile(r"^\s*-\s+\*\*Re-cited:\*\*", re.M)

# One mapping: `source #6 -> #034 "Title"` or `source #15 -> by title "Title"`.
# The arrow is ASCII `->` so it survives every editor and diff tool; the title is
# quoted so it may contain commas, dashes and the log's own `#`.
#
# BOTH quote styles are accepted, and that is not politeness. A lesson title in
# this log may itself contain a straight-quoted phrase (#036 quotes "nothing
# ran"), so a straight-quoted mapping would end at the title's own quote and the
# mapping would not parse. Curly quotes are the way to write those. The first cut
# of this file required a straight pair and its self-test obligingly used one —
# green here, unparseable against every real entry. A fixture written in a form
# the real data does not use measures the fixture.
MAP_RE = re.compile(
    r"source\s+#(\d{1,3})\s*->\s*(?:#(\d{1,3})|by\s+title)\s*"
    r"(?:“(?P<curly>[^”]+)”|\"(?P<straight>[^\"]+)\")")

# A lesson cross-reference in an entry BODY. Two shapes appear in this log:
# `LESSONS #14` and the bare in-log shorthand `#14` ("distinct from #8"). The
# bare form is the one that slipped through, so it must be matched — but `#` is
# also how this log writes PR, issue, run and item numbers, and those are not
# lesson citations. NEG_PREFIX_RE names the words that make a `#N` something
# else; anything else preceding a bare `#N` is read as a lesson reference.
XREF_RE = re.compile(r"(?:LESSONS\s+)?#(\d{1,3})\b")
NEG_PREFIX_RE = re.compile(
    r"(?:PR|PRs|issue|issues|run|runs|item|items|step|steps|§|section|CWE|"
    r"C17|phase|L)\s*$", re.I)

# Words that end a citation but not a list: `#6, #8` continues, `#19, PR #86`
# does not. Reused from check_lesson_refs's boundary rule so the two agree.
SKIP_DIRS = {".git", "target", "node_modules", "__pycache__"}


def parse_entries(text):
    """[(number, title, body)] for every `## NNN. Title` entry, in file order."""
    out = []
    hits = list(ENTRY_RE.finditer(text))
    for i, m in enumerate(hits):
        end = hits[i + 1].start() if i + 1 < len(hits) else len(text)
        out.append((int(m.group(1)), m.group(2), text[m.end():end]))
    return out


def normalize_title(t):
    """Compare titles by their words, not their punctuation. A log renders the
    same title with an em dash here and a hyphen there, and curly quotes arrive
    from anywhere; none of that changes which lesson is meant, and failing on it
    would train the reader to edit the assertion rather than the citation."""
    t = t.replace("—", " ").replace("–", " ").replace("-", " ")
    t = t.replace("“", '"').replace("”", '"')
    t = t.replace("‘", "'").replace("’", "'")
    t = re.sub(r"[^0-9a-z]+", " ", t.lower())
    return " ".join(t.split())


def recited_block(body):
    """The text of the `- **Re-cited:**` bullet, or None. The bullet wraps across
    lines in the real file, so it runs to the next top-level `- **` bullet."""
    m = RECITED_RE.search(body)
    if not m:
        return None
    rest = body[m.end():]
    nxt = re.search(r"^\s*-\s+\*\*", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def strip_meta(body):
    """The entry body with its `Imported`/`Re-cited` bullets removed — the prose
    whose cross-references must be accounted for. The mapping bullet cites both
    sides by construction, so scanning it would make every entry self-approving."""
    out, m = body, IMPORTED_RE.search(body)
    for blk in (recited_block(body),):
        if blk:
            out = out.replace(blk, " ")
    if m:
        rest = body[m.end():]
        nxt = re.search(r"^\s*-\s+\*\*", rest, re.M)
        out = out.replace(body[m.start(): m.end() + (nxt.start() if nxt else len(rest))], " ")
    return out


def body_xrefs(text):
    """Lesson numbers cross-referenced in prose, as {number: [offsets]}. Skips a
    `#N` that a preceding word marks as a PR/issue/run/item number."""
    found = {}
    for m in XREF_RE.finditer(text):
        if NEG_PREFIX_RE.search(text[max(0, m.start() - 12): m.start()]):
            continue
        found.setdefault(int(m.group(1)), []).append(m.start())
    return found


def check(lessons_path):
    text = open(lessons_path, encoding="utf-8").read()
    entries = parse_entries(text)
    titles = {n: t for n, t, _ in entries}
    problems, imported = [], 0

    for num, _title, body in entries:
        if not IMPORTED_RE.search(body):
            continue
        imported += 1
        blk = recited_block(body)
        prose = strip_meta(body)
        refs = body_xrefs(prose)
        # The entry's own number is not a cross-reference.
        refs.pop(num, None)

        if blk is None:
            if refs:
                problems.append(
                    f"#{num:03d}: imported, cross-references "
                    f"{', '.join('#%d' % r for r in sorted(refs))}, but has no "
                    f"`- **Re-cited:**` bullet. An imported entry's numbers came "
                    f"from the SOURCE log, where they mean different lessons; "
                    f"record what each was re-cited to.")
            continue

        mapped, mapped_dests = {}, set()
        for m in MAP_RE.finditer(blk):
            src = int(m.group(1))
            dest = int(m.group(2)) if m.group(2) else None
            mapped[src] = (dest, m.group("curly") or m.group("straight"))
            if dest is not None:
                mapped_dests.add(dest)

        if not mapped:
            problems.append(
                f"#{num:03d}: has a `Re-cited` bullet with no parseable mapping. "
                f"Each one reads `source #N -> #MMM \"Title\"` or "
                f"`source #N -> by title \"Title\"`.")
            continue

        # (1) resolution — the destination exists and IS the lesson named.
        for src, (dest, title) in sorted(mapped.items()):
            if dest is None:
                if normalize_title(title) in {normalize_title(t) for t in titles.values()}:
                    problems.append(
                        f"#{num:03d}: source #{src} is mapped `by title` "
                        f"({title!r}) but an entry with that title EXISTS here — "
                        f"cite it by number.")
                continue
            if dest not in titles:
                problems.append(
                    f"#{num:03d}: source #{src} re-cited to #{dest:03d}, which is "
                    f"not an entry in this log.")
            elif normalize_title(titles[dest]) != normalize_title(title):
                problems.append(
                    f"#{num:03d}: source #{src} re-cited to #{dest:03d}, but "
                    f"#{dest:03d} is {titles[dest]!r}, not {title!r}. The number "
                    f"resolves and still points at the wrong lesson — which is "
                    f"the whole failure mode this check exists for.")

        # (2) completeness — no body number escaped the mapping.
        for ref in sorted(refs):
            if ref not in mapped_dests:
                problems.append(
                    f"#{num:03d}: body cross-references #{ref} but no `Re-cited` "
                    f"mapping lands there. Either it was carried over from the "
                    f"source lineage unchanged (where #{ref} is a different "
                    f"lesson), or the mapping is missing. Re-cite it.")

    return imported, problems


# ---------------------------------------------------------------------------
# Imported FILES (harnesses, skills) — the same hazard, no heading to hang a
# mapping on, so the mapping is a marker comment in the file itself.

# A real marker is a FILE HEADER: it sits above the module docstring in a .py
# and just under the frontmatter in a skill's .md, so 20 lines covers both with
# room to spare. Matching it anywhere would make THIS file mark itself on its own
# documentation and fixtures (it did, 16 times), and would let a passing mention
# in prose conscript an unrelated file into the check.
#
# The marker must also OPEN its line, after nothing but a comment or markup
# opener. Prose that merely names it does not mark a file — which is not a
# hypothetical either: the README gained a sentence explaining `KIT-IMPORT:` in
# its banner and was immediately counted as an imported file.
MARKER_RE = re.compile(r"^\s*(?:#+|//+|<!--|--|;+|\*)?\s*KIT-IMPORT:")
MARKER_HEAD_LINES = 20
# The mapping is read from the marker's own block — its line plus the few that
# continue it — so a `#6->#034` written anywhere else in the file cannot widen
# the declared destination set and quietly bless a carried-over citation.
MARKER_BLOCK_LINES = 5
# `#1->#001` / `#1 -> #001`, and `#36 by title` for a source lesson with no
# counterpart here. The destinations are what every citation in the file must
# land in.
FILEMAP_RE = re.compile(r"#(\d{1,3})\s*->\s*#(\d{1,3})")
FILETITLE_RE = re.compile(r"#(\d{1,3})\s+by\s+title")
# An imported file may later cite a lesson this log wrote ITSELF — one with no
# source-lineage counterpart, so nothing to re-cite FROM. Those are declared
# `Local: #052, #054` in the marker block. Without this an imported harness could
# never cite a native lesson, which would either block the citation or push the
# marker off the file; both are worse than naming them.
FILELOCAL_RE = re.compile(r"Local:\s*((?:#\d{1,3}[,\s]*)+)")


def _expand_citations(text):
    """Every lesson number a file's `LESSONS #N` citations claim, as
    [(offset, number)] — expanded through check_lesson_refs's own list/range
    rules so `#034, #14` and `#001/#6` yield BOTH members, not just the head.
    Sharing that expansion is the point: a continuation member is exactly what
    slipped through here, twice."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import check_lesson_refs as C  # noqa: E402
    # The checker's own flatten, not a bare whitespace collapse: a member that
    # continues on the next COMMENT line (`# (LESSONS #034,` / `# #14)`) has the
    # marker between separator and member, and a whitespace collapse leaves it
    # there — the member is never read (LESSONS #057).
    flat, _offsets = C._flatten_map(text)
    out = []
    for head in C.CITE_RE.finditer(flat):
        members, _errs = C.expand(flat, head)
        out.extend(members)
    return out


def check_files(kit_root, lessons_path):
    """Check every KIT-IMPORT-marked file under kit_root. Returns (n, problems)."""
    entry_nums = {n for n, _t, _b in parse_entries(
        open(lessons_path, encoding="utf-8").read())}
    problems, n_files = [], 0
    for dirpath, dirnames, filenames in os.walk(kit_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if not fn.endswith((".py", ".md", ".sh", ".yml", ".yaml", ".toml")):
                continue
            path = os.path.join(dirpath, fn)
            try:
                text = open(path, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            lines = text.split("\n")
            marked = next((i for i, ln in enumerate(lines[:MARKER_HEAD_LINES])
                           if MARKER_RE.search(ln)), None)
            if marked is None:
                continue
            n_files += 1
            rel = os.path.relpath(path, kit_root)
            block = "\n".join(lines[marked: marked + MARKER_BLOCK_LINES])
            dests = {int(b) for _a, b in FILEMAP_RE.findall(block)}
            by_title = {int(a) for a in FILETITLE_RE.findall(block)}
            local = {int(n) for grp in FILELOCAL_RE.findall(block)
                     for n in re.findall(r"#(\d{1,3})", grp)}
            for n in sorted(local):
                if n not in entry_nums:
                    problems.append(
                        f"{rel}: KIT-IMPORT declares #{n:03d} as a local lesson, "
                        f"but there is no such entry in LESSONS.md.")
            dests |= local
            for d in sorted(dests):
                if d not in entry_nums:
                    problems.append(
                        f"{rel}: KIT-IMPORT maps a source citation to #{d:03d}, "
                        f"which is not an entry in LESSONS.md.")
            cites = _expand_citations(text)
            if not dests and not by_title and cites:
                problems.append(
                    f"{rel}: marked KIT-IMPORT and cites "
                    f"{', '.join('#%d' % n for _o, n in cites)}, but declares no "
                    f"`Re-cited:` mapping. Its numbers came from the source "
                    f"lineage, where they mean different lessons.")
                continue
            for _off, num in cites:
                if num not in dests:
                    problems.append(
                        f"{rel}: cites LESSONS #{num} — not a destination of this "
                        f"file's KIT-IMPORT mapping. Either it was carried over "
                        f"from the source lineage (where #{num} is a different "
                        f"lesson), or the mapping is missing it. Continuation "
                        f"members count: `#034, #14` and `#001/#6` are two "
                        f"citations each.")
    return n_files, problems


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--self-test" in argv:
        return _self_test()
    # .../porting-kit/harnesses/lessons/check_imports.py -> .../porting-kit
    kit = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = argv[0] if argv else os.path.join(kit, "LESSONS.md")
    if not os.path.exists(path):
        sys.exit(f"error: no LESSONS.md at {path}")
    imported, problems = check(path)
    n_files, file_problems = check_files(kit, path)
    problems += file_problems
    for p in problems:
        print("PROBLEM  " + p)
    print(f"{imported} imported entr(ies), {n_files} KIT-IMPORT file(s), "
          f"{len(problems)} problem(s)")
    if not imported and not n_files:
        # Nothing imported is a legitimate state for a kit that never forked —
        # but say so, rather than printing a green line that reads like a pass
        # over entries that were checked. (A gate with nothing to check is not a
        # passing gate; this one reports which it is.)
        print("note: nothing marked `Imported` or `KIT-IMPORT` — nothing to re-cite.")
    return 1 if problems else 0


def _self_test():
    ok = True

    def chk(name, cond):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name)
        ok = ok and cond

    import tempfile

    def run(md):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "LESSONS.md")
            open(p, "w", encoding="utf-8").write(md)
            return check(p)

    base = (
        "## 004. Differential fidelity is stdout AND exit code, not stdout alone\n\n"
        "- body\n\n---\n\n"
        "## 034. Gates fail open on nothing ran\n\n- body\n\n---\n\n"
    )

    # A clean import: mapping resolves, titles agree, no stray numbers.
    good = base + (
        "## 041. An acceptance list that matches by name becomes a mute button\n\n"
        "- **Imported:** from the c2rust-port lineage, where it is #008.\n"
        "- **Re-cited:** source #6 -> #034 \"Gates fail open on nothing ran\"\n"
        "- **What happened:** recurrences of #034 (fail-closed) were fixed.\n\n---\n")
    n, probs = run(good)
    chk("a complete, correct import passes", (n, probs) == (1, []))

    # THE motivating bug: head re-cited, continuation members carried over.
    stale = base + (
        "## 041. Something\n\n"
        "- **Imported:** from the c2rust-port lineage, where it is #008.\n"
        "- **Re-cited:** source #6 -> #034 \"Gates fail open on nothing ran\"\n"
        "- **What happened:** displaced one level up (LESSONS #034/#14/#18).\n\n---\n")
    n, probs = run(stale)
    chk("an un-re-cited continuation member (#034/#14/#18) is caught",
        len(probs) == 2 and any("#14" in p for p in probs)
        and any("#18" in p for p in probs))

    # A bare in-log shorthand reference, the other shape that slipped through.
    bare = base + (
        "## 041. Something\n\n"
        "- **Imported:** from the c2rust-port lineage, where it is #008.\n"
        "- **Re-cited:** source #6 -> #034 \"Gates fail open on nothing ran\"\n"
        "- **What happened:** This is distinct from #8, which pins a change.\n\n---\n")
    n, probs = run(bare)
    chk("a BARE `#8` shorthand is caught, not just `LESSONS #8`",
        any("#8" in p for p in probs))

    # Wrong destination: the number resolves, the lesson is not the one named.
    wrong = base + (
        "## 041. Something\n\n"
        "- **Imported:** from the c2rust-port lineage, where it is #008.\n"
        "- **Re-cited:** source #6 -> #004 \"Gates fail open on nothing ran\"\n"
        "- **What happened:** see #004.\n\n---\n")
    n, probs = run(wrong)
    chk("a re-cite to an existing but WRONG entry fails on the title",
        any("not 'Gates fail open on nothing ran'" in p.replace('"', "'")
            or "is not" in p or "not " in p for p in probs) and len(probs) >= 1)

    # Title mismatch must be the reason, not a missing number.
    chk("…and it says the destination is the wrong lesson",
        any("the wrong lesson" in p for p in probs))

    # PR/issue/item numbers are not lesson citations.
    noise = base + (
        "## 041. Something\n\n"
        "- **Imported:** from the c2rust-port lineage, where it is #008.\n"
        "- **Re-cited:** source #6 -> #034 \"Gates fail open on nothing ran\"\n"
        "- **What happened:** fixed in PR #3, tracked as issue #77, §6 item 8.\n\n---\n")
    n, probs = run(noise)
    chk("PR/issue/section numbers are not read as lesson citations", probs == [])

    # `by title` asserts there is no local number — so it must be false that one
    # exists, or the escape hatch becomes a way to dodge re-citing.
    dodge = base + (
        "## 041. Something\n\n"
        "- **Imported:** from the c2rust-port lineage, where it is #008.\n"
        "- **Re-cited:** source #6 -> by title \"Gates fail open on nothing ran\"\n"
        "- **What happened:** body.\n\n---\n")
    n, probs = run(dodge)
    chk("`by title` is refused when an entry with that title DOES exist",
        any("EXISTS here" in p for p in probs))

    # An imported entry citing nothing needs no mapping.
    plain = base + (
        "## 041. Something\n\n"
        "- **Imported:** from the c2rust-port lineage, where it is #008.\n"
        "- **What happened:** no cross-references at all.\n\n---\n")
    n, probs = run(plain)
    chk("an import with no cross-references needs no mapping", (n, probs) == (1, []))

    # …but one that cites and has no mapping bullet is refused.
    unmapped = base + (
        "## 041. Something\n\n"
        "- **Imported:** from the c2rust-port lineage, where it is #008.\n"
        "- **What happened:** see #034 for the fail-closed rule.\n\n---\n")
    n, probs = run(unmapped)
    chk("an import that cites with NO `Re-cited` bullet is refused",
        any("no `- **Re-cited:**` bullet" in p for p in probs))

    # Curly quotes — the form every real entry uses, because a title may quote a
    # phrase of its own. A straight-quote-only parser reports "no parseable
    # mapping" on the whole log while its own fixtures stay green.
    curly = base + (
        "## 041. Something\n\n"
        "- **Imported:** from the c2rust-port lineage, where it is #008.\n"
        "- **Re-cited:** source #6 -> “Gates fail open on nothing ran”\n"
        "- **What happened:** see #034.\n\n---\n").replace(
        "source #6 -> “", "source #6 -> #034 “")
    n, probs = run(curly)
    chk("a curly-quoted mapping parses", (n, probs) == (1, []))

    # …and a title that itself contains a straight-quoted phrase, which is the
    # reason curly quotes are accepted at all.
    inner = (
        "## 034. Gates fail open on \"nothing ran\" — self-test the degenerate case\n\n"
        "- body\n\n---\n\n"
        "## 041. Something\n\n"
        "- **Imported:** from the c2rust-port lineage, where it is #008.\n"
        "- **Re-cited:** source #6 -> #034 “Gates fail open on \\\"nothing "
        "ran\\\" — self-test the degenerate case”\n"
        "- **What happened:** see #034.\n\n---\n")
    n, probs = run(inner)
    chk("a title containing its own straight quotes still maps", (n, probs) == (1, []))

    # A log with no imports must report that, not a silent green.
    n, probs = run(base)
    chk("a log with no imported entries reports 0 imported, 0 problems",
        (n, probs) == (0, []))

    # The degenerate case the gate must fail on: an entry whose ONLY numbers are
    # in the mapping bullet must not self-approve.
    self_approve = base + (
        "## 041. Something\n\n"
        "- **Imported:** from the c2rust-port lineage, where it is #008.\n"
        "- **Re-cited:** source #6 -> #034 \"Gates fail open on nothing ran\"\n"
        "- **What happened:** carried over #18 unchanged.\n\n---\n")
    n, probs = run(self_approve)
    chk("the mapping bullet does not launder a stray body number",
        any("#18" in p for p in probs))

    # ---- imported FILES (KIT-IMPORT markers) -------------------------------
    def run_files(files, md=base):
        with tempfile.TemporaryDirectory() as td:
            lp = os.path.join(td, "LESSONS.md")
            open(lp, "w", encoding="utf-8").write(md)
            for name, body in files.items():
                fp = os.path.join(td, name)
                os.makedirs(os.path.dirname(fp), exist_ok=True)
                open(fp, "w", encoding="utf-8").write(body)
            return check_files(td, lp)

    n, probs = run_files({"harnesses/h/x.py":
        "# KIT-IMPORT: from the c2rust-port lineage.\n"
        "# Re-cited: #6->#034, #4->#004\n"
        "# see LESSONS #034 and LESSONS #004\n"})
    chk("a KIT-IMPORT file whose citations are all mapped passes", (n, probs) == (1, []))

    # THE bug this half exists for: a continuation member, invisible to a grep
    # for `LESSONS #14` because it is written `LESSONS #034, #14`.
    n, probs = run_files({"harnesses/h/x.py":
        "# KIT-IMPORT: from the c2rust-port lineage.\n"
        "# Re-cited: #6->#034\n"
        "# the fail-closed rule (LESSONS #034, #14.)\n"})
    chk("a comma continuation member (`#034, #14`) is caught in a FILE",
        any("#14" in p for p in probs))

    # The same continuation, wrapped onto the next comment line — the shape the
    # kit's own Makefile carried, unread by every checker until the collision
    # resolver's loose pass listed the token.
    n, probs = run_files({"harnesses/h/x.py":
        "# KIT-IMPORT: from the c2rust-port lineage.\n"
        "# Re-cited: #6->#034\n"
        "# the fail-closed rule (LESSONS #034,\n"
        "#                      #14)\n"})
    chk("a member continued on the next COMMENT line is caught in a FILE",
        any("#14" in p for p in probs))

    n, probs = run_files({"skills/s/SKILL.md":
        "# KIT-IMPORT: from the c2rust-port lineage.\n"
        "Re-cited: #4->#004\n"
        "a design smell (LESSONS #004/#6); design it out.\n"})
    chk("a slash continuation member (`#004/#6`) is caught in a FILE",
        any("#6" in p for p in probs))

    # The number is assembled rather than written, because `check_lesson_refs`
    # scans this file too, and a literal citation of a nonexistent entry is
    # indistinguishable from a real citation to a lesson that does not exist —
    # which is precisely what that check is for. Test data, not a citation.
    absent = "9" * 3
    n, probs = run_files({"harnesses/h/x.py":
        "# KIT-IMPORT: from the c2rust-port lineage.\n"
        f"# Re-cited: #6->#{absent}\n# LESSONS #{absent}\n"})
    chk("a KIT-IMPORT mapping to a non-existent entry is caught",
        any(absent in p and "not an entry" in p for p in probs))

    n, probs = run_files({"harnesses/h/x.py":
        "# KIT-IMPORT: from the c2rust-port lineage.\n# see LESSONS #034\n"})
    chk("a KIT-IMPORT file that cites but declares no mapping is refused",
        any("declares no" in p for p in probs))

    # An imported file with no citations at all needs no mapping — normalize.py
    # is exactly this, and refusing it would push the marker off the file.
    n, probs = run_files({"harnesses/h/x.py":
        "# KIT-IMPORT: from the c2rust-port lineage. No LESSONS citations.\n"})
    chk("a KIT-IMPORT file with no citations needs no mapping", (n, probs) == (1, []))

    # `by title` on its own is a complete declaration for a file whose only
    # source citation has no counterpart here.
    n, probs = run_files({"harnesses/h/x.py":
        "# KIT-IMPORT: from the c2rust-port lineage.\n"
        "# Re-cited: #36 by title (no entry here).\n"
        "# the raw-byte gap; see the source lineage.\n"})
    chk("`by title` alone is a complete file mapping", (n, probs) == (1, []))

    # A native lesson cited from an imported file: declared `Local:`, because
    # there is no source number to re-cite FROM. Without this an imported harness
    # could never cite a lesson THIS log wrote.
    n, probs = run_files({"harnesses/h/x.py":
        "# KIT-IMPORT: from the c2rust-port lineage.\n"
        "# Re-cited: #6->#034. Local: #004\n"
        "# see LESSONS #034 and this log's own LESSONS #004\n"})
    chk("a `Local:` native lesson may be cited from an imported file",
        (n, probs) == (1, []))

    # Assembled, not written literally: `check_lesson_refs` scans this file too,
    # and a literal citation of a nonexistent entry is indistinguishable from a
    # real one — the same reason `absent` is built above. Test data, not a claim.
    gone = "0" + "77"
    n, probs = run_files({"harnesses/h/x.py":
        "# KIT-IMPORT: from the c2rust-port lineage.\n"
        f"# Re-cited: #6->#034. Local: #{gone}\n# LESSONS #{gone}\n"})
    chk("a `Local:` number with no such entry is refused",
        any("local lesson" in p for p in probs))

    # An UNMARKED file is not this check's business, however it cites.
    n, probs = run_files({"harnesses/h/native.py": "# LESSONS #14 is fine here\n"})
    chk("a file with no KIT-IMPORT marker is not checked", (n, probs) == (0, []))

    # The marker is a HEADER. A file that merely TALKS about KIT-IMPORT — this
    # very file, its docstring and its fixtures — must not conscript itself, and
    # a `#6->#034` written in prose must not widen the declared set. Without the
    # header rule this check flagged itself 16 times on its own examples.
    n, probs = run_files({"harnesses/h/doc.py":
        "#!/usr/bin/env python3\n\"\"\"Explains things.\n" + "\n" * 25 +
        "A marker looks like `KIT-IMPORT: ...` with `Re-cited: #6->#034`.\n"
        "\"\"\"\n# LESSONS #14\n"})
    chk("a KIT-IMPORT mention below the header does not mark the file",
        (n, probs) == (0, []))

    # Prose that NAMES the marker, inside the header, still does not mark the
    # file — the marker must open its line. The README did exactly this.
    n, probs = run_files({"README.md":
        "# Kit\n\n> A file carrying a `KIT-IMPORT:` header must account for every\n"
        "> citation in it. Re-cited: #6->#034.\n\nLESSONS #14 is cited here.\n"})
    chk("prose naming KIT-IMPORT mid-line does not mark the file",
        (n, probs) == (0, []))

    n, probs = run_files({"harnesses/h/x.py":
        "# KIT-IMPORT: from the c2rust-port lineage.\n"
        "# Re-cited: #4->#004\n" + "#\n" * 6 +
        "# prose further down that says #6->#034 must not widen the set\n"
        "# LESSONS #034\n"})
    chk("a mapping written below the marker block does not widen the set",
        any("#34" in p for p in probs))

    print("\nself-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
