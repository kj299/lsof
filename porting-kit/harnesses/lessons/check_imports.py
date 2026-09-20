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
`(LESSONS #034/#14/#18/#20)`: the head was re-cited and the three continuation
members were not, so the sentence silently pointed at three unrelated entries and
every gate stayed green. Two more entries carried a bare `#8` and `#6` from the
source lineage.

The fix travels with the import. An imported entry records what each source
citation was re-cited TO, **and the title it had** — so the claim is checkable
here, offline, without the source log:

    ## 041. Some lesson

    - **Imported:** from the c2rust-port lineage of this kit, where it is #008.
    - **Re-cited:** source #6 -> #034 "Gates fail open on \"nothing ran\"";
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

Usage:  check_imports.py [LESSONS.md]     (default: the kit this file is in)
        check_imports.py --self-test

Exit: 0 = every imported entry's re-citations resolve and are complete.
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
# this log may itself contain a straight-quoted phrase (#034 quotes "nothing
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
    for p in problems:
        print("PROBLEM  " + p)
    print(f"{imported} imported entr(ies), {len(problems)} problem(s)")
    if not imported:
        # Nothing imported is a legitimate state for a kit that never forked —
        # but say so, rather than printing a green line that reads like a pass
        # over entries that were checked. (A gate with nothing to check is not a
        # passing gate; this one reports which it is.)
        print("note: no `- **Imported:**` entries — nothing to re-cite here.")
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

    print("\nself-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
