#!/usr/bin/env python3
"""Resolve a lesson-number collision — two branches of the append-only log took
the same numbers, and the block that landed second must move.

`LESSONS.md` is append-only, and its next number is shared mutable state that
git cannot merge (LESSONS #048). Two branches each append `## 050.`; the merge
conflicts; and the procedure #048 recorded — the side that landed first keeps
its numbers, the other block shifts as a unit, every citation to the shifted
block is repointed — was then carried out by hand five times on one pull
request. The fourth time it was done with `sed`, sequentially, and repointed
three of four citations wrongly while `check_lesson_refs.py` stayed green,
because a citation that resolves to the wrong lesson still resolves
(LESSONS #046). The renumber is where the damage happens, not the merge.

This tool does the procedure mechanically, from git, with the one input a human
cannot reliably supply by reading: **which side wrote each citation.** In a
collision the same `#NNN` is written on both sides and means a different
lesson on each; nothing in the text distinguishes them, so nothing that works
on the text alone — sed, a hand-written map, a careful reader — can be trusted
to. Provenance can. A line that exists in the KEEP side's version of a file is
the keep side's and stays; a line that does not is the moving side's and is
repointed; a line both sides added that was not there at the fork is genuinely
ambiguous and REFUSED.

Given BASE (the fork point), KEEP (whose numbers stand) and MOVE (which
shifts), auto-detected from the merge or cherry-pick in progress:

  1. Rebuild LESSONS.md. Entries up to BASE's last number are three-way merged
     with `git merge-file` — a conflict there is an edit conflict, not a
     collision, and is refused. KEEP's appended block follows unchanged. MOVE's
     appended block follows, renumbered to continue KEEP's.
  2. Inside MOVE's block rewrite, in ONE simultaneous pass: headings,
     `LESSONS #N` citations (a list member by member; a range only as a uniform
     shift, otherwise refused) and re-cited destinations (`-> #NNN`). Source
     lineage numbers (`source #6 ->`, `where it is #016`) are never touched.
  3. In every other file the citation checker scans, repoint the moving side's
     citations by line provenance, as above.
  4. List for a human every remaining `#N` token on a moving-side line that
     names a moved number and was NOT rewritten — the strict-against-loose
     comparison #048 asks for, so a citation the rules did not recognise is
     seen rather than silently kept.
  5. With --apply, write the files and run `check_lesson_refs` and
     `check_imports` over the result. Without it, print the plan and the
     diffs and write nothing.

Every refusal is exit 1 and writes nothing: an ambiguous line, a split range,
an edit conflict inside the shared entries, a non-contiguous block on either
side, or a conflict marker left in another file that cites a moved number. (A
conflicted file that cites none is the merge's business, not the renumber's:
it is left alone and does not block it.)

Usage:
  resolve_collision.py [--base REV] [--ours REV] [--theirs REV]
                       [--keep theirs|ours] [--apply]
      With no revisions: a merge in progress (MERGE_HEAD) or a cherry-pick
      (CHERRY_PICK_HEAD). In a merge the INCOMING side keeps its numbers — you
      merged master, and master landed first. In a cherry-pick the BRANCH keeps
      them and the picked commit's lessons move.
  resolve_collision.py --self-test
"""
from __future__ import annotations

import argparse
import bisect
import difflib
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from check_lesson_refs import (CITE_RE, CONT_RE, ENTRY_RE, SCAN_EXTS,  # noqa: E402
                               SKIP_DIRS, _flatten_map, run as check_refs)

KIT_ROOT = os.path.dirname(os.path.dirname(HERE))

# An entry heading with its title: `## 054. Title`.
HEAD_RE = re.compile(r"^## (\d{3})\.\s*(.*?)\s*$", re.M)
# A re-cited DESTINATION — `source #6 -> #036` in an entry's Re-cited bullet,
# `#6->#036` in a KIT-IMPORT marker. The number AFTER the arrow is this log's;
# the one before it belongs to the source lineage and must never move.
ARROW_RE = re.compile(r"->\s*#(\d{1,3})")
# `# Local: #NNN, #NNN` in a KIT-IMPORT marker — this log's numbers. (Written
# with placeholders: a real-looking example here is a line the tool would
# offer to renumber, and did, on its first live run.)
LOCAL_RE = re.compile(r"\bLocal:\s*((?:#\d{1,3}[,\s]*)+)")
HASHNUM_RE = re.compile(r"#(\d{1,3})")
# The LOOSE pass: any `#N` at all. What this matches and the strict rules did
# not is reported for a human, never rewritten (LESSONS #048).
LOOSE_RE = re.compile(r"(?<![\w#])#(\d{1,3})(?!\d)")
CONFLICT_RE = re.compile(r"^(<{7}|>{7}|={7})( |$)", re.M)


class Refuse(Exception):
    """A condition under which nothing may be written."""


# -------------------------------------------------------------------- git --
def _git(repo, *args):
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True)
    if p.returncode != 0:
        raise Refuse(f"git {' '.join(args)}: "
                     f"{p.stderr.decode('utf-8', 'replace').strip()}")
    return p.stdout.decode("utf-8", "replace")


def _show(repo, rev, path):
    """The file at REV, or None if it does not exist there."""
    p = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"],
                       capture_output=True)
    return p.stdout.decode("utf-8", "replace") if p.returncode == 0 else None


def _merge3(current, base, other):
    """`git merge-file -p`; None on conflict, so the caller can refuse."""
    with tempfile.TemporaryDirectory(prefix="lessons-merge-") as d:
        paths = []
        for name, text in (("current", current), ("base", base), ("other", other)):
            p = os.path.join(d, name)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(text)
            paths.append(p)
        r = subprocess.run(["git", "merge-file", "-p", *paths], capture_output=True)
    return r.stdout.decode("utf-8") if r.returncode == 0 else None


def detect_sides(repo, base=None, ours=None, theirs=None, keep=None):
    """(base, keep_rev, move_rev) as SHAs — from flags, else from the operation
    in progress. In a merge the incoming side (MERGE_HEAD) keeps its numbers;
    in a cherry-pick the branch does and the picked commit moves."""
    gd = _git(repo, "rev-parse", "--absolute-git-dir").strip()
    merging = os.path.exists(os.path.join(gd, "MERGE_HEAD"))
    picking = not merging and os.path.exists(os.path.join(gd, "CHERRY_PICK_HEAD"))
    if theirs is None:
        if merging:
            theirs = "MERGE_HEAD"
        elif picking:
            theirs = "CHERRY_PICK_HEAD"
        else:
            raise Refuse("no merge or cherry-pick in progress — give --theirs "
                         "(and --base, --keep) explicitly")
    ours = ours or "HEAD"
    if base is None:
        base = f"{theirs}^" if picking else _git(repo, "merge-base", ours, theirs).strip()
    if keep is None:
        keep = "ours" if picking else "theirs"
    sha = lambda r: _git(repo, "rev-parse", "--verify", f"{r}^{{commit}}").strip()
    base, ours, theirs = sha(base), sha(ours), sha(theirs)
    return (base, theirs, ours) if keep == "theirs" else (base, ours, theirs)


# ---------------------------------------------------------------- the log --
def split_entries(text):
    """(preamble, [(number, entry_text)]); an entry runs from its `## NNN.`
    heading up to the next heading, so separators belong to the entry before."""
    heads = list(ENTRY_RE.finditer(text))
    if not heads:
        return text, []
    out = []
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        out.append((int(m.group(1)), text[m.start():end]))
    return text[:heads[0].start()], out


def _line_of(text, off):
    return text.count("\n", 0, off) + 1


def _norm_title(s):
    return " ".join(s.split()).casefold()


def strict_edits(text, mapping, where="", headings=True):
    """Every rewrite the rules recognise, as (start, end, replacement, rule),
    on ORIGINAL offsets, so they can be applied in one pass from the end.

    A range citation shifts only as a whole; one the mapping would split is a
    Refuse — a human must decide what the sentence now means."""
    edits = {}

    def put(s, e, new, rule):
        edits[(s, e)] = (new, rule)

    def renum(digits, new):            # `#3` stays bare, `#003` stays padded
        return str(new).zfill(len(digits))

    for m in (ENTRY_RE.finditer(text) if headings else ()):
        n = int(m.group(1))
        if n in mapping:
            put(m.start(1), m.end(1), f"{mapping[n]:03d}", "heading")

    flat, idx = _flatten_map(text)
    for m in CITE_RE.finditer(flat):
        # Walk the citation exactly as check_lesson_refs.expand does, but keep
        # every member's OWN digit offset and whether it closes a range.
        members = [(m.start(1), m.group(1), None)]
        prev, pos = int(m.group(1)), m.end()
        while True:
            c = CONT_RE.match(flat, pos)
            if not c:
                break
            members.append((c.start(3), c.group(3), prev if c.group(2) else None))
            prev, pos = int(c.group(3)), c.end()
        for off, digits, rng_from in members:
            n = int(digits)
            if rng_from is not None:
                span = range(rng_from, n + 1)
                inside = [x for x in span if x in mapping]
                if inside:
                    deltas = {mapping[x] - x for x in inside}
                    if len(inside) != len(span) or len(deltas) != 1:
                        raise Refuse(
                            f"{where}:{_line_of(text, idx[off])}: the range "
                            f"LESSONS #{rng_from}–#{n} is SPLIT by the renumbering "
                            f"— decide what it means now and repoint it by hand")
            if n in mapping:
                s = idx[off]
                put(s, s + len(digits), renum(digits, mapping[n]), "citation")

    for m in ARROW_RE.finditer(text):
        n = int(m.group(1))
        if n in mapping:
            put(m.start(1), m.end(1), renum(m.group(1), mapping[n]), "re-cited destination")

    for m in LOCAL_RE.finditer(text):
        for h in HASHNUM_RE.finditer(m.group(1)):
            n = int(h.group(1))
            if n in mapping:
                s = m.start(1) + h.start(1)
                put(s, s + len(h.group(1)), renum(h.group(1), mapping[n]), "KIT-IMPORT Local")

    return [(s, e, new, rule) for (s, e), (new, rule) in sorted(edits.items())]


def provenance(line, keep_lines, base_lines, move_lines):
    """THE VERDICT on one line that carries a moved number: whose is it?

    "move"      — not in KEEP's version of the file: the moving side wrote it
                  (or the merge produced it). Its number is repointed.
    "keep"      — KEEP has it: KEEP's meaning; left alone. A line that was
                  already there at the fork is KEEP's too.
    "ambiguous" — KEEP has it, BASE does not, and MOVE has it as well: both
                  sides wrote this exact line and the number means a different
                  lesson on each. No text-only rule can pick. Refuse.
    """
    if line not in keep_lines:
        return "move"
    if line in base_lines:
        return "keep"
    return "ambiguous" if line in move_lines else "keep"


def plan_text(text, mapping, keep_txt, base_txt, move_txt, where, first_line=1,
              headings=False, also_review=frozenset()):
    """(edits, ambiguous, review) for one file's merged text.

    `keep_txt`/`base_txt`/`move_txt` are that file at the three revisions (None
    where absent). Passing None for all three declares every line the moving
    side's — used for MOVE's own appended block."""
    keep_lines = set((keep_txt or "").splitlines())
    base_lines = set((base_txt or "").splitlines())
    move_lines = set((move_txt or "").splitlines())
    lines = text.splitlines(keepends=True)
    starts, pos = [], 0
    for ln in lines:
        starts.append(pos)
        pos += len(ln)

    def line_index(off):
        return bisect.bisect_right(starts, off) - 1

    edits, ambiguous, review, covered = [], [], [], set()
    for s, e, new, rule in strict_edits(text, mapping, where, headings=headings):
        i = line_index(s)
        ltxt = lines[i].rstrip("\r\n")
        verdict = provenance(ltxt, keep_lines, base_lines, move_lines)
        if verdict == "ambiguous":
            ambiguous.append(f"{where}:{first_line + i}: both sides wrote this line, "
                             f"and #{text[s:e]} means a different lesson on each: "
                             f"{ltxt.strip()}")
        elif verdict == "move":
            edits.append((s, e, new, rule, first_line + i))
            covered.add(s)
    # The loose pass, over the moving side's lines only.
    for i, ln in enumerate(lines):
        ltxt = ln.rstrip("\r\n")
        if ltxt in keep_lines:
            continue
        for m in LOOSE_RE.finditer(ltxt):
            num = int(m.group(1))
            if (num in mapping or num in also_review) and (starts[i] + m.start(1)) not in covered:
                review.append(f"{where}:{first_line + i}: '#{m.group(1)}' was not "
                              f"rewritten — {ltxt.strip()}")
    return edits, ambiguous, review


def apply_edits(text, edits):
    """Every edit was computed on the ORIGINAL text, so none can see another's
    output — that is what makes the pass simultaneous (LESSONS #048, property
    1). Applying from the end is what keeps the offsets valid when a
    replacement is wider than what it replaces (`#9` -> `#10`)."""
    for s, e, new, *_ in sorted(edits, key=lambda t: t[0], reverse=True):
        text = text[:s] + new + text[e:]
    return text


def _displaced(base_prefix, side_prefix, block, min_len=20):
    """Lines a side REMOVED from the shared entries that its appended block
    contains verbatim — each reported with the entry it came from."""
    gone = set(base_prefix.splitlines()) - set(side_prefix.splitlines())
    have = {ln.strip() for ln in block.splitlines()}
    out = []
    if not gone or not have:
        return out
    home = "?"
    for ln in base_prefix.splitlines():
        if ln.startswith("## "):
            home = ln[3:6]
        s = ln.strip()
        if ln in gone and len(s) >= min_len and s in have:
            out.append(f"from #{home}: {s[:70]}")
    return out


def _walk(repo):
    for dp, dns, fns in os.walk(repo):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for f in sorted(fns):
            if f.endswith(SCAN_EXTS):
                yield os.path.relpath(os.path.join(dp, f), repo).replace(os.sep, "/")


class Plan:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def build_plan(repo, kit_rel, base, keep_rev, move_rev):
    """Compute everything; write nothing. Raises Refuse."""
    lessons_rel = "LESSONS.md" if kit_rel in ("", ".") else f"{kit_rel}/LESSONS.md"
    texts = {}
    for name, rev in (("base", base), ("keep", keep_rev), ("move", move_rev)):
        texts[name] = _show(repo, rev, lessons_rel)
        if texts[name] is None:
            raise Refuse(f"{lessons_rel} does not exist at {name} ({rev[:9]})")
    B, K, M = texts["base"], texts["keep"], texts["move"]
    pre_b, eb = split_entries(B)
    pre_k, ek = split_entries(K)
    pre_m, em = split_entries(M)
    base_max = max([n for n, _ in eb], default=0)

    def appended(entries, side):
        blk = [(n, t) for n, t in entries if n > base_max]
        got = [n for n, _ in blk]
        want = list(range(base_max + 1, base_max + 1 + len(blk)))
        if got != want:
            raise Refuse(f"the {side} side's appended entries are "
                         f"{[f'{n:03d}' for n in got]}, not the contiguous run "
                         f"an append-only log requires ({base_max + 1:03d}..)")
        return blk

    k_added, m_added = appended(ek, "keep"), appended(em, "move")
    ambiguous, review = [], []
    mapping = {}
    if k_added and m_added:
        k_max = base_max + len(k_added)
        mapping = {n: k_max + i + 1 for i, (n, _) in enumerate(m_added)}

    # Entries renumbered BETWEEN the fork and KEEP. In a plain merge this is
    # empty — the fork point is a KEEP commit, and a landed entry never moves.
    # In a CHERRY-PICK it is not: the picked commit's base is a branch commit
    # whose own appended lessons have since landed under other numbers, so a
    # citation in the picked commit to `#050` means what the BASE called #050,
    # which KEEP now holds elsewhere. Found by title. Without this the citation
    # would resolve, silently, to whatever KEEP holds at #050 today — the #046
    # shape, produced by the tool meant to prevent it. A base entry whose title
    # KEEP no longer has anywhere is ORPHANED: nothing can say what a citation
    # of it means now, so its number joins the review list instead.
    keep_by_title = {}
    for n, txt in ek:
        h = HEAD_RE.match(txt)
        if h:
            keep_by_title.setdefault(_norm_title(h.group(2)), n)
    renumbered, orphaned = {}, set()
    for n, txt in eb:
        h = HEAD_RE.match(txt)
        if not h:
            continue
        dest = keep_by_title.get(_norm_title(h.group(2)))
        if dest is None:
            orphaned.add(n)
        elif dest != n:
            renumbered[n] = dest
    assert not (set(renumbered) & set(mapping)), "appended and renumbered sets overlap"
    mapping.update(renumbered)

    def prefix(pre, entries):
        return pre + "".join(t for n, t in entries if n <= base_max)

    # The three prefixes legitimately differ in their TRAILING bytes — one side
    # ends the last shared entry with `\n`, another adds a `---` separator
    # line before its block (two sessions, two conventions) — and a line-based
    # merge reads that as both sides editing the same last line. The seventh
    # collision made it bite for real: master had appended `---` to the last
    # shared entry and this branch had appended a follow-up bullet to it, and
    # the tool refused an "edit conflict" that was a joint. Trailing whitespace
    # AND a trailing separator line are the JOINT, not content: strip both
    # before merging and re-add KEEP's style when rebuilding. When the merge
    # comes back as KEEP's prefix, use KEEP's original bytes so a merge that
    # adds nothing to the shared entries reproduces KEEP's file exactly.
    def norm(s):
        s = s.rstrip("\n")
        while s.endswith("\n---"):
            s = s[:-4].rstrip("\n")
        return s + "\n"
    prefix_k = prefix(pre_k, ek)
    keep_sep = prefix_k.rstrip("\n").endswith("\n---")
    verbatim_k = False
    merged_prefix = _merge3(norm(prefix(pre_m, em)), norm(prefix(pre_b, eb)), norm(prefix_k))
    if merged_prefix is not None and merged_prefix == norm(prefix_k):
        merged_prefix, verbatim_k = prefix_k, True
    if merged_prefix is None:
        raise Refuse(f"{lessons_rel} conflicts INSIDE the shared entries "
                     f"(001..{base_max:03d}) — that is an edit conflict, not a "
                     f"collision; resolve it by hand first")

    # Text the MOVE side deleted from a shared entry that reappears in its own
    # block is a paragraph that fell out of its entry — an ordinary edit did
    # exactly that to ten lines of #021 on this repository, and four merges
    # carried it because nothing reads entry content. An old entry is amended
    # by appending, never by cutting, so this is a refusal, not a review line.
    displaced = _displaced(prefix(pre_b, eb), prefix(pre_m, em), m_block_text := "".join(t for _, t in m_added))
    if displaced:
        raise Refuse("text the move side removed from the shared entries reappears in "
                     "its appended block — a displaced paragraph:\n  " +
                     "\n  ".join(displaced) +
                     "\n  Restore it to its entry on the move side, then re-run.")
    for line in _displaced(prefix(pre_b, eb), prefix_k, m_block_text):
        review.append(f"{lessons_rel}: KEEP removed a shared-entry line that the moved "
                      f"block contains — {line}")

    p_edits = []
    # Run the passes whenever there is anything to rewrite OR to review: an
    # orphaned fork entry with nothing renumbered must still reach the list.
    if mapping or orphaned:   # the moving side may have cited its new entries from an old one
        p_edits, amb, rev = plan_text(merged_prefix, mapping, K, B, M, lessons_rel,
                                      also_review=orphaned)
        ambiguous += amb
        review += rev
    new_prefix = apply_edits(merged_prefix, p_edits)
    k_block = "".join(t for _, t in k_added)
    m_block = "".join(t for _, t in m_added)
    head = new_prefix
    if k_block:
        # KEEP's own prefix already carries its joint (separator or not); a
        # merged prefix lost it to `norm` and gets KEEP's style back.
        joint = "\n\n" if verbatim_k else ("\n\n---\n\n" if keep_sep else "\n\n")
        head = head.rstrip("\n") + joint + k_block
    if m_block:
        head = head.rstrip("\n") + "\n\n"
    m_edits = []
    if m_block and (mapping or orphaned):
        m_edits, _, rev = plan_text(m_block, mapping, None, None, None, lessons_rel,
                                    first_line=head.count("\n") + 1, headings=True,
                                    also_review=orphaned)
        review += rev
    new_lessons = head + apply_edits(m_block, m_edits)
    if not new_lessons.endswith("\n"):
        new_lessons += "\n"

    titles = {n: (HEAD_RE.match(t) or [None, None, ""])[2] for n, t in m_added}
    titles.update({n: (HEAD_RE.match(t) or [None, None, ""])[2]
                   for n, t in eb if n in renumbered})
    file_changes = []
    if mapping or orphaned:
        for rel in _walk(repo):
            if rel == lessons_rel:
                continue
            try:
                # newline="" — no translation either way, so a CRLF file stays
                # CRLF and an LF file stays LF on every platform (only digits
                # change under an edit).
                with open(os.path.join(repo, rel), encoding="utf-8", newline="") as fh:
                    text = fh.read()
            except (UnicodeDecodeError, OSError):
                continue
            if not any(int(h) in mapping or int(h) in orphaned
                       for h in HASHNUM_RE.findall(text)):
                continue
            if CONFLICT_RE.search(text):
                raise Refuse(f"{rel} still carries conflict markers — resolve it, "
                             f"then re-run")
            edits, amb, rev = plan_text(
                text, mapping, _show(repo, keep_rev, rel), _show(repo, base, rel),
                _show(repo, move_rev, rel), rel, also_review=orphaned)
            ambiguous += amb
            review += rev
            if edits:
                file_changes.append((rel, text, apply_edits(text, edits), edits))
    if ambiguous:
        raise Refuse("\n  " + "\n  ".join(ambiguous) +
                     "\n  — no text-only rule can pick. Repoint these by hand, then re-run.")

    return Plan(base=base, keep_rev=keep_rev, move_rev=move_rev, base_max=base_max,
                k_added=[n for n, _ in k_added], m_added=[n for n, _ in m_added],
                mapping=mapping, renumbered=renumbered, orphaned=sorted(orphaned),
                titles=titles, lessons_rel=lessons_rel,
                keep_lessons=K, new_lessons=new_lessons, prefix_edits=p_edits,
                merged_prefix=merged_prefix,
                block_edits=m_edits, file_changes=file_changes, review=review)


def describe(plan, out=print):
    out(f"base {plan.base[:9]}  keep {plan.keep_rev[:9]}  move {plan.move_rev[:9]}")
    out(f"shared entries 001..{plan.base_max:03d} merge cleanly; "
        f"keep appends {_span(plan.k_added)}; move appends {_span(plan.m_added)}")
    if not plan.mapping:
        out("no collision: nothing to renumber")
    for old, new in plan.mapping.items():
        tag = "  (renumbered since the fork; found in KEEP by title)" if old in plan.renumbered else ""
        out(f"  #{old:03d} -> #{new:03d}  {plan.titles.get(old, '')}{tag}")
    for n in plan.orphaned:
        out(f"  #{n:03d} at the fork is not in KEEP under any number — citations of it "
            f"are listed for review, not rewritten")
    if plan.block_edits:
        heads = sum(1 for *_x, rule, _l in plan.block_edits if rule == "heading")
        out(f"{plan.lessons_rel}: moved block — {heads} heading(s), "
            f"{len(plan.block_edits) - heads} citation(s) rewritten")
    # A rewrite in a SHARED entry is the moving side's own line inside an old
    # lesson (a follow-up, a see-also). Listed one by one: these are exactly the
    # citations a hand renumber misses, because nobody greps old entries.
    for s, e, new, rule, line in plan.prefix_edits:
        out(f"  {plan.lessons_rel}:{line}  #{plan.merged_prefix[s:e]} -> #{new}  "
            f"({rule}, in a shared entry)")
    for rel, _old, _new, edits in plan.file_changes:
        for s, e, new, rule, line in edits:
            out(f"  {rel}:{line}  #{_old[s:e]} -> #{new}  ({rule})")
    if plan.review:
        out("REVIEW — a moved number on a moving-side line that no rule rewrote:")
        for r in plan.review:
            out(f"  {r}")
    out("")
    for line in difflib.unified_diff(
            plan.keep_lessons.splitlines(keepends=True),
            plan.new_lessons.splitlines(keepends=True),
            f"keep:{plan.lessons_rel}", f"resolved:{plan.lessons_rel}", n=2):
        out(line.rstrip("\n"))
    for rel, old, new, _ in plan.file_changes:
        for line in difflib.unified_diff(old.splitlines(keepends=True),
                                         new.splitlines(keepends=True),
                                         f"a/{rel}", f"b/{rel}", n=1):
            out(line.rstrip("\n"))


def _span(nums):
    return "nothing" if not nums else f"{nums[0]:03d}..{nums[-1]:03d}"


def apply_plan(repo, plan):
    written = [plan.lessons_rel]
    # newline="" here too: write exactly the bytes planned. LESSONS.md is rebuilt
    # from git's blobs (LF as stored); git's own eol handling applies on add.
    with open(os.path.join(repo, plan.lessons_rel), "w", encoding="utf-8", newline="") as fh:
        fh.write(plan.new_lessons)
    for rel, _old, new, _ in plan.file_changes:
        with open(os.path.join(repo, rel), "w", encoding="utf-8", newline="") as fh:
            fh.write(new)
        written.append(rel)
    return written


def post_checks(repo, kit_root, real):
    """The two checkers, over the written result. `real` also runs
    check_imports, whose KIT-IMPORT scan is anchored to the real kit."""
    rc = check_refs(kit_root, also=[repo])
    if real:
        r = subprocess.run([sys.executable, os.path.join(HERE, "check_imports.py"),
                            os.path.join(kit_root, "LESSONS.md")],
                           capture_output=True, text=True)
        print(r.stdout.strip())
        rc = rc or r.returncode
    return rc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base")
    ap.add_argument("--ours")
    ap.add_argument("--theirs")
    ap.add_argument("--keep", choices=("theirs", "ours"))
    ap.add_argument("--apply", action="store_true", help="write the result")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    try:
        repo = _git(KIT_ROOT, "rev-parse", "--show-toplevel").strip()
        kit_rel = os.path.relpath(KIT_ROOT, repo).replace(os.sep, "/")
        base, keep_rev, move_rev = detect_sides(repo, a.base, a.ours, a.theirs, a.keep)
        plan = build_plan(repo, kit_rel, base, keep_rev, move_rev)
    except Refuse as e:
        print(f"REFUSED: {e}")
        return 1
    describe(plan)
    if not a.apply:
        print("(dry run — nothing written; re-run with --apply)")
        return 0
    written = apply_plan(repo, plan)
    print(f"wrote {len(written)} file(s); checking the result:")
    rc = post_checks(repo, KIT_ROOT, real=True)
    if rc:
        print("the checkers are RED on the written result — inspect before committing")
        return rc
    print("next: git add " + " ".join(written) + "  &&  git commit")
    return 0


# ---------------------------------------------------------------- self-test --
def _self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    BASE_LOG = ("# Lessons\n\n## 001. One\n\nbody one\n\n"
                "## 002. Two\n\nbody two cites (LESSONS #001).\n")
    KEEP = "\n## 003. Keep three\n\nkeep body\n"
    MOVE = ("\n## 003. Move three\n\nmove body; see PR #3 for context.\n"
            "\n## 004. Move four\n\n"
            "- **Imported:** from elsewhere, where it is #016.\n"
            "- **Re-cited:** source #9 -> #003 “Move three”\n\n"
            "body cites (LESSONS #003).\n"
            "\n## 005. Move five\n\nbody cites LESSONS #3 and #004.\n")

    def repo(tmp):
        r = os.path.join(tmp, "repo")
        os.makedirs(os.path.join(r, "kit"))

        def g(*args, ok=True):
            p = subprocess.run(
                ["git", "-C", r, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                 "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
                capture_output=True, text=True)
            if ok and p.returncode != 0:
                raise RuntimeError(p.stderr)
            return p
        g("init", "-q")
        return r, g

    def w(r, rel, text, append=False):
        p = os.path.join(r, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "a" if append else "w", encoding="utf-8", newline="") as fh:
            fh.write(text)

    def read(r, rel):
        with open(os.path.join(r, rel), encoding="utf-8", newline="") as fh:
            return fh.read()

    def commit(g, msg):
        g("add", "-A")
        g("commit", "-q", "-m", msg)

    def fork(tmp):
        r, g = repo(tmp)
        w(r, "kit/LESSONS.md", BASE_LOG)
        w(r, "doc.md", "cites (LESSONS #1).\n")
        commit(g, "base")
        g("branch", "keep")
        g("branch", "move")
        return r, g

    def collide(r, g, keep_log, move_log, keep_files=(), move_files=()):
        g("checkout", "-q", "keep")
        w(r, "kit/LESSONS.md", keep_log, append=True)
        for rel, t in keep_files:
            w(r, rel, t, append=True)
        commit(g, "keep")
        g("checkout", "-q", "move")
        w(r, "kit/LESSONS.md", move_log, append=True)
        for rel, t in move_files:
            w(r, rel, t, append=True)
        commit(g, "move")
        return g("merge", "--no-edit", "keep", ok=False)

    def refusal(r, *sides):
        try:
            build_plan(r, "kit", *(sides or detect_sides(r)))
        except Refuse as e:
            return str(e)
        return None

    def try_plan(r, *sides):
        """(plan, None) or (an inert plan, message): a refusal must FAIL the
        checks that follow, not crash the self-test with a Traceback."""
        try:
            return build_plan(r, "kit", *(sides or detect_sides(r))), None
        except Refuse as e:
            print(f"      (refused: {str(e).splitlines()[0][:90]})")
            return Plan(mapping={}, review=[], new_lessons="", file_changes=[]), str(e)

    # --- the collision itself, end to end --------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        collide(r, g, KEEP, MOVE,
                keep_files=[("kdoc.md", "keep cites LESSONS #003 and #3.\n"),
                            ("tool.py", "# Re-cited: #6->#003\n")],
                move_files=[("mdoc.md", "move cites LESSONS #3, a list (LESSONS #003, "
                                        "#005), a range (LESSONS #003–#005).\n"),
                            ("doc.md", "move adds LESSONS #004.\n"),
                            ("cdoc.py", "# see (LESSONS #003,\n# #005) here\n")])
        conflicted = read(r, "kit/LESSONS.md")
        check("the fixture really collides: git left markers", "<<<<<<<" in conflicted)
        plan, msg = try_plan(r)
        check("the collision is planned, not refused", msg is None)
        check("the moving block is renumbered to follow the kept one",
              plan.mapping == {3: 4, 4: 5, 5: 6})
        check("a plan writes nothing",
              read(r, "kit/LESSONS.md") == conflicted
              and read(r, "mdoc.md").startswith("move cites LESSONS #3,"))
        if msg is None:
            apply_plan(r, plan)
        L = read(r, "kit/LESSONS.md")
        check("kept side keeps its numbers; the moved block follows, shifted in ONE "
              "pass (a chained shift would end three entries at 006)",
              ENTRY_RE.findall(L) == ["001", "002", "003", "004", "005", "006"]
              and "## 003. Keep three" in L and "## 004. Move three" in L
              and "## 005. Move four" in L and "## 006. Move five" in L)
        check("a cross-citation inside the moved block moves with it",
              "body cites (LESSONS #004)." in L)
        check("a re-cited DESTINATION moves; the SOURCE number before the arrow does not",
              "source #9 -> #004 “Move three”" in L)
        check("a source-lineage number in prose is untouched", "where it is #016." in L)
        check("a bare member stays bare and a padded one padded",
              "body cites LESSONS #4 and #005." in L)
        check("the kept side's own citations are left alone",
              read(r, "kdoc.md") == "keep cites LESSONS #003 and #3.\n"
              and read(r, "tool.py") == "# Re-cited: #6->#003\n")
        check("the moving side's list and range are repointed member by member",
              read(r, "mdoc.md") == "move cites LESSONS #4, a list (LESSONS #004, #006), "
                                    "a range (LESSONS #004–#006).\n")
        check("a citation wrapped onto a second comment line is repointed whole",
              read(r, "cdoc.py") == "# see (LESSONS #004,\n# #006) here\n")
        check("in a SHARED file only the line the moving side added is repointed",
              read(r, "doc.md") == "cites (LESSONS #1).\nmove adds LESSONS #005.\n")
        check("a `#3` no rule recognised is listed for review, not rewritten",
              any("PR #3" in x for x in plan.review) and "see PR #3 for context" in L)
        check("the result passes check_lesson_refs",
              check_refs(os.path.join(r, "kit"), also=[r]) == 0)

    # --- refusals: each writes nothing -----------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        collide(r, g, KEEP, "\n## 003. Move three\n\nmove body\n",
                keep_files=[("doc.md", "see LESSONS #003.\n")],
                move_files=[("doc.md", "see LESSONS #003.\n")])
        before = read(r, "doc.md")
        msg = refusal(r)
        check("a line BOTH sides wrote is ambiguous and refused",
              msg is not None and "doc.md" in msg and "both sides" in msg)
        check("a refusal writes nothing",
              "<<<<<<<" in read(r, "kit/LESSONS.md") and read(r, "doc.md") == before)

    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        g("checkout", "-q", "keep")
        w(r, "kit/LESSONS.md", BASE_LOG.replace("body one", "body one, keep") + KEEP)
        commit(g, "keep")
        g("checkout", "-q", "move")
        w(r, "kit/LESSONS.md", BASE_LOG.replace("body one", "body one, move")
          + "\n## 003. Move three\n\nmove body\n")
        commit(g, "move")
        g("merge", "--no-edit", "keep", ok=False)
        msg = refusal(r)
        check("an edit conflict INSIDE the shared entries is refused as not a collision",
              msg is not None and "INSIDE the shared entries" in msg)

    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        collide(r, g, KEEP, "\n## 003. A\n\nx\n\n## 005. B\n\ny\n")
        msg = refusal(r)
        check("a non-contiguous appended block is refused",
              msg is not None and "contiguous" in msg)

    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        collide(r, g, KEEP, "\n## 003. A\n\nx\n\n## 004. B\n\ny\n",
                move_files=[("mdoc.md", "see (LESSONS #002–#004).\n")])
        msg = refusal(r)
        check("a range the renumbering would SPLIT is refused",
              msg is not None and "SPLIT" in msg and "mdoc.md" in msg)

    # A file other than the log that git left conflicted, citing a moved number:
    # rewriting citations inside an unresolved merge edits both halves of a
    # conflict nobody has decided yet. The docstring promised this refusal and
    # no fixture reached it; LESSONS #069's decision sweep forced it off and the
    # self-test stayed green.
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        collide(r, g, KEEP, "\n## 003. Move three\n\nmove body\n",
                keep_files=[("doc.md", "keep says LESSONS #003.\n")],
                move_files=[("doc.md", "move says LESSONS #003.\n")])
        before = read(r, "doc.md")
        msg = refusal(r)
        check("a conflict marker left in another file is refused, naming the file",
              "<<<<<<<" in before and msg is not None and "doc.md" in msg
              and "conflict markers" in msg)
        check("...and that refusal writes nothing", read(r, "doc.md") == before)

    # --- no collision: nothing renumbered, the merge is still a merge ----
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        base = g("rev-parse", "HEAD").stdout.strip()
        g("checkout", "-q", "keep")
        w(r, "kdoc.md", "unrelated\n")
        commit(g, "keep")
        keep = g("rev-parse", "HEAD").stdout.strip()
        g("checkout", "-q", "move")
        w(r, "kit/LESSONS.md", "\n## 003. Move three\n\nmove body\n", append=True)
        commit(g, "move")
        move = g("rev-parse", "HEAD").stdout.strip()
        plan = build_plan(r, "kit", base, keep, move)
        check("with nothing on the kept side there is no collision and no renumbering",
              plan.mapping == {} and "## 003. Move three" in plan.new_lessons
              and plan.file_changes == [])

    # --- a cherry-pick: the branch keeps, the picked commit moves ---------
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        g("checkout", "-q", "move")
        w(r, "kit/LESSONS.md", "\n## 003. Picked\n\nbody\n", append=True)
        w(r, "pdoc.md", "cites LESSONS #003.\n")
        commit(g, "picked")
        g("checkout", "-q", "main")
        w(r, "kit/LESSONS.md", KEEP, append=True)
        commit(g, "landed first")
        g("cherry-pick", "move", ok=False)
        base, keep, move = detect_sides(r)
        check("a cherry-pick is detected with the roles reversed",
              keep == g("rev-parse", "HEAD").stdout.strip()
              and move == g("rev-parse", "CHERRY_PICK_HEAD").stdout.strip()
              and base == g("rev-parse", "CHERRY_PICK_HEAD^").stdout.strip())
        plan = build_plan(r, "kit", base, keep, move)
        apply_plan(r, plan)
        check("the picked lesson takes the next free number and its citation follows",
              plan.mapping == {3: 4} and "## 004. Picked" in read(r, "kit/LESSONS.md")
              and read(r, "pdoc.md") == "cites LESSONS #004.\n")

    # --- the joint: KEEP writes `---` separators, MOVE does not ------------
    # This is the shape of the real collision: base ended the last shared entry
    # with `\n`, master added `\n\n---\n\n` before its block, the branch added
    # `\n\n` — and a line-based merge called that both sides editing one line.
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        collide(r, g, "\n---\n\n## 003. Keep three\n\nkeep body\n\n---\n",
                "\n\n## 003. Move three\n\nmove body\n")
        plan, msg = try_plan(r)
        check("tails that differ on the last shared entry are not an edit conflict, "
              "and KEEP's bytes come through verbatim",
              msg is None and plan.new_lessons ==
              BASE_LOG + "\n---\n\n## 003. Keep three\n\nkeep body\n\n---\n\n"
                         "## 004. Move three\n\nmove body\n")

    # --- both sides touch the tail of the last shared entry: KEEP appends its
    # `---` separator, MOVE appends a follow-up bullet. A joint, not an edit
    # conflict — the seventh collision, refused by the tool until this fixture.
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        g("checkout", "-q", "keep")
        w(r, "kit/LESSONS.md", "\n---\n\n## 003. Keep three\n\nkeep body\n\n---\n", append=True)
        commit(g, "keep")
        g("checkout", "-q", "move")
        w(r, "kit/LESSONS.md", "  follow-up on two\n\n## 003. Move three\n\nmove body\n", append=True)
        commit(g, "move")
        g("merge", "--no-edit", "keep", ok=False)
        plan, msg = try_plan(r)
        check("KEEP's trailing separator and MOVE's follow-up on the same last entry are a "
              "joint, not an edit conflict; the follow-up stays and KEEP's separator style is kept",
              msg is None and plan.new_lessons ==
              BASE_LOG + "  follow-up on two\n\n---\n\n## 003. Keep three\n\nkeep body\n\n---\n\n"
                         "## 004. Move three\n\nmove body\n")

    # --- a moving-side line added to an OLD entry (the #021 follow-up case) --
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        g("checkout", "-q", "keep")
        w(r, "kit/LESSONS.md", KEEP, append=True)
        commit(g, "keep")
        g("checkout", "-q", "move")
        w(r, "kit/LESSONS.md", BASE_LOG + "\n  Follow-up: see LESSONS #003.\n"
          + "\n## 003. Move three\n\nmove body\n")
        commit(g, "move")
        g("merge", "--no-edit", "keep", ok=False)
        plan, msg = try_plan(r)
        if msg is None:
            apply_plan(r, plan)
        check("a citation the moving side appended to an OLD entry is repointed too",
              msg is None and "Follow-up: see LESSONS #004." in read(r, "kit/LESSONS.md")
              and "## 003. Keep three" in read(r, "kit/LESSONS.md"))

    # --- a paragraph cut from an old entry and carried in the new block ------
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        base = g("rev-parse", "HEAD").stdout.strip()
        g("checkout", "-q", "keep")
        w(r, "kit/LESSONS.md", KEEP, append=True)
        commit(g, "keep")
        keep = g("rev-parse", "HEAD").stdout.strip()
        g("checkout", "-q", "move")
        w(r, "kit/LESSONS.md", BASE_LOG.replace("body two cites (LESSONS #001).\n", "")
          + "\n## 003. Move three\n\nmove body\n\nbody two cites (LESSONS #001).\n")
        commit(g, "move")
        move = g("rev-parse", "HEAD").stdout.strip()
        # This one merges CLEAN — the cut line was the file's last, so git sees
        # two non-overlapping edits and commits a log with two `## 003.` and no
        # marker (LESSONS #048's mid-file hazard). The tool is then run the way a
        # human would after check_lesson_refs fails: with the revisions spelled out.
        g("merge", "--no-edit", "keep", ok=False)
        plan, msg = try_plan(r, base, keep, move)
        check("text the moving side cut from an old entry and carries in its block "
              "is refused as a displaced paragraph, naming the entry",
              msg is not None and "displaced" in msg and "from #002" in msg)

    # --- line endings: a CRLF file keeps CRLF, only the digits change --------
    # Python's default text mode on Windows translates newlines on read AND on
    # write; a resolver that did that would rewrite every line of an LF file.
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        collide(r, g, KEEP, "\n## 003. Move three\n\nmove body\n",
                move_files=[("crlf.md", "one\r\ncites LESSONS #003 here\r\nthree\r\n")])
        plan, msg = try_plan(r)
        if msg is None:
            apply_plan(r, plan)
        check("a CRLF file is repointed byte-for-byte, keeping its line endings",
              msg is None and read(r, "crlf.md") == "one\r\ncites LESSONS #004 here\r\nthree\r\n")

    # --- a cherry-pick after a renumber: the fork's numbers are not KEEP's ---
    # Branch A appends 003 and then a commit C that cites it. main lands its own
    # 003 first and then A's lesson as 004. Cherry-picking C onto main, C's
    # `#003` means A's lesson — #004 on main now — and C's own 004 must move too.
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        g("checkout", "-q", "move")
        w(r, "kit/LESSONS.md", "\n## 003. A lesson\n\nfrom branch A\n", append=True)
        commit(g, "A lesson")
        w(r, "kit/LESSONS.md", "\n## 004. C lesson\n\nsee LESSONS #003 for the A lesson\n",
          append=True)
        w(r, "cdoc.md", "C cites LESSONS #003 and LESSONS #004.\n")
        commit(g, "C")
        g("checkout", "-q", "main")
        w(r, "kit/LESSONS.md", "\n## 003. M lesson\n\nlanded first\n\n## 004. A lesson\n\n"
          "from branch A, renumbered on landing\n", append=True)
        commit(g, "main: M first, then A as 004")
        g("cherry-pick", "move", ok=False)
        plan, msg = try_plan(r)
        if msg is None:
            apply_plan(r, plan)
        L = read(r, "kit/LESSONS.md") if msg is None else ""
        check("a cherry-pick maps the fork's numbers to KEEP's by title, and the picked "
              "block after them",
              msg is None and plan.mapping == {3: 4, 4: 5} and plan.renumbered == {3: 4})
        check("the picked commit's citations follow the renumbered entry",
              "see LESSONS #004 for the A lesson" in L and "## 005. C lesson" in L
              and read(r, "cdoc.md") == "C cites LESSONS #004 and LESSONS #005.\n"
              and "## 003. M lesson" in L and "## 004. A lesson" in L)

    # --- ...and a fork entry KEEP no longer has anywhere is listed, not guessed
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        g("checkout", "-q", "move")
        w(r, "kit/LESSONS.md", "\n## 003. Gone lesson\n\nnever landed\n", append=True)
        commit(g, "gone")
        w(r, "kit/LESSONS.md", "\n## 004. C lesson\n\nsee LESSONS #003\n", append=True)
        commit(g, "C")
        g("checkout", "-q", "main")
        w(r, "kit/LESSONS.md", "\n## 003. M lesson\n\nlanded first, and different\n", append=True)
        commit(g, "main")
        g("cherry-pick", "move", ok=False)
        plan, msg = try_plan(r)
        check("a fork entry absent from KEEP is ORPHANED: its citation is reviewed, not rewritten",
              msg is None and plan.orphaned == [3] and 3 not in plan.mapping
              and any("'#003'" in x for x in plan.review))

    # --- shapes no fixture above reached (LESSONS #069/#071's decision sweep) --
    # A kit at the repository root: main() passes kit_rel ".", and the log is
    # then `LESSONS.md`, not `./LESSONS.md`, which the file walk would take for
    # another file and refuse for its conflict markers.
    with tempfile.TemporaryDirectory() as tmp:
        r, g = repo(tmp)
        w(r, "LESSONS.md", BASE_LOG)
        commit(g, "base")
        g("branch", "keep")
        g("branch", "move")
        g("checkout", "-q", "keep")
        w(r, "LESSONS.md", KEEP, append=True)
        commit(g, "keep")
        g("checkout", "-q", "move")
        w(r, "LESSONS.md", MOVE, append=True)   # its block cites its own entries
        w(r, "mdoc.md", "cites LESSONS #003.\n")
        commit(g, "move")
        g("merge", "--no-edit", "keep", ok=False)
        try:
            plan, msg = build_plan(r, ".", *detect_sides(r)), None
        except Refuse as e:
            plan, msg = None, str(e)
        check("a kit at the repository root (kit path '.') is planned like any other",
              msg is None and plan.mapping == {3: 4, 4: 5, 5: 6}
              and [c[0] for c in plan.file_changes] == ["mdoc.md"])

    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        head = g("rev-parse", "HEAD").stdout.strip()
        try:
            build_plan(r, "nokit", head, head, head)
            msg = None
        except Refuse as e:
            msg = str(e)
        check("a log missing at a revision is refused, naming the side",
              msg is not None and "does not exist at base" in msg)

    # KEEP's bytes, when the shared entries merge to KEEP's own: a joint KEEP
    # wrote its own way (two blank lines before its separator) is kept as
    # written, not rebuilt in the tool's style.
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        collide(r, g, "\n\n---\n\n## 003. Keep three\n\nkeep body\n",
                "\n## 003. Move three\n\nmove body\n")
        keep_log = g("show", "keep:kit/LESSONS.md").stdout
        plan, msg = try_plan(r)
        check("KEEP's log comes through byte for byte, its own joint included",
              msg is None and plan.new_lessons.startswith(keep_log)
              and plan.new_lessons.endswith("\n\n## 004. Move three\n\nmove body\n"))

    # No block on a side adds nothing for it: no joint, no blank line.
    for keep_adds in (False, True):
        with tempfile.TemporaryDirectory() as tmp:
            r, g = fork(tmp)
            base = g("rev-parse", "HEAD").stdout.strip()
            g("checkout", "-q", "keep")
            if keep_adds:
                w(r, "kit/LESSONS.md", KEEP, append=True)
            w(r, "kdoc.md", "keep\n")
            commit(g, "keep")
            keep = g("rev-parse", "HEAD").stdout.strip()
            g("checkout", "-q", "move")
            w(r, "mdoc.md", "move\n")
            commit(g, "move")
            move = g("rev-parse", "HEAD").stdout.strip()
            plan = build_plan(r, "kit", base, keep, move)
            want = BASE_LOG + (KEEP if keep_adds else "")
            check("with no block appended on the moving side"
                  + (" (KEEP appends one)" if keep_adds else " or the kept one")
                  + ", the log is KEEP's exactly", plan.new_lessons == want)

    # ...and when the prefix is REBUILT (MOVE amended a shared entry), the joint
    # is KEEP's style: no separator where KEEP wrote none.
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        g("checkout", "-q", "keep")
        w(r, "kit/LESSONS.md", KEEP, append=True)
        commit(g, "keep")
        g("checkout", "-q", "move")
        w(r, "kit/LESSONS.md", read(r, "kit/LESSONS.md").replace(
            "body one\n", "body one\n  a follow-up\n") + "\n## 003. Move three\n\nmove body\n")
        commit(g, "move")
        g("merge", "--no-edit", "keep", ok=False)
        plan, msg = try_plan(r)
        check("a rebuilt prefix joins KEEP's block the way KEEP does: no `---` it never wrote",
              msg is None and "a follow-up" in plan.new_lessons
              and "## 003. Keep three" in plan.new_lessons and "---" not in plan.new_lessons)

    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        collide(r, g, KEEP, "\n## 003. Move three\n\nmove body")
        plan, msg = try_plan(r)
        check("a moved block with no final newline still ends the log with one",
              msg is None and plan.new_lessons.endswith("## 004. Move three\n\nmove body\n"))

    # An ORPHANED number is reviewed wherever the moving side cites it: in an
    # old entry and in another file, not only in its own appended block.
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        g("checkout", "-q", "move")
        w(r, "kit/LESSONS.md", "\n## 003. Gone lesson\n\nnever landed\n", append=True)
        commit(g, "gone")
        w(r, "kit/LESSONS.md", read(r, "kit/LESSONS.md").replace(
            "body one\n", "body one\n  see also LESSONS #003\n"))
        w(r, "kit/LESSONS.md", "\n## 004. C lesson\n\nC body\n", append=True)
        w(r, "odoc.md", "cites LESSONS #003.\n")
        commit(g, "C")
        g("checkout", "-q", "main")
        w(r, "kit/LESSONS.md", "\n## 003. M lesson\n\nlanded first, and different\n",
          append=True)
        commit(g, "main")
        g("cherry-pick", "move", ok=False)
        plan, msg = try_plan(r)
        check("an orphaned number is reviewed in an old entry and in another file too",
              msg is None and plan.orphaned == [3] and plan.mapping == {}
              and any(x.startswith("odoc.md:1:") for x in plan.review)
              and any("see also LESSONS #003" in x for x in plan.review))

    # A conflicted file that cites no moved number is the merge's to finish,
    # and must not block the renumber.
    with tempfile.TemporaryDirectory() as tmp:
        r, g = fork(tmp)
        collide(r, g, KEEP, "\n## 003. Move three\n\nmove body\n",
                keep_files=[("notes.md", "keep: see issue #7\n")],
                move_files=[("notes.md", "move: see issue #8\n")])
        conflicted = "<<<<<<<" in read(r, "notes.md")
        plan, msg = try_plan(r)
        check("a conflict in a file citing no moved number does not block the renumber",
              conflicted and msg is None and plan.mapping == {3: 4})

    check("a line already there at the fork is KEEP's, even when MOVE has it too",
          provenance("x", {"x"}, {"x"}, {"x"}) == "keep")

    # --- widths: `#9` -> `#10` grows the text under the edit after it --------
    check("a replacement wider than its original does not corrupt the next edit",
          apply_edits("(LESSONS #9, #9)", strict_edits("(LESSONS #9, #9)", {9: 10}))
          == "(LESSONS #10, #10)")

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # `| head` closed the pipe: the reader has what it wanted. Redirect so
        # the interpreter's own flush at exit does not print a second error.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
