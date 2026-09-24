# Retrospective — the repo-cleanup arc (2026-09-16 → 2026-09-20, PRs #81–#96)

Written 2026-09-24, four days after the last PR merged, and measured against
`master` at `1516da8` rather than recalled. Companion to `RETROSPECTIVE-lsof.md`,
which covers the port itself; this one covers the side quest that was meant to
tidy the repository around it.

The brief was: *delete files that do not relate to the C→Rust rewrite — stale
files, and files that reference other files.* The boundary the arc settled on
early, and kept: the C tree is the **differential oracle**, not legacy. A file
stays if it builds, tests or documents the oracle or the port. "C versus Rust"
was never the test.

## The headline

**One PR did the cleanup. Ten PRs proved it, and repaired the checks that should
have.**

| | |
|---|---|
| PRs merged | **11** — #81, #82, #83, #84, #86, #87, #89, #90, #91, #94, #96 |
| deleted | **128 files / 31,272 lines**, every one of them in #81 |
| added afterwards | ~2,060 lines across the other ten PRs, almost all of it controls and their tests |
| lessons | **11 new entries** (#027–#035, #049, #054), plus the restored heading of #022, which had been silently deleted |
| controls built | 5 — sanitizer ledger reads executable text; citation lists and ranges are parsed; citations are checked repo-wide; triggers corrected in both directions; a platform ledger |

Per PR, as each merge brought it in:

| PR | + | − | what it was |
|---|---|---|---|
| #81 | 131 | 31,272 | the deletion |
| #82 | 109 | 0 | reachability and manifest lessons (#027, #028) |
| #83 | 352 | 3 | wired `check-kit` into CI; lesson cross-reference checker; restored #022 |
| #84 | 36 | 62 | fixed #81's `./Configure` regression, plus a `-n`-free CI guard |
| #86 | 77 | 178 | `00README` and friends stopped documenting deleted scripts (#030) |
| #87 | 179 | 5 | sanitizer ledger reads jobs, not prose (#031) |
| #89 | 237 | 7 | citation lists and ranges (#032) |
| #90 | 232 | 41 | citation scan reaches the host repo (#033) |
| #91 | 202 | 14 | path filters, both directions; the kit template corrected (#034, #035) |
| #94 | 72 | 1 | CI providers, not check runs (#049) |
| #96 | 563 | 8 | the platform ledger (#054) |

## What held up

Re-run on `master` four days and 42 commits later — every control the arc built
is present and green:

- lesson refs: `62 entries, 508 citations in 72 files, 0 problems` — the scan
  has grown with the repository, from 216 citations in 50 files when built
- platform ledger: `7 selectable, 5 built by CI, 2 waived, 8 CI configs, 0 problems`
- `lsof-rs` ledgers: `5 present, 0 missing`
- the lesson log: 62 entries, unique, contiguous

## The pattern

Every one of the eleven PRs found the same thing: **a check that reported on
something adjacent to what it claimed to check.** Four forms:

| form | instances |
|---|---|
| **nothing ran it** | `00MANIFEST` (223 of 280 entries dangling, read by nothing); `check-kit` never wired to CI |
| **it read the wrong thing** | the sanitizer ledger accepted a comment as evidence; a citation list read as its first number; the platform ledger certified `darwin` from a comment on its first run |
| **it saw too little** | a kit-only citation scan (52 of 214 citations unchecked); the GitHub status list taken as the set of gates, when three platforms are gated on Cirrus and sourcehut |
| **it couldn't be woken** | `build.yml` over-triggered; the differential under-triggered on its own oracle |

A green board looks identical in all four cases, which is why CI found none of
them. Each was found by asking what a gate actually *reads*.

## Errors made by the arc itself

**Four reached `master`**, each fixed by a later PR in the arc:

1. **#81 broke `./Configure linux`.** Verified only with `-n`, the flag
   `Configure` documents as skipping exactly what #81 deleted. Fixed in #84.
2. **#84 called `00README` "inert prose"**, classified by its neighbours
   instead of being read. Fixed in #86.
3. **The lesson checker built in #83 read only the head of a citation list.**
   Fixed in #89.
4. **The same checker scanned only the kit.** Fixed in #90.

**About eight more were caught before merge:** a global `sed` that edited the
append-only log; deletions that broke `case-14` and the legacy build
(`tests/Makefile`, `lib/ptti.c`); a fabricated `PRs #81–#85` citation; a scope
estimate of 17 that was 19; "one citation" that was 52; a branch reset that would
have emptied the still-open #91; the `darwin` comment.

Nearly all share one cause: **a measurement trusted before its instrument was.**
A `-n` build, a line-oriented grep, a truncated `grep | head`, a single grep hit,
one provider's status list. The arc wrote that down as LESSONS #032 and repeated
it the next day, which became LESSONS #033 — *writing a lesson does not put it in
force; a check does.*

## What did not close

1. **#91's oracle trigger has never fired live.** No commit in the four days since
   has touched an oracle source (`src/`, `lib/`, `include/`, `m4/`, `autotools/`,
   `configure.ac`, `Makefile.am`, `version*`). The claim rests on a simulator of
   GitHub's path matching, validated against five real PRs first. Good evidence;
   not proof.
2. **Lesson-number collisions are structural.** `master` records at least eight,
   two from this arc. LESSONS #048's procedure — first to land keeps its numbers,
   the other block shifts as a unit, the renumber scoped to files citing the moved
   entry — resolves each one, but by hand at every merge, and nothing prevents
   the next. An append-only log with a shared counter and several concurrent
   writers will keep colliding.
3. **"A vendored kit cannot see its host" was fixed per harness.** Four days
   after #90, another session found the same blind spot in
   `check_lessons_pinned` and fixed it by copying `--also-scan`, spelling
   included. The fix spread by imitation; the class is still open for the next
   harness that walks files.
4. **`aix` and `sun` remain waived** — kept as source on the owner's decision,
   gated by nothing. The platform ledger keeps that waiver honest: if either ever
   gains a CI job, the waiver is reported stale.

## What would be done differently

- **Validate the instrument before reporting the number.** Diff old against new
  over the real corpus instead of grepping for what you expect.
- **When fixing an instance, sweep for the class.** Several of these defects were
  members of a class already fixed once.
- **Treat a branch reset as destructive while that branch has an open PR.**
- **Weigh the investigation, not the diff.** The arc's best outcome was the
  dialect decision: asked to delete six "unused" dialects, measurement showed four
  were live tested platforms — three on providers no GitHub check displays — and
  the result was a table and an empty diff.

## Recommended next steps, highest value first

1. **Fix lesson numbering at the source** — stop allocating numbers on branches,
   e.g. a placeholder that a merge-time step numbers. A design decision about the
   log's workflow.
2. **Live-fire #91's trigger** — a PR that changes only a comment under `lib/`,
   confirming `differential (linux, vs the C)` appears. Closes the arc's last
   untested claim.
3. **One host-aware scan-root helper** shared by every harness that walks files,
   so none can be written blind to the repository it is vendored into.
