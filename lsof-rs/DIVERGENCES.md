# DIVERGENCES — where lsof-rs knowingly differs from the C `lsof`

The porting kit's intentional-divergence ledger (PLAYBOOK Phase 2; LESSONS
#019 found this port had reached 1.0 without one). Two things live here:

1. **The ledger the differential reads.** `porting-kit/harnesses/differential/
   diff_run.py` harvests lines of the form `- [x] case-name: reason` and reports
   a divergence in that case as `DIVERGE(ledgered)` instead of failing. A case is
   listed here only for a **known, reasoned** difference — never to make a run
   green. Each entry names who closes it: a phase (`DEBT (Lx)`), or a decision
   (`DECISION`) that changes shared output and is the maintainer's to make.
2. **The record.** Every difference found, including the ones that were fixed
   the day they were found, so the gate's history is legible.

Since 2026-09-02 the Linux differential (`differential/linux_diff.py`) runs the C
built from **this tree** (4.99.6) against lsof-rs on the same fixtures, on every
Linux CI run. The Windows side has no such oracle; see `differential/README.md`
for its oracle-substitution mode.

A third kind of entry exists since 2026-09-04: **`C-DEFECT`** — a divergence
where the C is wrong and the port deliberately does not follow it (porting-kit
`CLAUDE.md`: "the C is a specification that may be buggy; do not faithfully
re-implement a vulnerability"). It stays ledgered because the oracle will keep
disagreeing, and it names the C code so anyone can check the triage.

## Ledger (read by `diff_run.py`)

- [x] files-offset-o: DECISION — with `-o` the C changes the header to `OFFSET`
  and prints an empty cell for `cwd`/`rtd`/`txt` (no fdinfo, no offset);
  lsof-rs keeps `SIZE/OFF` and falls back to the size. Shared renderer
  (`lsof-core`), so it changes Windows output too; not a backend fix.
- [x] files-fields-F: DECISION — `-F` default field set. The C emits `g` (pgid),
  `u` (uid), `G` (file flags), `l` (lock), `D` (device as hex) and *empty*
  `a`/`l` fields; lsof-rs emits none of those and `d` (`maj,min`) where the C
  emits `D`. Model and renderer gaps shared with Windows.
- [x] hostile-comm-utf8-table: C-DEFECT, not reproduced — the C sizes the
  COMMAND column with `safestrlen()` (`lib/misc.c`), which compares each
  `char` with `0x20`; `char` is signed on x86-64, so every byte ≥ 0x80 is
  sized as a 2-column escape while `safestrprtn()` prints 4 (`\xc3`). The
  printer then cuts the command to the undersized width: fixture D's comm
  `h^[[2J\r\x20\\\x7f\t\xc3\xa9\xc2\x9bz` loses `\xc2\x9bz` even under
  `+c 0`, which is documented to print every character. lsof-rs sizes and
  prints the same text. `hostile-comm-utf8-fields-Ffc` on the same comm
  MATCHes — `-F` has no column, so no width to get wrong. Platform-dependent
  in the C (an unsigned-`char` target such as aarch64 sizes correctly).

## Fixed by naming anonymous inodes (2026-09-05)

Item 8 below is closed. An epoll, eventfd, pidfd or inotify fd has no
filesystem identity at all — the kernel gives it a link target of
`anon_inode:<kind>` — and lsof-rs typed those `unknown` and printed the raw
target. The C types them `a_inode`, drops the prefix, and prints the kind.

Three kinds carry an identity in `fdinfo` that the C substitutes in
(`lib/dialects/linux/dproc.c:1283-1301`), and each had to be measured rather
than guessed:

- **`[eventpoll:4,6]`** — the `tfd:` lines, which are the fds the epoll is
  watching. `fdinfo` lists them most-recent-first and the C sorts them
  ascending, so a fixture with a single registration would not have tested the
  sort. Capped at 32 with a trailing `...`, the C's `EPOLL_MAX_TFDS`.
- **`[eventfd:6]`** — `eventfd-id`. Not the counter (`eventfd-count`, 7 in the
  fixture) and not the fd number (8): three plausible readings, one right, and
  only running the C separates them.
- **`[pidfd:4242]`** — the `Pid:` line, the process the pidfd refers to.

Everything else keeps its bare kind: `inotify` prints as `inotify`, with no
brackets, because that is what the kernel wrote after the colon.

`parse_fdinfo` now returns a struct rather than a pair, since an fd's fdinfo
carries these three identities as well as the access mode and offset. Verified
against the C by a new fixture holding one of each kind at once
(`anon-inode-kinds`), and the `proc_fdinfo` fuzz target gained the invariants
that keep the NAME cell bounded and ordered: the tfd list is capped at 32 and
sorted, the `anon_inode:` prefix is always dropped, and a name that differs
from the bare kind is an enrichment of it rather than something new.

## Fixed by reading /proc/locks (2026-09-05)

Item 7 below — the lock character on the FD cell — is closed on Linux. `lsof`
prints `3uW` for an fd holding a whole-file write lock, and that column is the
whole answer to "who has this file locked"; lsof-rs printed `3u`.

`/proc/locks` is one table for the whole system with a pid column, so it is read
once per gather and indexed by `(pid, device, inode)`. The kernel reports only
shared-vs-exclusive and the byte range, which is exactly the four characters
Linux can produce — `W`/`w` for a write lock on the whole file or part of it,
`R`/`r` for a read lock. (The C also knows `u`/`U` and the Xenix `x`/`X`, which
no Linux kernel can report; `LockKind` deliberately does not define them rather
than defining values nothing ever produces.)

Two details that would each have produced a *wrong* lock character, which is
worse than none — it claims a process holds a lock it does not:

- A line beginning `N: -> ` is a process **blocked waiting** for that lock, not
  one holding it. Counting it would put a `W` on the waiter's fd.
- An `OFDLCK` line reports pid `-1`: an open-file-description lock belongs to
  the description, not to a process, so there is no row to attach it to.

The device in `/proc/locks` is hex (`fe:00`) where every row in the backend
renders decimal (`254,0`), so the key is converted on the way in. Verified
against the C by a new fixture holding one of each of the four characters at
once (`locks-fd-suffix`), and fuzzed by `proc_locks`, which asserts the parser
invents nothing and that every key it emits is in the shape a built row can be
looked up by.

## Fixed by reading /proc/<pid>/maps (2026-09-05)

`files-mem-rows` is no longer ledgered debt: the Linux backend emits `mem` rows,
so it MATCHes. A mapping keeps a file open exactly as an fd does, and lsof lists
both. What the C does, established by running it rather than reading it:

- One row per **distinct file**, identified by the `(device, inode)` pair from
  the maps line and not by the path — a shared object is normally mapped four or
  five times, one segment per protection, and collapses to one row.
- In **maps order** (ascending address), between the `txt` row and the numbered
  fds. The differential compares stdout byte for byte, so the order is part of
  the contract.
- The executable's own mapping is the `txt` row and is not repeated as `mem`.
- SIZE is the **file's** size from `stat`, not the mapping's length.
- A mapping whose file has been **deleted** is not a `mem` row at all: it is an
  `FdType::Deleted` (`DEL`) row carrying the device and inode from the maps
  line, with SIZE blank — there is nothing left to stat. This is the row
  `lsof | grep DEL` looks for after a package upgrade, to find the processes
  still running against the replaced shared objects. It cost a wrong first
  conclusion: `lsof -d mem` showed nothing for a deleted mapping, which looked
  like "the C skips it", until running without the filter showed the row under
  a different FD.

`mem` rows also made two things testable that were not: `files-table-with-mem`
compares the whole default table with mem rows in place, and `mappings-mem-and-del`
runs against a new fixture holding one live mapped library and one deleted while
still mapped. Both library copies have a space in the name, because a maps path
is the rest of the line and must never be split on whitespace — the `proc_maps`
fuzz target asserts that, along with "no row is invented", "every path is
absolute", "the kernel's ` (deleted)` marker never reaches a name" and "one row
per (device, inode)". 1.9M runs clean.

What the C prints and lsof-rs still does not: a mapping it cannot `stat`, and
one whose `stat` disagrees with the maps line, get a row with a
`(stat: ...)` or `(path inode=...)` name addition. lsof-rs omits rows it cannot
describe, the same deliberate choice it makes for an unreadable `/proc` link
(see "Deliberate, and staying").

## Fixed by rebuilding the selection engine (2026-09-05)

Item 4 below — lsof's OR-by-default list semantics — is closed. It was the
largest behavioural gap left, and it changes Windows output too.

The C's rule is a set membership test, not a chain of filters, and it lives in
seven lines (`lib/proc.c:is_file_sel`). Every file carries the set of selecters
it matched: it starts with the set its *process* matched (`lib/proc.c:178`,
`Lf->sf = Lp->sf`) and ORs in the file-level kinds it matches itself. Without
`-a` a file is listed when that set is non-empty; with `-a` the set must contain
every specified kind. `lsof-core`'s `selection::SelKinds` now models exactly
that, where before it ORed the process selecters and applied every file-level
selecter unconditionally.

Measured against the C, not inferred. The consequence nobody predicts, and the
one that proves the model: without `-a`, `lsof -d ^mem -p PID` lists the whole
host **including that PID's `mem` rows** — they inherit the PID kind even though
the fd selecter excluded them. Both binaries now agree at 11 rows, 4 of them
`mem`; adding `-a` gives 7 rows and none. Three further facts the source alone
did not settle, each measured:

- **`-d ^mem` is an inclusion.** The exclusion form sets the fd selecter's bit
  on every file it does *not* name (`lib/proc.c:223`), so on its own it selects
  the whole system minus `mem` rows rather than filtering something else.
- **`-s` is not a list option.** The C has no `SEL*` bit for socket state, so
  `-s` can only veto a row, never select one; its exclusion form is `SELEXCLF`,
  a veto that outranks even the OR.
- **A process failing its only process selecter is dropped outright**, but one
  failing *one of several* is not — it is still walked so its files can match
  file selecters (the `Selflags == SELPID` equality tests at
  `lib/proc.c:684-720`). The same asymmetry governs when a backend may skip a
  process, which is why `Selection::selects_process` had to change with it.

The gate changed shape too. `files-or-semantics-no-a` is gone: it ran a
whole-host command, and a whole-host command **cannot be gated**, because each
binary lists *itself* under a pid that differs every run — two consecutive runs
of the C do not even match each other. It is replaced by
`or-semantics-path-or-inet` and `or-semantics-path-and-inet`, which OR (and AND)
two selecters that each name exactly one fixture, so the result is two rows and
nothing on the host can drift into it. Both MATCH, stdout and exit code.

## Fixed by the renderer escaping (2026-09-04)

Item 10 below — found by the `proc_status` fuzz target, decided as the
security fix the kit's prime directive asks for — is closed. COMMAND, USER and
NAME now go through `lsof-core`'s `render::escape`, a port of the C's
`safestrprt()`/`safestrprtn()`/`safepup()`, in the table and in `-F`; the JSON
renderers, which already escaped the C0 range, now also escape DEL, the C1
controls and U+2028/U+2029. The Linux backend un-escapes the kernel's `\n` and
`\\` in `/proc/<pid>/status` so the model carries the raw comm the C reads from
`stat`, and both binaries escape the same bytes. Verified against the oracle
by four new fixtures-worth of cases (a file and two comms named with an ANSI
clear-screen, CR, space, backslash, DEL, TAB, `^A`, é and the 8-bit CSI
U+009B): `files-fd-4-hostile-name`, `files-fields-Ffn-hostile-name`,
`hostile-comm-table`, `hostile-comm-fields-Ffc`, `hostile-comm-utf8-fields-Ffc`
all MATCH byte for byte; `hostile-comm-utf8-table` is the C-DEFECT above.

Two things the oracle taught on the way, neither visible from the source:

- **COMMAND and NAME are printed by different functions.** `safestrprtn()`
  (COMMAND) has no wide-character path, so the column is always pure ASCII
  (é is `\xc3\xa9`) and a space is `\x20`; `safestrprt()` (NAME, `-F`) passes
  printable UTF-8 through in a UTF-8 locale and escapes only what
  `iswprint()` rejects. lsof-rs mirrors both, locale-independently, which is
  why the differential now pins `LC_ALL=C.UTF-8` for both binaries.
- **`+c 0` means no cap** (`CmdLim && len > CmdLim`); lsof-rs read it as a
  cap of zero and printed an empty COMMAND column. Fixed.

Two decisions where lsof-rs is deliberately *not* the C, both safer:

- **The backslash is escaped on Unix and is text on Windows.** The C doubles
  it so `\` `n` cannot pose as a newline; on Windows every NAME is `C:\…` and
  every domain user `DOMAIN\user`, so that rule would make the common case
  unreadable to close an ambiguity `-J`/`-j` already close. `Escaper::for_host`
  is the one platform-dependent line in the renderer.
- **USER is escaped too.** The C prints it raw (`printf`). Its source is
  root-controlled (`/etc/passwd`, the SAM), so this changes no real output;
  it removes the last cell the renderer trusted.

The `render_escape` fuzz target guards the property (no control character in
any output; COMMAND pure ASCII and whitespace-free; `+c` never splits an
escape) under both styles. Its first draft repeated the `proc_status` lesson:
it checked "no partial escape" by looking for a trailing `^` or `\`, and the
fuzzer disproved that in seconds with `\n\x1e`, whose escape `\n^^` ends in
`^` legitimately (0x1e + 0x40). The invariant was rewritten as "the cut is the
escaped form of the longest input prefix that fits", which is what the C's
`break` means. 1.9M runs clean after that.

## Fixed by the gate, before it was a gate (2026-09-02)

Found on the first fixture, fixed in the same PR that landed the harness —
both backend-local to `lsof-backend-linux`:

- **SIZE/OFF for character devices and FIFOs.** The C prints the offset
  (`0t0`); lsof-rs printed the size (`0`). `st_size` of a device node or pipe
  describes nothing, so the backend now withholds it and the shared renderer
  falls through to the offset — read from `/proc/<pid>/fdinfo`'s `pos:` line,
  which the backend was already opening for `flags:`. This also makes `-o` and
  the `-F o` field real on Linux.
- **`pipe` in NAME.** The C prints `pipe`; lsof-rs printed the raw link target
  `pipe:[12047]`. The inode is already the NODE cell.

## Fixed by the fuzz targets, before they were a gate (2026-09-03)

The Linux backend's four text parsers gained cargo-fuzz targets (`proc_net`,
`proc_status`, `proc_fdinfo`, `passwd`). Run for sixty seconds each before the
CI job that runs them was written:

- **`proc_net`: a panic in the IPv6 address decoder** — within seconds.
  `parse_addr` checked the host half was 32 *bytes* and then sliced it at
  8-byte offsets; a host made of multi-byte characters passes the check and is
  sliced mid-character. Hex digits are ASCII, so anything else is now rejected
  before indexing. The kernel would never write such a line, which is exactly
  why no test had — the contract is *no panic on any input*, not on
  well-formed input. Regression tests pin the misaligned case and the
  lossy-UTF-8 shape the fuzzer produced; the reproducer replays clean.
- **`proc_status`: a wrong invariant in the target itself** — also within
  seconds. The first draft asserted the command carried no `\r`; the fuzzer
  produced `Name:PPid:\rd:Uid:` and the parser returned it verbatim, which is
  correct: `lines()` splits only on `\n`, and the kernel escapes only `\n` and
  `\\` in `/proc/<pid>/status`. Not a parser bug. What it *is* is item 10 in
  the table below — a renderer decision this port has not made.
- `proc_fdinfo` and `passwd`: clean at 1.4 and 1.5 million cases.

## Recorded for decision — shared output, found by the Linux oracle

These change what the **Windows** binary prints too, and each alters output the
golden fixtures and the 59-case smoke suite assert. Matching the C is very
likely right; it is a compatibility decision, not a backend phase.

| # | The C | lsof-rs | Where |
|---|---|---|---|
| 1 | `(QR=0 QS=0)` | `(QR=0) (QS=0)` | `-T` suffix shape · `docs/known-limitations.md` |
| 2 | `-Tq` replaces the state | keeps `(ESTABLISHED)`, appends | `-T` semantics · `docs/known-limitations.md` |
| 3 | `COMMAND` truncated to 9 | not truncated | default column width · `docs/known-limitations.md` |
| 4 | list options ORed unless `-a` | ~~file-level selectors always ANDed~~ **resolved 2026-09-05** | selection engine; see "Fixed by rebuilding the selection engine" above |
| 5 | `-F` emits `g u G l D`, empty `a`/`l` | omits them; `d` for `D` | `-F` renderer + model · `files-fields-F` above |
| 6 | `-o` → header `OFFSET`, blank when unknown | header unchanged, falls back to size | renderer · `files-offset-o` above |
| 7 | `8uW` — `W` marks a write lock on the fd | ~~`8u`~~ **resolved on Linux 2026-09-05** | lock column, from `/proc/locks`. Windows still shows none: `FsRtlGetNextFileLock` is kernel-mode and nothing in user mode enumerates another process's locks (`docs/known-limitations.md`). |
| 8 | `TYPE a_inode`, NAME `[eventpoll:7,9,…]` | ~~`unknown`, `anon_inode:[eventpoll]`~~ **resolved 2026-09-05** | Linux: named anon_inode kinds; see "Fixed by naming anonymous inodes" above |
| 9 | a directory fd from `opendir` shows access `u` | `r` | **open question** — fdinfo `flags` say read-only; find how the C derives `u` before deciding which side is right |
| 10 | non-printable bytes in a name are escaped (`safestrprt()`) | ~~printed raw~~ **resolved 2026-09-04** | renderer, both platforms. Found by the `proc_status` fuzz target: a `\r` in `Name:` survives the parser verbatim, as it must (the kernel escapes only `\n` and `\\` there), and reached the COMMAND column raw — a process named with an ANSI escape sequence drove the terminal of whoever ran lsof-rs. Closed as the C does it; see "Fixed by the renderer escaping" above. |
| 11 | `-F` emits the `f` marker only when selected (`-Fcn` → `p`, `c`, `n` lines) | `f` on every file, whatever the selection | `-F` renderer. Lsof.8: only `p` is "always selected". Found while writing the hostile-name `-F` cases, which select `f` explicitly (`-Ffc`, `-Ffn`) so they compare the escaping and not this. **DECISION** — a Windows `-F` consumer that selects fields without `f` sees `f` lines today. |

| 12 | option parsing **stops at the first non-option argument**, so `lsof FILE -iTCP:N` reads `-iTCP:N` as a second *filename*, does not find it, and exits 1 | permutes: `-iTCP:N` is an option wherever it appears | `lsof-cli`'s argument parser. Found by the `or-semantics-*` cases, whose first draft put the path first and diverged for this reason rather than the one they test. **DECISION** — matching the C would make command lines that work today stop working, so it is recorded rather than changed alongside the selection fix. |

| 13 | `lsof -c ^name` **exits 1** even on a successful listing (1522 rows here), while `lsof -u ^name` exits 0 | both exit 0 | exit status. The C counts a negated `-c` as a search item it never located, and a negated `-u` not at all — an asymmetry between two options the man page describes identically, which is why this reads as an accident rather than a design. lsof-rs copies the half that is defensible: an *excluded* process does not count as a located `-p`, so `-c ^sleep -p <that sleep>` exits 1 in both. **C-DEFECT**, not reproduced. |

Items 4–9 were found by the Linux differential in one afternoon, on fixtures of
a dozen open files. None was visible to the Windows smoke suite or the golden
tests, because a golden test pins what its author believed the C emits.

## Deliberate, and staying

- **No hostname or service resolution.** lsof-rs behaves as if `-n -P` were
  always given; both flags are accepted as no-ops. Resolution costs DNS traffic
  from a diagnostic tool, which is a poor default for where this runs. The
  differential passes `-n -P` to the C for parity.
- **Inaccessible files are omitted, not reported with an errno.** The C emits a
  row such as `txt unknown /proc/2/exe (readlink: Permission denied)`; lsof-rs
  emits nothing for a link it cannot read. Matching it means reproducing
  libc's errno strings — DEBT (L2), tracked in the coverage inventory as the
  `UNKN*` TYPE codes.

## The C-flaw scan — 127 findings, UNTRIAGED

`porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py ../src ../lib` reports, on
this tree: 94 `int-overflow-mul`, 24 `unbounded-copy`, 8 `format-string`,
1 `command-exec`. The kit's rule is that each is triaged into this file as
"closed by the port" (Rust's checked arithmetic, bounded `Vec`s, no `printf`)
or "not applicable". **That triage has not been done.** It is listed here so the
gap is a line in the ledger rather than an absence — the retrospective found the
absence had gone unnoticed through three releases (LESSONS #019). The Windows
backend's 139 `unsafe` blocks are individually documented (`audit_unsafe.py`
139/139) but have never been run under a sanitizer; the Linux backend and the
core have none.

The scan has no pattern for the defect the differential found on 2026-09-04
(`safestrlen()`: a signed `char` compared with `0x20`, so bytes ≥ 0x80 take the
wrong branch). A `signed-char-compare` rule — `char` variables or `*p` derefs
of `char *` compared against a numeric literal without an `(unsigned char)`
cast — would have flagged it and its siblings; it is a candidate for the kit's
next retrospective, recorded in LESSONS #023.
