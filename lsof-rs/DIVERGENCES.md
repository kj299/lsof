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

## Ledger (read by `diff_run.py`)

- [x] files-mem-rows: DEBT (L2) — the C emits one `mem` row per mapped library
  from `/proc/<pid>/maps`; the Linux backend does not read `maps` yet. Every
  other file case passes `-d ^mem` so it measures its own surface.
- [x] files-offset-o: DECISION — with `-o` the C changes the header to `OFFSET`
  and prints an empty cell for `cwd`/`rtd`/`txt` (no fdinfo, no offset);
  lsof-rs keeps `SIZE/OFF` and falls back to the size. Shared renderer
  (`lsof-core`), so it changes Windows output too; not a backend fix.
- [x] files-fields-F: DECISION — `-F` default field set. The C emits `g` (pgid),
  `u` (uid), `G` (file flags), `l` (lock), `D` (device as hex) and *empty*
  `a`/`l` fields; lsof-rs emits none of those and `d` (`maj,min`) where the C
  emits `D`. Model and renderer gaps shared with Windows.
- [x] files-or-semantics-no-a: DECISION — lsof ORs list options unless `-a`
  (Lsof.8 §OPTIONS: "list options that are specifically stated are ORed";
  `-a` "causes all list selection options to be ANDed"). lsof-rs ORs the
  *process* selectors (`-p -c -u -g`) unless `-a`, matching the C, but applies
  *file-level* selectors (`-i`, `-d`, `-U`, paths) unconditionally. So
  `lsof -d ^mem -p PID` lists the whole host in the C and one process in
  lsof-rs. Deliberately the only un-`-a`'d case, so the divergence stays
  visible in every run.

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

## Recorded for decision — shared output, found by the Linux oracle

These change what the **Windows** binary prints too, and each alters output the
golden fixtures and the 59-case smoke suite assert. Matching the C is very
likely right; it is a compatibility decision, not a backend phase.

| # | The C | lsof-rs | Where |
|---|---|---|---|
| 1 | `(QR=0 QS=0)` | `(QR=0) (QS=0)` | `-T` suffix shape · `docs/known-limitations.md` |
| 2 | `-Tq` replaces the state | keeps `(ESTABLISHED)`, appends | `-T` semantics · `docs/known-limitations.md` |
| 3 | `COMMAND` truncated to 9 | not truncated | default column width · `docs/known-limitations.md` |
| 4 | list options ORed unless `-a` | file-level selectors always ANDed | selection engine · `files-or-semantics-no-a` above |
| 5 | `-F` emits `g u G l D`, empty `a`/`l` | omits them; `d` for `D` | `-F` renderer + model · `files-fields-F` above |
| 6 | `-o` → header `OFFSET`, blank when unknown | header unchanged, falls back to size | renderer · `files-offset-o` above |
| 7 | `8uW` — `W` marks a write lock on the fd | `8u` | lock column; Linux source is `/proc/locks` (L2), Windows has byte-range locks |
| 8 | `TYPE a_inode`, NAME `[eventpoll:7,9,…]` | `unknown`, `anon_inode:[eventpoll]` | DEBT (L2), Linux: named anon_inode kinds |
| 9 | a directory fd from `opendir` shows access `u` | `r` | **open question** — fdinfo `flags` say read-only; find how the C derives `u` before deciding which side is right |

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
