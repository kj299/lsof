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
- [x] path-bare-hardlink: DECISION — the NAME cell only. Both binaries find
  the same fd on the same inode when a file is queried through a hard link;
  they disagree on what to call it. The C substitutes **the name you asked
  about** (`hard.txt`) into NAME, lsof-rs prints **the name the process
  actually opened** (`f.txt`). The C's choice also makes its exit status
  depend on which name it bound first — with two names for one inode in a
  `+d` expansion, the other is reported unlocated and the run exits 1. See
  item 17.
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

## The Windows unsafe layer, under a sanitizer at last (2026-09-12)

Not a divergence — the last of the four playbook exit criteria this port had
never executed. The miri job covers `lsof-core` and `lsof-cli`, the two crates
that forbid unsafe entirely; the Windows backend's ~150 `unsafe` blocks, each
an FFI call handing Win32 a buffer this code sized itself, had never been under
any sanitizer.

`asan-windows` runs the backend's tests and one real run of the binary under
`-Zsanitizer=address` on `x86_64-pc-windows-msvc`. The test that matters is
`enumerates_real_kernel_object_types`: it creates an event, a mutex, a section
and a token, then walks the live handle table through the same unsafe
enumeration the binary uses — so the buffers those calls fill are the buffers
ASan is watching.

### The canary, and why the job has one

A sanitizer job that reports nothing is indistinguishable from a job that never
instrumented anything. A mistyped `RUSTFLAGS`, a missing `--target` (which would
leave the sanitizer on the build scripts and off the code), an ASan runtime DLL
that failed to load — every one of those ends in a green job that checked
nothing. This project already knows that failure mode from the inside: it is
exactly how the kit's sanitizer gate came to be declared-but-never-run
(LESSONS #019).

So the job's **first** step builds `tests/asan_canary.rs` — a test that reads
one byte past a four-byte heap allocation, behind a feature nothing else sets —
and requires the run to abort with an `AddressSanitizer` diagnostic. If the
canary survives, the step fails with `CANARY SURVIVED` and the job stops before
it can say anything reassuring about the real code.

### Observe-first, and what is deliberately NOT claimed

It lands non-blocking, on the kit's promotion rule (LESSONS #13): consecutive
log-verified green runs, read from the step log rather than the job status,
before it becomes a hard gate. This one could not be validated locally the way
the miri job was — there is no Windows here, and every detail of it (the
nightly's ASan support on the MSVC target, the `vswhere` path to
`clang_rt.asan_dynamic-x86_64.dll`, GitHub's pwsh appending `exit
$LASTEXITCODE` to a step whose command is *supposed* to fail) was written
blind. Observe-first is doing real work here rather than ceremony.

`progress.json` still reads `differential` for `lsof-backend-windows`, on
purpose: a gate is not passed until it has actually run, and advancing the row
on the strength of a job that has never executed would be the same bookkeeping
this ledger exists to prevent.

### First run, read from the log

    AddressSanitizer: heap-buffer-overflow on address 0x110bbc4a2050 at pc …
    canary caught: ASan is live

then both real steps clean. So the sanitizer is genuinely instrumenting, the
runtime DLL resolved, and the gate has demonstrated it can fail — which is the
only evidence that makes a clean run mean anything. One green run of the three
the promotion rule asks for.

## Fixed by asking the socket's own namespace (2026-09-12)

Closes item 16, whose stated cause was wrong, and turns up two more things.

`/proc/net/*` shows the **calling** process's network namespace, so a socket
inside a container is an inode no local table explains. The C prints

    python3 5753 root 3u  sock  0,9  0t0  34280  protocol: TCP

— a lowercase `sock`, the OFFSET rather than a size, and a NAME that gives the
protocol and no address. lsof-rs printed `SOCK  0,9  0  34280  socket:[34280]`,
differing in all three cells.

### Where the C gets that protocol, and why it matters

Item 16 said "the C reads the target's own `/proc/<pid>/net/*`" and framed the
fix as a cost-model change: tables read once per namespace instead of once per
run. That is not what the C does. `dsock.c` falls back to a single

    getxattr(path, "system.sockprotoname", …)

on the fd — which is why it can name the protocol without knowing the address,
and why it costs one syscall per unidentified socket rather than anything
per-namespace. Reading the source after measuring the output is what caught
it: an implementation that read the namespace's table would have had the
address and printed it.

lsof-rs now reads the owning process's own `/proc/<pid>/net/*`, cached by the
namespace itself (`readlink /proc/<pid>/ns/net`) rather than by pid, so a
hundred processes in one container read its tables once, and a pid cache keeps
a process with many unresolved sockets to one `readlink`. It takes the
**protocol name only** from that table and deliberately drops the address it
learns on the way, because matching the C is the contract — a mutant that
prints the address is one of the five that turn these cases red.

### The cost, measured rather than feared

| | before | after |
|---|---|---|
| `lsof -i`, whole host | 5.9 ms | 6.9 ms |
| `lsof`, whole host | 19.2 ms | 20.0 ms |

Nothing is read on a host where every socket resolves locally; the cost above
is one namespace's seven table files on a host that has two. Peak RSS is
unchanged at ~10.1 MB, and the port stays faster than the C (20.0 against
22.1 ms).

### Two more things

**`-i` is a search item.** `main.c` holds `Fnet` at 1 until some saved row
carries `SELNET`, and `if (Fnet && Fnet < 2)` at the end is a search failure —
so `lsof -a -i -p 1` exits **1**, with `-V` saying `no Internet files located`,
even though pid 1 exists and was located. lsof-rs exited 0. `-U` has no
equivalent rule, which is what makes this about the inet selector and not about
sockets generally. Ten shapes were measured, including `-iTCP:65533`, `-i6` and
`-iUDP` against a host that has a v4 TCP listener and nothing else.

**A family with no table at all stays unresolved** — item 22. This host holds an
AF_VSOCK socket, which the C names from the xattr and no `/proc/net` file
lists. It is in the **caller's own namespace**, so it is not what item 16 was
about, and the namespace fallback cannot reach it. Closing it needs `getxattr`,
which has no `std` API: that means `unsafe` FFI or a dependency in a crate
documented as needing neither. Recorded for a decision rather than taken.

### What the gate gained

Fixture **J** — a listener inside its own network namespace, the first fixture
whose sockets are invisible to the caller's `/proc/net`. It needs
`CAP_SYS_ADMIN` for `unshare --net`, so the harness **skips** its three cases
where that is unavailable rather than failing: a missing capability is neither
a divergence nor a broken harness. Five mutants, every case killed by at least
one, two of them by exactly one:

| mutant | cases it kills |
|---|---|
| no namespace fallback (the old behaviour) | the table and `-F` cases |
| TYPE stays `SOCK` | the table and `-F` cases |
| a size instead of the offset | the table case — and only that |
| drop the `-i` search-item rule | the `-i` case — and only that |
| print the address the table reveals | the table and `-F` cases |

## Fixed by making the search-item contract the C's (2026-09-12)

Closes item 19, and the sweep around it found three more things — two fixed
here, two recorded as items 20 and 21.

A path argument is `stat()`ed once, up front. The failure is reported with its
errno and the argument is **dropped**; whether that is fatal depends on how many
survived. `ck_file_arg` returns non-zero only on `!ss` — no search item was
created at all — and `main.c` answers that with `Error()`, which exits *before*
the listing runs. So:

| command | C |
|---|---|
| `lsof /nope` | message, nothing listed, exit 1 |
| `lsof /a/real/file /nope` | message, the real file's rows, exit 1 |
| `lsof -p 123 /nope` | message, **nothing listed**, exit 1 |
| `lsof -Q /nope` | silent, nothing listed, exit **0** |

The third line is what item 19 named: the `-p` never gets its turn, because
argument processing gave up first. lsof-rs had printed its rows. The second line
is what the entry got wrong — it said the failure is fatal full stop, and
lsof-rs already matched there.

### `-Q` mutes the status, not just the message

The bigger gap, and the one scripts actually feel. `-Q` clears `ErrStat` and
never sets `LSOF_SEARCH_FAILURE`, so `lsof -Q /nope`, `lsof -Q /an/unopened/file`
and `lsof -Q -p 999999` all exit **0**. lsof-rs had suppressed the message alone
and still exited 1, which is the half that `if lsof -Q …; then` branches on.

### `-V` narrates on stdout, in the C's words

Every "not located" line in `main.c` is a `printf`, not an `fprintf(stderr, …)`:
`lsof: no file use located: <path>`, `lsof: process ID not located: <pid>`.
lsof-rs wrote its own wording to stderr, so a consumer redirecting stdout got
the table and none of the explanation. And `+d`/`+D` reach the C through
`enter_dir()` rather than `ck_file_arg()`, so an unstattable directory there is
a `WARNING: can't stat(…)` on stderr and the run continues — the opposite of a
bare path. lsof-rs had said nothing at all, which made a typo'd `+d` path look
like an empty directory.

### What the gate gained

Fifteen differential cases, and the first `-V` or `-Q` in any of them: the suite
had 69 cases and exercised neither option. Seven mutants; every case is killed by
at least one:

| mutant | cases it kills |
|---|---|
| never fatal (the old behaviour) | the `-p` case, and `-V` on a bad path |
| fatal whenever ANY path fails | the two "one good path survives" cases |
| only the FIRST failure recorded | `all-paths-unstattable` — and only that one |
| `-V` messages back to stderr | the two `-V` reporting cases |
| `-Q` stops muting the status | all four `-Q` cases |
| an unlocated path stops counting | five, including `unlocated-path-exits-1` |
| drop the `+d`/`+D` guard | `plus-d-supplies-a-surviving-item` — and only that |

Two cases had to be rewritten before a mutant could kill them, which is
LESSONS #026 again. `all-paths-unstattable` was first written as
`lsof {NOPE} {NOPE}x`: with no other selector, "every path is bad" prints
nothing whether or not the run aborts, so it could not fail. Adding `-p {A}`
gave it something to lose. And `plus-d-supplies-a-surviving-item` first named
`{ADIR}`, where the C drops four entry rows to the defect now ledgered as item
20 — so it was measuring that defect, not the abort rule. It names `{ASUB}`
now, which is open and empty.

## Fixed by listing tasks the way the C decides to (2026-09-07)

Closes item 18. A Linux task is not a decoration on a process row: `CLONE_FS`
and `CLONE_FILES` are optional, so a thread can hold its own cwd, root and fd
table, and lsof models it as a **process entry of its own** that repeats the
whole file set. On fixture I — a `python3` with two `prctl(PR_SET_NAME)`
threads — `-K` is 22 rows against 8, and 49 against 17 with `mem` rows included.

### The ledger entry was wrong about the rule

Item 18 said the C "lists threads by default". It does not. The C lists them
when **nothing at all** is selected (`main.c` leaves `Selflags == SelAll`); give
it any selector — `-p`, `-u`, `-c`, `-i`, `-d`, or a path — and tasks disappear,
`TID`/`TASKCMD` columns included. The whole-host count the entry was written
from (1052 rows vs 261) is consistent with both readings, so it never tested
the claim. Ten forms were measured this time, and the header's `TID` column is
the tell:

| form | C lists tasks |
|---|---|
| `lsof` (nothing selected) | yes |
| `-d ^mem`, `-u root`, `-p N`, `-c name`, `-i`, a path argument | **no** |
| `-K`, `-K -p N` | yes |
| `-K i` | no |

So the model is three-valued, not a flag: *when unselected* (the default),
*always* (`-K`), *never* (`-K i`). `-K` also joins the OR — `lsof -K -p N`
prints N's rows **and** every other process's tasks, because the two selectors
are ORed — but it is dropped from the `-a` requirement, since `lsof -K -a -p N`
still shows N's own entry alongside its tasks.

### Two argument-parsing bugs the sweep found

`-K` had been read as "take the next word only if it is exactly `i`". The C
(`main.c` case `'K'`) takes the next word **whatever it is**, and pushes it back
only when it opens an option (`*GOv == '-' || *GOv == '+'`):

* **`lsof -K /var/log` listed the whole host** instead of exiting 1. The C
  rejects the path as `-K`'s argument; lsof-rs left it as a *name* to look up,
  and the bare `-K` then selected every task on the box.
* **`-K I` was rejected.** The C compares with `strcasecmp`.

Both were invisible to the first draft of the gate. `-K x` — the obvious case to
write — passed for the wrong reason: `x` is a name that matches nothing, so
lsof-rs also exited 1 with no output. It took a mutant that accepted any
argument to show the case was measuring nothing, and a path argument to make the
divergence visible at all.

### Windows is deliberately narrower

The Windows backend lists tasks on an explicit `-K` only, not on the C's
"nothing selected" default. A Linux task holds files, so the default listing
would otherwise miss them; a Windows `THRD` row holds none — it is a thread
inventory. Turning it on by default would put one contentless row per thread,
hundreds on an idle box, into every bare `lsof.exe`, and pay for a system-wide
`CreateToolhelp32Snapshot` to do it. Two smoke cases pin the choice so it stays
a decision: a bare run must emit no task row, and `-K i` must parse as one
option.

Those cases failed on their first Windows run, and the reason is the same
lesson a third time. **`THRD` alone does not mean `-K`**: a thread HANDLE is an
ordinary entry in a process's handle table, and the all-handle scan types it
`THRD` too (`handles.rs` maps the native `"Thread"` object type). A PowerShell
process holds several, so `THRD` is in a bare run's output whether or not `-K`
did anything — which means the *pre-existing* `tasks-dash-K` case, asserting
only that `THRD` appears, had been passing with the feature deleted. The marker
that means `-K` is the FD cell `task` (`FdType::Task`, produced only by
`threads.rs`) next to TYPE `THRD`; a handle carries a number there instead. All
three cases key on that now, and a golden test renders the two rows side by
side so the discriminator is checked on every push from a platform that cannot
run the smoke suite.

### What the gate gained

Thirteen differential cases on fixture I, the first fixture in the suite with
a second thread — which is exactly why deleting the whole feature left the
other 56 cases green. Ten mutants were run; every case is killed by at least one:

| mutant | cases it kills |
|---|---|
| never list tasks | `-K`, `-K` with mem, `-K` fields, the three width cases |
| always list tasks | the three suppression cases |
| `TASKCMD` echoes `COMMAND` | `-K`, `-K` with mem, `-K` fields |
| tasks omit `mem` rows | `-K` with mem — and nothing else, so it is not redundant |
| `-K` accepts any argument | the two argument cases |
| `-K` consumes only a literal `i` | the case-insensitivity and path cases |
| case-sensitive compare | the case-insensitivity case |
| `TASKCMD` reuses the `COMMAND` width | all five task-row cases |
| `TASKCMD` ignores `+c` | four of them (not `+c 0`, which caps nothing) |
| `TASKCMD` width seeded from 0 | `+c` below the header — and only that one |

The renderer's two columns need no mutant of their own: the runner collapses
runs of spaces, so a process row reads `python3 PID root cwd …` and a task row
`python3 PID TID taskname- root cwd …`. The extra fields are the diff.

### A third bug, in the column the columns needed

The sweep that found the two parsing bugs was run again against a fixture whose
threads name themselves with control characters, because a thread's `comm` is
attacker-controlled exactly as a process's is. The escaping held — no raw ESC
reaches the terminal — but **TASKCMD was cut against the COMMAND column**: a
`python3` with a 22-character escaped thread name printed six characters of it
under `+c 0`, where the C prints all 22.

`print.c` keeps `TaskCmdColW` separate from `CmdColW`, seeds it from
`strlen("TASKCMD")`, grows it over `Lp->tcmd` with each name capped by
`TaskCmdLim` (which `+c` sets alongside `CmdLim`), and cuts at that width. The
port now does the same. The first draft of the fixture could not see any of
this: both its threads were named `worker1`/`worker2`, and 7 is also what
`COMMAND` sizes to, so the wrong width and the right one printed the same
seven characters. The names are lopsided now — `taskname-long-1` (15 bytes, the
kernel's `comm` ceiling) and `t2`.

Two golden tests carry the portable half: the width rule, and that a
`prctl(PR_SET_NAME)` of `\x1b[2J` reaches TASKCMD as `^[[2J` rather than
clearing the reader's terminal. Both die under a mutant that drops the escaper
and under one that reuses the COMMAND width.

### One thing this did not fix

The sweep turned up an unrelated divergence, now item 19: an unstattable path
argument is fatal in the C (nothing printed, exit 1) and is not here. `-a` hides
it, which is why every existing path case matches. It is recorded rather than
folded in — it belongs to `ck_file_arg`, not to tasks, and needs its own sweep.

## Fixed by reading the mount table (2026-09-07)

Closes item 15, the last **DEBT** entry that had a clear owner. Naming a mount
point now selects every open file on that filesystem, as Lsof.8 says it should:
`lsof /proc` listed 9 rows from the C and 0 from lsof-rs.

The rule is one line of the C (`isfn.c`, `is_file_named`): a search argument
flagged as a file system matches when `s->dev == Lf->dev`. What made it debt was
the *left* side — the port had nowhere to keep a row's filesystem device,
because the DEVICE cell is `st_rdev` for a device node. `OpenFile::fs_device`
landed with the `-F` work, so the comparison finally has both halves.

### What the sweep added to the one-line rule

* **A block-device mount SOURCE names its filesystem too.** `lsof /dev/vda` is
  the root filesystem, not the device node. `+f` widens that to *any* source,
  which is how a filesystem whose source is not a block device (`devtmpfs`,
  `overlay`, `tmpfs`) can be named.
* **`-f` and `+f` force the question.** `-f --` makes every argument a plain
  file — `lsof -f -- /` looks for files *named* `/` — and `+f` makes every
  argument a file system, complaining and exiting 1 for one that names no
  mount. Neither option existed here.
* **One argument can name several mounts.** `+f -- tmpfs` names all of them, and
  the C makes a separate search item of each: a run that finds files on one and
  nothing on the others prints rows *and* exits 1.
* **`+d`/`+D` are not affected.** They are directory expansions and reach the C
  through a different path, so `+d /` is one level of `/`, not the root
  filesystem.

### The trap that had made this debt, hit again

The first attempt over-reported `lsof /` and was backed out. So did this one, on
the first run — for a different reason, and one worth recording: a file-system
argument resolves **no identity**, and `path_matches` chose between "match by
identity" and "match by name" on whether the identity set was empty. With only a
file-system argument that set is empty, so selection fell through to the
name-prefix fallback, where `/` is a prefix of every absolute path. `lsof / -a
-p PID` returned 13 rows against the C's 10, the extra three being `/dev/null`
on a different filesystem.

The fix is to stop inferring: [`Backend::identifies_paths`] states the
capability, so a backend that resolves identities never falls back to names,
whatever any particular argument produced. The name fallback exists for Windows
alone, and the C has no name-prefix matching for a bare path argument at all.

### A panic, found in seconds

`/proc/self/mounts` escapes space, tab, newline and backslash as `\OOO`, so the
parser decodes them — and computed the byte in a `u8`. Three octal digits reach
511, so `\777` overflowed and panicked. The C masks (`cur_ch = temp_ch & 0xff`,
`dmnt.c`) and now so does this. A mount source is attacker-influenced on any
host where users may mount, which is what the new `proc_mounts` fuzz target is
for; it found this on its first run and is clean at 1.9M afterwards.

### What the gate gained, and one thing it did not

Eight differential cases, on `/dev` and `/` — separate filesystems on every
Linux host, so nothing has to be mounted for the test — plus `-f`, `+f`, a
non-block source, an argument that names no mount, and an empty filesystem.
Seven mutants were run against them; six were caught by the case meant for them.

The seventh, **taking only the first of several matching mounts**, is *not*
caught by the differential: it needs two filesystems mounted from the same
source, which a CI runner cannot create. It is caught by a unit test over
`filesystems_named`, and end-to-end by a local probe that mounts two tmpfs
filesystems. Recorded rather than papered over: the CI gate on that one rule is
the unit test, not the oracle.

## Fixed by measuring `-T` and the COMMAND column (2026-09-05)

Closes items 1, 2 and 3 of the decision table — the last of the "recorded for
decision" renderer differences, all three found on the day the Linux
differential landed and all three shared with Windows.

The sweep found **more than the three**: `-T` turned out to be a selection
model, not a set of additive flags, and `+c` turned out to have three separate
rules rather than one number.

### `-T` selects; it does not add (items 1 and 2)

The C keeps one bitset, `Ftcptpi`, and `-T<letters>` **zeroes it** before ORing
the letters in. Measured, on a fixture holding TCP, UDP and four AF_UNIX rows:

| | the C | lsof-rs before |
|---|---|---|
| no `-T` | `(LISTEN)` | same |
| `-T` | *nothing at all* | `(LISTEN) (QR=0) (QS=0)` |
| `+T` | `(LISTEN)` | **rejected as an unknown option** |
| `-T s` | `(LISTEN)` | same |
| `-T q` | `(QR=0 QS=0)` | `(LISTEN) (QR=0) (QS=0)` |
| `-T qs` / `-T sq` | `(LISTEN QR=0 QS=0)` | `(LISTEN) (QR=0) (QS=0)` |
| `-T w` | error, exit 1 | accepted, rendered nothing |

Three things fall out of that table beyond the two ledgered items:

* **A bare `-T` disables the annotation** (`main.c`:
  `Ftcptpi = (GOp == '-') ? 0 : TCPTPI_STATE`). It is how lsof is told to stop
  annotating socket rows, and `+T` is the way back — an option lsof-rs did not
  accept at all.
* **`-T` takes a value** (`T:` in the C's option string), so `lsof -T q` with a
  space works and `lsof -T /path` consumes the path and rejects `/` as a
  sub-option. lsof-rs read the following word as a filename and exited 1.
* **`w` is not a letter the Linux C accepts.** `HASTCPTPIW` is undefined there,
  so `-T w` is a hard error rather than a request that quietly returns nothing.
  It stays valid on Windows, which reads the window from EStats — the C
  compiles its letter list per dialect and so does lsof-rs now.
* **The letter order never reaches the output**: `print_tcptpi()` has its own
  fixed order (state, read queue, send queue).
* **`f` is the socket's options** (`SO=ACCEPTCON,…`), not "follow" as lsof-rs's
  parser had it. Its Linux dialect fills `lts.opt` only for AF_UNIX rows, whose
  printer ignores everything but the state, so `-T f` there selects something
  that never prints — and leaves the separator space below on every row.

One C artifact is **reproduced deliberately**: the separator space is written
*before* `print_tcptpi()` runs, on the strength of `Ftcptpi` being non-zero and
the row being a resolved socket. When nothing then prints, the space is left, so
`lsof -T f` ends every socket row in whitespace. The differential's normalizer
strips trailing whitespace, so a golden test is what holds it.

### The COMMAND column has three rules, not one (item 3)

Measured with a 15-character command (the Linux comm ceiling):

* **The default width is 9** — the C's `CMDL`. lsof-rs printed the whole name.
* **`+c` caps a row's *contribution* to the column width; the cut happens at the
  resulting width.** `CmdColW` starts at `strlen("COMMAND")` and the print pass
  is `safestrprtn(cp, CmdColW, …)`, so **`+c 5` still prints seven characters**.
  lsof-rs cut at the `+c` number, so it printed five. Nothing had noticed
  because no case used a `+c` below the header width.
* **`+c` above `MAXSYSCMDL` is an error** — "what system provides", 15 on Linux.
  lsof-rs accepted any number. Platform-specific, like the `-T w` letter:
  Windows has no such ceiling on an image name and keeps accepting.

### What the gate gained

Fixture **H** exists because of a mutation test: deleting the new default cap
left all 46 cases green. Every other fixture's command is `sleep`, `python3` or
a hostile string — under the cap, or ledgered for another reason — so nothing
could see it. H is a sleeper with a plain 15-character name. Seven mutants were
then run against the 48-case suite and each was caught by the case meant for it.

## Fixed by implementing the whole `-F` field set (2026-09-05)

Retires ledger entries `files-fields-F` and item 11, and closes items 5 and 11
of the decision table. `-F` is lsof's scripting format: everything that consumes
lsof programmatically parses this, so a missing field or a reordered stream is a
broken script, not a cosmetic difference. Bare `-F` now matches the C
byte-for-byte on every fixture, and the differential grew four cases
(`files-fields-F0`, `files-fields-Fcn`, `sockets-fields-F`,
`sockets-unix-fields-F`) to hold it there.

Found by sweeping every field letter, and several combinations, against the
oracle rather than by reading `print.c` — six of these eight would have survived
a careful read.

- **The `f` marker was unconditional.** Lsof.8 says only `p` is "always
  selected"; the C emits `f` when it is asked for. `-Fcn` yielded `p c f n` here
  and `p c n` there, so a consumer keying on `f` to start a file record saw one
  extra record per file. (Item 11.)
- **Six fields were missing outright**: `g` (pgid), `u` (uid), `G` (file flags,
  `0x<flags>;0x<per-open>`), `l` (lock), `D` (device number in hex) and the
  *empty* `a`/`l` values the C prints so every file record has the same shape.
  `D` is the **filesystem** device — for `/dev/null` the C prints the devtmpfs
  the node lives on, not the `1,3` its DEVICE column shows — which is why the
  model needed `fs_device` separately from the DEVICE cell.
- **The field order was wrong.** The C walks a fixed sequence
  (`f a l t G d D s o i k P n`, then the `T` tokens) and the `T` tokens come
  *after* the name, because `print.c` calls `print_tcptpi()` once `printname()`
  has run. lsof-rs emitted `TST=` before `n`.
- **`-F0` replaced the NUL instead of appending the NL.** The C writes the
  field's `\0` and then the set's `\n`, so a set ends `…\0\n`. Replacing it
  breaks the one thing `-F0` exists for: a consumer splitting the stream on NUL
  got the last field of one set glued to the first field of the next. The golden
  test asserted the wrong rule, which is LESSONS #023 again — a golden test pins
  what its author believed.
- **`i` and `P` are one cell under two names**, and the C picks between them with
  one discriminant (`Lf->inp_ty`): a row's NODE either *is* an inode or *is* a
  protocol. Only an internet socket takes the protocol branch — an **AF_UNIX**
  socket reports its inode, like a regular file. lsof-rs emitted `Punix` and no
  `i` for every unix socket.
- **An AF_UNIX socket's state was baked into its NAME.** The C keeps it in
  `Lf->lts` and prints it from `print_tcptpi()`, exactly as it does a TCP row's,
  so `-Fn` carries `/path type=STREAM` and the state arrives separately as
  `TST=LISTEN`. lsof-rs put `(LISTEN)` in the name, so `-F` reported it twice
  and in the wrong field.
- **`UNCONNECTED` was missing.** Every AF_UNIX row has a state; lsof-rs mapped
  only `CONNECTING`/`CONNECTED`/`DISCONNECTING` and showed nothing for the
  common `SS_UNCONNECTED`, which is what a datagram or an unconnected stream
  socket sits in. Visible in the **table** too, not just `-F`.
- **UDP carried neither queues nor state.** `/proc/net/udp` has the same
  `tx_queue:rx_queue` column as `/proc/net/tcp` and lsof reports it; a
  *connected* UDP socket also has a state, though Linux registers exactly one
  name for UDP — `ESTABLISHED` — and prints nothing for any other value
  (`build_IPstates()`).

Two selection side effects came with it, from the C's field table (`store.c`):
selecting a field also switches on the collection it needs, which is why bare
`-F` prints `TQR=`/`TQS=` with no `-T` at all. The others (`k`→nlink,
`g`/`R`→pgid/ppid, `o`→offset) are no-ops here because those values are always
gathered.

Deliberately reproduced rather than corrected: the C decides an AF_UNIX socket
is `LISTEN` with `Lf->lts.opt == __SO_ACCEPTCON` — **equality**, not a bit test —
so a socket carrying any other flag alongside `SO_ACCEPTCON` is reported by its
`St` instead. Copied as-is; a diff of the two binaries stays clean, and the unit
test says why.

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

## Fixed by matching a path by what the file is (2026-09-05)

Item 14 below is closed, and item 15 is re-scoped with a much sharper reason.

lsof matches a path argument by the file's **identity** — its `(device,
inode)` — not by its name, and `+d` (one directory level) is not `+D` (the
tree). lsof-rs had one lowercased string-prefix match doing all three jobs, so
it was wrong in both directions at once. Measured against the C on one fixture:

| query | the C | lsof-rs before |
|---|---|---|
| `shallow.txt` | its fd | same |
| its **hard link** | its fd | nothing — **missed** |
| `top` (a directory) | the `cwd` row only | that plus every file under it — **invented** |
| `mid` (nobody holds it) | nothing | a file inside it — **invented** |
| `+d top` (one level) | `top` + its entries | only `top` — **missed** |
| `+D top` (recursive) | the whole tree | only `top` — **missed** |

Inventing rows is the worse half: it answers a question the user did not ask.
All six now match the C, exit codes included.

How it works: the `Backend` trait gains `identify_path`, which returns the
`(DEVICE, NODE)` of a path **rendered exactly as that backend renders a row**,
so selection is a plain equality test and the formatting stays with the code
that produces it. The CLI resolves the arguments once at startup, expanding
`+d` one level and `+D` through the tree, into `Selection::path_ids`. A backend
that cannot identify paths returns `None` and selection falls back to comparing
names — which is what the Windows backend still does, so its behaviour is
unchanged except that `+d` there now stops at one level too.

Two things this cost, both worth recording:

- **The identity has to be the DEVICE cell, not `st_dev`.** A row shows
  `st_rdev` for a device node and `st_dev` for everything else, so an
  `identify_path` that returned `st_dev` made `lsof /dev/null` compare `0,6`
  against the row's `1,3` — the row was found and then reported as an
  unlocated search item, exiting 1. Both now render through one function.
- **Every expanded entry is a search item.** `+d dir` exits 0 when every entry
  is open and 1 when one is not — verified by adding a single unopened file to
  a directory and watching the exit status flip. The reporting is identity-based
  too, so a file queried through a hard link counts as found under its other
  name.

Item 15, the mount-point rule, is **not** implemented, and the attempt is why
the reason is now precise: naming a mount point selects everything on that
filesystem, which is a match on the **filesystem** device — but the DEVICE cell
is `st_rdev` for device nodes, so it cannot be used for that, and the model has
nowhere else to carry the filesystem. Matching on the cell listed a process's
`cwd` and `rtd` for `lsof /` that the C does not list. It was backed out rather
than shipped half-working; closing it needs `OpenFile` to carry the filesystem
device separately from the one it displays.

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
golden fixtures and the 65-case smoke suite assert. Matching the C is very
likely right; it is a compatibility decision, not a backend phase.

| # | The C | lsof-rs | Where |
|---|---|---|---|
| 1 | `(QR=0 QS=0)` | ~~`(QR=0) (QS=0)`~~ **resolved 2026-09-05** | `-T` suffix is one space-separated group; see "Fixed by measuring `-T` and the COMMAND column" above |
| 2 | `-Tq` replaces the state | ~~keeps `(ESTABLISHED)`, appends~~ **resolved 2026-09-05** | `-T`'s letters select rather than add; a bare `-T` disables, `+T` restores |
| 3 | `COMMAND` truncated to 9 | ~~not truncated~~ **resolved 2026-09-05** | default column width, plus the `+c` cut rule and the `MAXSYSCMDL` ceiling |
| 4 | list options ORed unless `-a` | ~~file-level selectors always ANDed~~ **resolved 2026-09-05** | selection engine; see "Fixed by rebuilding the selection engine" above |
| 5 | `-F` emits `g u G l D`, empty `a`/`l` | ~~omits them; `d` for `D`~~ **resolved 2026-09-05** | `-F` renderer + model; see "Fixed by implementing the whole `-F` field set" above |
| 6 | `-o` → header `OFFSET`, blank when unknown | header unchanged, falls back to size | renderer · `files-offset-o` above |
| 7 | `8uW` — `W` marks a write lock on the fd | ~~`8u`~~ **resolved on Linux 2026-09-05** | lock column, from `/proc/locks`. Windows still shows none: `FsRtlGetNextFileLock` is kernel-mode and nothing in user mode enumerates another process's locks (`docs/known-limitations.md`). |
| 8 | `TYPE a_inode`, NAME `[eventpoll:7,9,…]` | ~~`unknown`, `anon_inode:[eventpoll]`~~ **resolved 2026-09-05** | Linux: named anon_inode kinds; see "Fixed by naming anonymous inodes" above |
| 9 | a directory fd from `opendir` shows access `u` | `r` | **open question** — fdinfo `flags` say read-only; find how the C derives `u` before deciding which side is right |
| 10 | non-printable bytes in a name are escaped (`safestrprt()`) | ~~printed raw~~ **resolved 2026-09-04** | renderer, both platforms. Found by the `proc_status` fuzz target: a `\r` in `Name:` survives the parser verbatim, as it must (the kernel escapes only `\n` and `\\` there), and reached the COMMAND column raw — a process named with an ANSI escape sequence drove the terminal of whoever ran lsof-rs. Closed as the C does it; see "Fixed by the renderer escaping" above. |
| 11 | `-F` emits the `f` marker only when selected (`-Fcn` → `p`, `c`, `n` lines) | ~~`f` on every file, whatever the selection~~ **resolved 2026-09-05** | `-F` renderer. Lsof.8: only `p` is "always selected". Found while writing the hostile-name `-F` cases, which select `f` explicitly (`-Ffc`, `-Ffn`) so they compare the escaping and not this. Windows `-F` output loses an `f` line per file when the selection omits it — which is the point. |

| 12 | option parsing **stops at the first non-option argument**, so `lsof FILE -iTCP:N` reads `-iTCP:N` as a second *filename*, does not find it, and exits 1 | permutes: `-iTCP:N` is an option wherever it appears | `lsof-cli`'s argument parser. Found by the `or-semantics-*` cases, whose first draft put the path first and diverged for this reason rather than the one they test. **DECISION** — matching the C would make command lines that work today stop working, so it is recorded rather than changed alongside the selection fix. |

| 13 | `lsof -c ^name` **exits 1** even on a successful listing (1522 rows here), while `lsof -u ^name` exits 0 | both exit 0 | exit status. The C counts a negated `-c` as a search item it never located, and a negated `-u` not at all — an asymmetry between two options the man page describes identically, which is why this reads as an accident rather than a design. lsof-rs copies the half that is defensible: an *excluded* process does not count as a located `-p`, so `-c ^sleep -p <that sleep>` exits 1 in both. **C-DEFECT**, not reproduced. |

| 14 | a **path argument matches by `(device, inode)`**, and `+d` is one directory level where `+D` is the tree | ~~one lowercased string-prefix match for all three~~ **resolved 2026-09-05** | see "Fixed by matching a path by what the file is" above |
| 15 | naming a **mount point** selects every file on the filesystem mounted there (Lsof.8: "it matches a mounted\-on directory name reported by `mount(8)`") | ~~matches only the mount point itself, so it **under-reports**~~ **resolved 2026-09-07** | Waited for `OpenFile::fs_device`, since the DEVICE cell is `st_rdev` for a device node and matching on it over-reported. Also brought `-f`/`+f` and the block-device mount source; see "Fixed by reading the mount table" above. |
| 16 | a socket in **another network namespace** shows `sock` / `protocol: TCP`, with the OFFSET rather than a size | ~~`SOCK` / `socket:[14902]`, and a size~~ **resolved 2026-09-12** | see "Fixed by asking the socket's own namespace" above. This entry's stated cause was **wrong**: it said the C reads the target's own `/proc/<pid>/net/*`, and framed the fix as a cost-model change. The C reads the `system.sockprotoname` extended attribute instead (`dsock.c`), which is why it prints a protocol and no address. Reading the namespace's own table reaches the same answer in safe, dependency-free Rust; measured cost is **+1.0 ms** on `lsof -i` and **+0.8 ms** whole-host on a two-namespace host, and nothing at all where every socket resolves locally. |

| 22 | a socket family with **no `/proc/net` table at all** is still named: `protocol: AF_VSOCK` | `SOCK` / `socket:[3467]` | the C's `system.sockprotoname` xattr names any socket, table or no table; item 16's namespace fallback can only name families that have one. Measured on this host, which holds one AF_VSOCK socket **in the same namespace as the caller** — so this is not a namespace problem and item 16 does not cover it. **DECISION PENDING** — `getxattr` has no `std` API, so closing it means adding `unsafe` FFI or a dependency to a crate whose doc says "nothing here needs FFI" and that carries `#![forbid(unsafe_code)]`. That is a posture change for one NAME cell, and it is the owner's call rather than a porting decision. |

| 18 | on Linux each **task is a process entry of its own** — it repeats the whole file set and the table grows `TID`/`TASKCMD` columns — and the C lists them **whenever nothing else is selected**; `-K` forces it on, `-K i` off | ~~lists processes only; `-K` opts in, and the two columns do not exist~~ **resolved 2026-09-07** | see "Fixed by listing tasks the way the C decides to" above. This entry's own wording was **wrong**: it said the C lists threads "by default", full stop. It does not — give it any selector at all (`-p`, `-u`, `-c`, `-i`, `-d`, a path) and tasks disappear, columns included. The whole-host row count that made the claim (1052 vs 261) was consistent with either reading, which is why writing the ledger from one measurement is not enough. |

| 19 | a path argument that cannot be `stat()`ed is reported and **dropped**, and if NO argument survived the run exits before listing anything; `-Q` mutes both the message and the status | ~~reported exit 1 but still printed what the other selectors matched, and `-Q` muted only the message~~ **resolved 2026-09-12** | see "Fixed by making the search-item contract the C's" above. This entry was also imprecise: it said the failure is fatal full stop. It is fatal only when EVERY path argument fails — `lsof /a/real/file /nope` prints the first file's rows and exits 1, and lsof-rs already matched there. |

| 20 | a bare path argument alongside `+d`/`+D` makes the C **silently lose the expansion's entries**, keeping only the directory itself | both are listed | `lsof +d DIR` prints `DIR` and its open entries; `lsof ANY_PATH +d DIR` prints `DIR` alone. Measured 2026-09-12 on a directory with one open entry (1 row vs 0) and again on fixture A (4 entry rows lost), with an existing, readable bare path — so it is not about the stat failure that found it. A correct result is dropped because of an unrelated argument. **C-DEFECT**, not reproduced; the `search-plus-d-supplies-a-surviving-item` case names `{ASUB}`, which is empty, precisely so it measures the abort rule and not this. |

| 21 | `-c`, `-u` and `-g` are **search items**: a value that matches nothing exits 1, and `-V` says `command not located:` / `no user use located:` etc. | they select, but never counted as unlocated, so the run exits 0 | measured 2026-09-12: `lsof -c nosuchcmd`, `-u nosuchuser` and `-g 999999` are all exit 1 from the C and 0 here, while `-p` and `-i` already match. **DEBT** — found by the item-19 sweep. Doing it properly means auditing every search-item class the C keeps (`main.c` has ten `not located` messages) and deciding each against the negated-`-c` defect already ledgered as item 13, so it is recorded rather than folded into a path-argument change. |

| 17 | the NAME cell shows **the name you asked about**: `lsof /a/hard.txt` prints `hard.txt` for an fd the process opened as `f.txt` | prints the name the process actually opened | renderer. Both find the same fd on the same inode. The C's choice also makes its exit status order-dependent: with two names for one inode in a `+d` expansion it binds the row to one and reports the other unlocated, exiting 1. **DECISION** — printing what the process opened is the more truthful answer, and it does not inherit that bookkeeping artefact; ledgered as `path-bare-hardlink`. |

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

## The C-flaw scan — triaged (2026-09-07)

`porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py ../src ../lib`. The kit's
rule is that every finding is triaged into this file as "closed by the port" or
"not applicable"; that had not been done, and the retrospective found the
absence had gone unnoticed through three releases (LESSONS #019). It is done
now, and it changed the scanner as well as this file.

### Reachability first: 224 findings, 94 of them live

The scan covers every dialect lsof ships. This port has a **Linux** backend and
a native **Windows** one, so a finding in `lib/dialects/sun/` is code that will
never be ported. And several files in the portable `lib/` compile to *nothing*
on Linux — verified rather than assumed, by object size and symbol count:
`lsof-rnam.o`, `lsof-rnch.o`, `lsof-rnmh.o`, `lsof-dvch.o`, `lsof-rmnt.o` are
3.5 KB with **2 defined symbols** each against `lsof-misc.o`'s 113 KB and 32,
because `HASNCACHE` and the device cache are off in this configuration.

| | count | verdict |
|---|---|---|
| other dialects (`sun`, `aix`, `hpux`, `darwin`, …) | 98 | **not applicable** — no such backend, and none planned |
| `lib/` files that compile to empty on Linux | 30 | **not applicable** in the configuration this port mirrors |
| dialect test programs | 2 | **not applicable** — not shipped |
| **live** (`src/`, live `lib/`, `lib/dialects/linux/`) | **94** | triaged below |

### The 94 live findings

| category | live | triage |
|---|---|---|
| `toctou` | 47 | **20** are matches on `stat(2)` inside a *trailing comment or field declaration* — scanner noise, now fixed (below). The other 27 are real `stat`/`lstat`/`access` calls, and they are **inherent to what lsof is**: it stats `/proc` paths that can change under it. None is a stat-then-open-for-write, so a race yields a stale row, not a privilege bug. **Closed by the port** in the only sense available: lsof-rs treats a path that vanishes mid-scan as ordinary and reports nothing for it. |
| `int-overflow-mul` | 39 | **Zero** have runtime size math. 25 are the regex matching the `*` in a `(MALLOC_P *)` cast on a two-argument `realloc`; the remaining 14 are `calloc(COMPILE-TIME-CONSTANT, sizeof(T))`, which cannot overflow. **Closed by the port** regardless: `Vec`/`String` growth is checked, and `lsof-core` and `lsof-backend-linux` are `#![forbid(unsafe_code)]`. |
| `unbounded-copy` | 4 | All four read individually. `dmnt.c:307` and `dproc.c:1815` are allocate-then-copy with the allocation sized from the same string. `dsock.c:1091` copies a 6-byte literal. `dproc.c:1919` writes the `]`/`...]` postfix at `p + 11 + wl` — bounded because `snp_eventpoll()` **reserves** 11 for the prefix, the postfix length and the NUL before calling. Careful code, not luck. **Closed by the port**: no fixed buffers, and the same `[eventpoll:…]` name is built with `format!`. |
| `format-string` | 4 | 2 are macros that expand to literals (`ACCESSERRFMT`). 2 are real non-literal formats — `InodeFmt_d`, `SzOffFmt_dv` — built at startup by `snpf` from compile-time constants (`INODEPSPEC`), so no input reaches the format. **Closed by the port**: no `printf`; `format!` takes a literal by construction. |
| `command-exec` | 0 live | The single hit is in another dialect. lsof-rs spawns no process at all. |

**No exploitable finding in the code this port mirrors.** That is the outcome,
and it is worth stating as a measurement rather than a reassurance: the value of
the exercise turned out to be in the two scanner defects it exposed.

### What the triage found wrong with the scanner

Both fixed in `porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py`, with
self-test cases:

* **Trailing comments were matched.** Comment-*only* lines were skipped, but
  `unsigned char mnt_stat; /* mount point stat(2) status */` matched the
  `toctou` rule. On this tree that was 20 of 47 live toctou hits — noise that
  buries the real call sites. Comments are now blanked before matching, which
  took the tree-wide toctou count from **97 to 65**.
* **No rule for the defect the differential found by hand.** `safestrlen()`
  compares `*sp` — a `char`, signed on x86-64 — with `0x20`, so every byte
  ≥ 0x80 takes the wrong branch (the `hostile-comm-utf8-table` C-DEFECT above).
  A scanner that misses the bug the porter found by hand has a hole in it. The
  new **`signed-char-compare`** rule collects the identifiers declared `char`
  in a file and flags comparisons of them, or of a deref of them, against a
  numeric literal with no `(unsigned char)` cast.

  It finds **3** hits on this tree, all in scope:
  * `lib/misc.c:1369` — **the known defect**, caught. This is the rule earning
    its place.
  * `src/print.c:174` — `json_print_char(…, char val)` does `val < 0x20`, the
    same shape. Not reachable with a high byte: the callers pass lsof's own
    access and lock characters, which are ASCII. Measured to be sure — the C's
    `-J` output prints a `café.txt` name raw, so the name field does not go
    through this function. **Latent, not exploitable.**
  * `lib/misc.c:1311` — a **false positive**. `safepup(unsigned int c, …)`
    declares `c` as `unsigned int`, but another function in the same file
    declares `char c`, and the identifier set is file-scoped. Function scoping
    needs a real parser; the scanner's own doc says every hit is a question, and
    this is the price of that. Recorded so the next reader does not re-derive it.

