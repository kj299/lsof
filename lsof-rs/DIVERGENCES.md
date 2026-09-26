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

- [x] search-c-negated-is-a-search-item-in-the-c [sha256:40e9ee00f613]: C-DEFECT, not reproduced —
  item 13. The C enters a `-c ^name` value in the same list as the `-c name`
  values it reports on (`lsof_select_process()`), and its end-of-run loop
  (`main.c`, `for (str = Cmdl; …)`) checks `str->f` without checking `str->x`
  — the exclusion test the PID, PGID and UID loops all have. Nothing ever
  marks an exclusion found, so every run with a `-c ^` exits 1. lsof-rs does
  not count a negation as a search item. Same rows; the exit differs.
- [x] search-c-first-match-only-in-the-c [sha256:40e9ee00f613]: C-DEFECT, not reproduced — item 13.
  `is_cmd_excl()` marks the FIRST matching `-c` value and returns, so a process
  that matches two of them (`-c abcde -c abcdefgh`, both prefixes of fixture
  H's command) locates only one, and the run exits 1 with the other reported
  `not located`. lsof-rs marks every value a process matches.
- [x] inet-first-match-only-in-the-c [sha256:40e9ee00f613]: C-DEFECT, not reproduced — item 13's
  twin in `is_nw_addr()` (`lib/misc.c`: `n->f = 1; return (1);`): B's TCP
  listener matches both `-iTCP:<port>` and `-iTCP`, the C marks one, and
  exits 1. lsof-rs marks every specification a file matches.
- [x] search-u-overflow-wraps-to-root-in-the-c: C-DEFECT, not reproduced —
  `enter_uid()` accumulates `-u` digits in a `uid_t` without an overflow
  check, so `-u 4294967296` is UID 0 and selects root's processes (measured:
  the same 75 PIDs as `-u 0`). lsof-rs does not read a number that does not
  fit as a UID; it is then looked up as a login name, which no account has,
  and the run stops with `can't get UID`. Not pinned to a fingerprint, unlike
  its neighbours: what the C prints here depends on whether fixture A runs as
  root (then `-u 0` names it), so the accepted diff differs between hosts.
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
- [x] states-udp-names-crash-the-c [sha256:ca9e69cbd288]: C-DEFECT, not
  reproduced — item 32. Every `-s UDP:<state>` is a segfault in the C (exit
  139, measured): `enter_state_spec()` `strcasecmp()`s each slot of `UdpSt[]`,
  and the Linux dialect enters its one UDP name, `ESTABLISHED`, under
  `TCP_ESTABLISHED` (1), so slot 0 is NULL (`build_IPstates()`). lsof-rs
  refuses the value with the message the man page promises for a protocol
  whose state names are unavailable — `no UDP state names available:
  UDP:Idle` — and exits 1. The same empty stdout; the exit differs.
- [x] options-after-a-name-are-still-options-in-lsof-rs [sha256:40e9ee00f613]:
  DECISION — item 12. The C's `GetOpt()` returns EOF at the first argument
  that is not an option, so in `lsof FILE -a -p PID` the last three are file
  names that cannot be stat'ed: it lists FILE's row and exits 1. lsof-rs reads
  options wherever they appear, lists the same row, and exits 0.

## Fixed by laying the table out as `print.c` does (2026-09-26)

Item 35, found by reading, and what comparing whitespace found once it could.
Every table lsof-rs printed was laid out differently from the C's. The
differential could not see it, because the kit runner collapses runs of blanks
before it compares.

`print.c` prints every column right-aligned (`" %*s"`) except COMMAND and
TASKCMD, which `safestrprtn()` pads on the right, and NAME, which is not padded
at all. lsof-rs right-aligned only the numbers. USER, FD, TYPE, DEVICE and NODE
were left-aligned; the item had listed four of the five. The rest, all
measured with `cat -A` against a process holding a listener, a locked file and
a dozen pipe fds:

```
COMMAND PID USER  FD   TYPE             DEVICE SIZE/OFF    NODE NAME
python3 496 root cwd    DIR              254,0     4096  475157 /home/user/lsof
python3 496 root   0u  unix 0x00000000b83b321e      0t0     281 type=STREAM (CONNECTED)
python3 496 root   4wW  REG              254,0        0 1884552 /tmp/…/locked.txt
python3 496 root  18r  FIFO               0,15      0t0    3757 pipe
```

* **FD is two cells.** The descriptor is right-aligned in the width of the
  longest one, followed by the access character and the lock character, both
  always printed (a space when there is none). A lock with no access mode
  shows `-` in the access place. The column is sized as `FdColW = max(2,
  len(fd) + 2)`, and the title is printed in `FdColW - 2`. So when every
  descriptor is one digit, as in any `-d 3` case, the `FD` title overruns its
  field and the rest of the header sits one column right of the rows.
* **NLINK** formats its cell as `" %ld"`, leading space included, before
  measuring it. A five-digit count therefore makes the column six wide.
  Measured on a directory with 12345 links.
* **A numeric USER is eight wide.** Under `-l`, and for a UID with no
  account, `printuid()` returns `"%*lu"` padded to `USERPRTL` (8). So the
  column is `    USER` over `       0`. That is item 36's visible half: the C
  also writes no `-F L` field for a number, where lsof-rs wrote `L0`.
  `Process::user` now holds a login name only, and the renderers print the
  number where there is none. JSON keeps it as the user, as before. The
  `no pwd entry for UID N` line the C writes to stderr is not reproduced.
* **The `-T` separator** goes only on a row the C keeps a TCP/TPI record for
  (`Lf->lts.type >= 0`): TCP, UDP and AF_UNIX. lsof-rs ended every
  packet-socket NAME with a space. This was the one case that still diverged
  once the renderer was fixed and whitespace was compared.

All of it is the shared renderer, so the Windows table changes the same way:
USER, FD, TYPE, DEVICE and NODE right-aligned, and the access letter in its
own fixed place. The smoke suite reads the COMMAND cell and matches content,
not columns, so none of its assertions depend on the old spacing.

### What the gate gained

**Every case now compares its whitespace.** The kit runner takes a per-case
`keep_whitespace` (porting-kit LESSONS #070), and `linux_diff.py` sets it on
every case, so all 207 compare byte for byte. The harness's self-test checks
that default and now runs in CI. Taking the default away fails no case, since
every case would still match once its blanks were collapsed.

Two new cases cover the one shape nothing else reached, USER as a number:
`layout-numeric-user-is-eight-wide` and `fields-no-login-field-for-a-number`.

Five goldens pin the measured layouts: the table above, the FD title overrun,
the numeric USER, the five-digit NLINK, and the `-T` separator.

Sixteen mutants, all killed, twelve of them by the differential. Four only by
the goldens, because no fixture reaches them:
* the `-` for a lock without an access mode;
* an access letter on a named FD;
* NLINK's leading space;
* the JSON user for a number.

The `-T` separator is killed locally by `packet-socket-row`. CI skips that
fixture (no CAP_NET_RAW), so there the golden holds it.

### What it found next to it

The same byte-for-byte look found three differences in what the rows say,
recorded as items 41–43 rather than folded in:
* `-L` adds the NLINK column in lsof-rs and removes it in the C.
* `+L` alone is refused, and `+L1` keeps rows whose link count was never
  read.
* A `-F` field list given as its own word is read as a file name.

## Fixed by reporting what could not be read (2026-09-25)

Items 37 and "Inaccessible files are omitted", which sat under "Deliberate,
and staying". Measured with a process that made itself unreadable
(`prctl(PR_SET_DUMPABLE, 0)`), from a user who cannot read it:

```
python3 478 root  cwd   unknown   /proc/478/cwd (readlink: Permission denied)
python3 478 root  rtd   unknown   /proc/478/root (readlink: Permission denied)
python3 478 root  txt   unknown   /proc/478/exe (readlink: Permission denied)
python3 478 root NOFD      0000   /proc/478/fd (opendir: Permission denied)
```

The C does not drop what it cannot read (`dproc.c`, `process_id()`). Each of
cwd, rtd and txt is a row of TYPE `unknown` naming the `/proc` path it tried and
why that failed. An fd directory that will not open is one `NOFD` row, and the
fds under it are not listed; an fd whose link will not read is a row under its
number. lsof-rs printed one bare `unk unknown` line for all of it — and that is
what a non-root user sees of **every other user's process**. Whole-host, as
`nobody`, the two binaries now print the same 425 lines; as root on this
host, the same 1131, apart from items 9 and 22.

The details, each measured:

* **The reason is libc's own text.** The obstacle the "deliberate" entry gave —
  "matching it means reproducing libc's errno strings" — was never tested.
  Rust's `io::Error` already prints `strerror`'s text, plus ` (os error N)`;
  the CLI already had the function that strips it (`errno_text`, now in
  `lsof-core` for both sides).
* **`NOFD`'s TYPE is `0000`.** The row never gets a type, and the C's fallback
  prints the raw number, `%04o`. Under `-F` the row has no `t` field at all.
  `-d NOFD` selects it: the C compares any `-d` name with the FD cell, so `-d
  DEL` works the same way, and lsof-rs now accepts both.
* **A kernel thread's executable has no reason.** `(errno != ENOENT) || uid`:
  a root-owned process whose `exe` is simply not there prints `/proc/2/exe`
  alone. Not reachable on either test host, so pinned by unit test.
* **A link that reads but will not `stat`** keeps its name and gains
  `(stat: <reason>)` — a dead FUSE mount, say. lsof-rs showed the name alone.
  The C also `lstat`s an fd's link and can add `(lstat: …)`; that call fails
  only in a race, and costs a syscall per fd on every run, so lsof-rs does not
  make it.
* **Under `-w` none of these rows is made**, and a process left with nothing is
  not listed — but it was found: `lsof -w -p P` prints nothing and exits 0, and
  `-V` says nothing. The C's `-t` sets `-w`, so `lsof -t -p P` prints no pid;
  `-t +w` does, `+w -t` does not. lsof-rs printed the pid from a fast path that
  never looked at the files. It still does not walk them: it asks whether any
  link reads, which a readable process answers on its first `readlink`.
  `Selection::omit_unreadable` carries this, apart from `suppress_warnings`,
  because `-t` must not silence the Windows privilege hint.
* **Task rows name their own directory**: `/proc/85/task/86/cwd (readlink: …)`.

Windows is unchanged. A process with no rows is marked `unlisted` only by the
Linux backend; the Windows backend keeps its bare line for a process whose
handles it could not read.

### What the gate gained

Fixture U is a process with `PR_SET_DUMPABLE` 0, which the kernel makes
unreadable even to its own user without CAP_SYS_PTRACE — measured, `dr-x------
root` on its fd directory while it runs as `nobody`. Its ten cases set
`LSOF_DIFF_UNPRIVILEGED`. An unprivileged CI runner runs them as itself; a
root harness runs them as `nobody`, through a wrapper per binary, since the kit
runner takes one path per side for every case. Before trusting them, the
harness checks from that same user that U really cannot be read. If it can,
the cases are SKIPPED, because they would otherwise MATCH on a readable
process and prove nothing (porting-kit LESSONS #068). Eighteen mutants, all
killed: fourteen by the differential, four by unit tests alone. Those four
are the kernel-thread rule, `(stat: …)`, fd rows under an fd directory that
opens, and rows under a socket-only run, which selection drops anyway.

### What it corrected in the coverage ledger

The `UNKN*` TYPE codes had been waived on Linux as "the C emits these on an
unreadable link, with the errno". That is not what they are. An unreadable
link is TYPE `unknown`. `UNKNcwd`, `UNKNrtd`, `UNKNtxt` and `UNKNfd` are what
`-e` prints for a row it exempts from `stat` (`isefsys()`), which lsof-rs has
done since 2026-09-20. They are covered now, by the `-e` case that was
already comparing them. Measuring them found **item 40**: `-e` does not yet
exempt mapped files, which the C prints as `UNKNmem`. Plain `UNKN` is
unreachable on this dialect.

## Fixed by making `-s` the C's state filter (2026-09-25)

Item 32. lsof-rs had three faults here. It took any text as a state, so a
typo listed nothing and exited 0. It kept only the last `-s`. And it applied
`-s TCP:` to TCP sockets alone while **dropping every other socket**, the unix
ones included. Measured against the C, on a process holding one socket of each
kind:

| `-s` | the C lists |
|---|---|
| `TCP:LISTEN` | the listener, the unix socket, the file |
| `TCP:CLOSE` | the **unconnected UDP** socket, the unix socket, the file |
| `TCP:ESTABLISHED` | both TCP ends, the **connected UDP** socket, the unix socket, the file |
| `TCP:^CLOSE` | everything but the unconnected UDP socket |

On Linux the C runs one path for every socket in the TCP and UDP tables
(`process_proc_sock()`), and that path checks the TCP lists against the
kernel's state number. The kernel numbers UDP with TCP's states: 7, `CLOSE`,
for an unconnected socket and 1, `ESTABLISHED`, for a connected one. So a UDP
socket is included or dropped by the state it never prints. **This item's own
entry was wrong about that**: it said a TCP filter "leaves UDP … alone". It
had been read off the source and not measured, and measuring corrected it
before any code was written.

Now:

* **Every TCP and UDP socket that carries a state is tested; nothing else
  is.** The Linux backend keeps UDP's number, and `SocketInfo::shown_state`
  still prints only `ESTABLISHED` for UDP, as the C's one-entry UDP table
  does. A state beyond the C's table (`NEW_SYN_RECV`) is neither required nor
  excluded, as `i < TcpNstates` says.
* **The names are the platform's.** On Linux they are the C's
  (`build_IPstates()`): `CLOSE` and `SYN_RECV` where lsof-rs had used Windows'
  `CLOSED` and `SYN_RCVD`, which changes the NAME of a socket in either state
  too. `CLOSED`, state 0, is accepted and never located. Windows keeps
  `MIB_TCP_STATE`'s names.
* **Every one of the C's errors**, in its words: `unknown -s protocol:
  "<value>"`, `no TCP state names in:`, `NULL TCP state name in:`, `unknown TCP
  state name:`, `duplicate TCP inclusion:`, and `can't include and exclude TCP
  state:`. A duplicate counts across two `-s` options, since the C's tables are
  global.
* **Each included state is a search item.** `TCP state not located: <STATE>`,
  in the C's table order rather than the order given, and exit 1. A state is
  located by any socket in it that the C reads, before `-d`, `-i` or `-a` has
  decided the row. Which processes it reads matters. With two process
  selecters and no `-a` it reads every process (`is_proc_excl` skips only when
  `Selflags == SELPID` and its like), so `lsof -p A -c x -sTCP:LISTEN` is
  located by a listener anywhere. lsof-rs widens its walk to match only when
  `-s` names a state, because nothing else can tell. `-t`'s fast path, which
  reads no sockets, is not taken under `-s`.
* **`-s UDP:` with names is refused**, with the man page's message for a
  protocol whose state names are unavailable: `no UDP state names available:
  UDP:Idle`. The C **segfaults** on every such value, ledgered as
  `states-udp-names-crash-the-c`. `-s UDP:` alone is the C's own `no UDP state
  names in:`.

Windows shares the filter, the validation and the search items. The one
visible change there: `-s TCP:` no longer drops UDP and AF_UNIX sockets, as
Windows gives UDP no state. That is also what the C does on macOS, the other
platform without UDP states (`darwin/dsock.c` filters `SOCKINFO_TCP` alone).
The Windows `-t` fast path steps aside under `-s`, as the Linux one does.

### What the gate gained

Fixture S holds one socket of each kind above, and twenty-five cases compare
it. They cover the four filters, inclusion with exclusion, accumulation, case,
a value given as its own word, the report order, the walk rule, `-t`, `-F`,
and every fatal error; the fatal cases carry `-V` so that a run which accepted
the value could not match. Sixteen mutants, all killed: fourteen by the
differential, two by unit tests alone. Those two are a state beyond the table,
and the exact `UDP:` message, which exits 1 either way.

## Fixed by making every search item one (2026-09-25)

Closes item 21, re-examines item 13, and records what the audit item 21 asked
for turned up beyond it as items 32–39.

Item 21 said `-c`, `-u` and `-g` were not search items. That was the smallest
part of it. Measured against the C, option by option:

| run | the C | lsof-rs before |
|---|---|---|
| `-c ytho`, `-c PYTHON` | nothing, exit 1 — `-c` is a case-sensitive **prefix** (`strncmp`) | lists `python3`: it matched case-insensitively and by substring |
| `-c abcdefghijklmnop` | fatal — longer than the 15 bytes `comm` holds | a name that could never match, exit 0 |
| `-c /pyt/` | a regular expression | a literal that matched nothing, exit 0 |
| `-u 0` | root's processes | **nothing** — compared with the name `root` |
| `-u ROOT`, `-u nosuchuser` | fatal: `can't get UID for …` | `root`'s processes, and silence |
| `-g <pgid>` | the process group, plus a PGID column | processes whose **parent** was that number |
| `-g ^N`, bare `-g`, `-p ^N` | exclusion, the column, exclusion | errors |
| `-i :80 -i :443` | both ports | **port 443 only** — each `-i` overwrote the last |
| `-i :80` | the spec `:80` | a bare `-i` and a file called `:80` |
| `-i:1-2`, `-i:http` | ports 1–2, port 80 | every Internet file |
| `-V` with a listing | the table, then the `not located` lines | the lines, then the table |

The rules that decide "located" are the C's, and they are not one rule. `-p`,
`-g` and `-u` are marked by any matching process that survives the `^`
exclusions, whatever else the run asked (`is_proc_excl()` marks each list
before deciding an AND). `-c` is marked only by a process that got past those
tests — under `-a`, one that also matched every `-p`/`-g`/`-u` given. Each
`-i` specification, and the bare `-i` and `-N` items, are marked by a file of
such a process **as it is kept**, not as it is printed: `lsof -a -p P -i -d 3`
lists nothing and exits 0 when P has a socket on another fd, because `Fnet` is
set in `link_lfile()` and `-a` is applied at print time. A socket that `-s`
vetoes marks nothing. Under `-a` a bare `-i` and a specification are two
requirements, `SELNET` and `SELNA`, so lsof-rs grew the second kind. `-V`
reports in the C's order — commands (last given first: the list is
prepended), files, Internet addresses (also last first, a repeated text once),
`no Internet files`, NFS, PIDs, process groups, users — and a file-system
argument has its own wording, `no file system use located`.

### Item 13, and two defects of the same family

Three places in the C's bookkeeping read as accidents, and all three are
ledgered rather than copied: a `-c ^x` value is itself a search item nothing
can mark, so **every** run using one exits 1; `is_cmd_excl()` marks only the
first matching `-c` value, so `-c py -c python` exits 1 though python3 matches
both — and `-c x -c x` can never succeed; `is_nw_addr()` does the same for
`-i`. lsof-rs marks every value a process matches. And `-u 4294967296` is UID 0
to the C, whose digit loop wraps a `uid_t`; lsof-rs refuses it.

### What the gate gained

The fixture list grew by three and a session: **O** (two files at offsets the
`-o` rule tells apart), **X** (a name, a unix socket and a mapped file that are
not UTF-8), **Z** (a zombie main thread with a live thread, and a zombie
child), and **H** now runs in a process group of its own, the only way a `-g`
case can name exactly one process. 61 cases were added (109 → 170): 163 MATCH,
6 are ledgered. Every "fatal" case carries `-V`, because a fatal error and an
unlocated item both print nothing and exit 1 — only `-V` tells them apart.

Mutation, against the differential: **45 mutants, 45 killed**, each by the
cases written for it. One survived the first run — "`-c` ignores the `-a`
rule" — and `search-c-under-a-is-located-only-past-the-other-kinds` was
written to kill it. The first pass of that run was itself wrong: its driver
restored each mutated file with an older mtime, cargo kept the mutant, and
later mutants ran on top of earlier ones (porting-kit LESSONS #066). Re-run
from a forced rebuild, the results above are the clean ones.

## Fixed by measuring the SIZE/OFF column's three modes (2026-09-25)

Closes item 6. One column, three modes, chosen in `print.c`:

| mode | header | a row with a size | a row with only an offset |
|---|---|---|---|
| default | `SIZE/OFF` | the size | the offset |
| `-o` | `OFFSET` | **its offset, or blank** | the offset |
| `-s` (bare) | `SIZE` | the size | **blank** |

`cwd`, `rtd`, `txt` and `mem` have a size and no offset — there is no fdinfo
behind them — so under `-o` they are blank; lsof-rs fell back to the size
under the old header. The rest was not in the ledger at all:

- **an offset prints in hex past `OffDecDig` digits** — 8 unless `-o <digits>`
  says otherwise, and `-o 0` means no limit. 123456789 is `0x75bcd15` by
  default, in the table and in `-F`'s `o` field; lsof-rs always printed `0t…`.
- **`-o <digits>` is only a limit**: it keeps `SIZE/OFF`. Its value is digits
  and nothing else; the rest is option letters again (`-o 3t` is `-o3 -t`), and
  a word that is not digits is not its value (`-o /file`). lsof-rs rejected
  `-o5` and read `-o 5` as a file called `5`.
- **a bare `-s` is the SIZE column** — with a value it is the state filter —
  and **`-o` with `-s` is fatal**, in either order, `-Fo` included (selecting
  the `o` field sets the same flag). lsof-rs read the word after `-s` as a
  state whatever it was, so `lsof -s -o` silently filtered every socket out by
  a state named `-o`.

Shared renderer: Windows prints the `OFFSET` column too, which the smoke suite's
`-o` cases (`0t128`) still pass.

## Fixed by not listing zombies (2026-09-25)

Closes item 31. The C reads each process's state and skips one in state `Z`
before selection (`read_id_stat()` returns 1; `dproc.c`: `prv != 1`), so
`lsof -p <zombie>` prints nothing and exits 1 — the pid is a search item not
located. lsof-rs gathered the zombie, fileless, and the renderer drew its
bare `unk unknown` row. It now reads `State:` and drops the entry.

Not every zombie is gone, though: the C still walks a zombie's **tasks**, so a
process whose main thread has exited while another thread runs on is listed
through that live task under `-K` (and in a bare run, where tasks are listed
by default). Its mapped files then exist only in the task's own `maps` —
`/proc/<pid>/maps` is empty once the leader's `mm` is gone — and lsof-rs read
every task's mapped files from the process's file, so the live task had no
`mem` rows. It reads the task's own now, as the C does. Zombie *tasks* are
skipped too; no fixture can make one on purpose, so that line is held by
reading the C, not by a case.

The renderer's blank row stays: it is still what a process whose files cannot
be read looks like (item 37 records how `-w` and `-t` differ).

## Fixed by reading bytes: one byte had blinded a whole table (2026-09-25)

Found while measuring item 31, and the most serious thing in this change. The
Linux backend read every kernel table with `read_to_string`, which fails on the
first byte that is not UTF-8, and treated the failure as "this table is empty".
Those bytes are an unprivileged user's to write:

| written by any user | lsof-rs | the C |
|---|---|---|
| `prctl(PR_SET_NAME, "\xff\xfe…")` | the process is in no listing; `-p` says it does not exist | listed as `\xff\xfe` |
| a unix socket bound to `…/sock\xff` | `lsof -U` lists **nothing, for any process** | every socket |
| a mapped file named with such a byte | every `mem` row of that process gone | all listed |
| `lsof /tmp/$'\xff'` | **panic**, exit 101 | a lookup |

Every table is now read as bytes and decoded lossily (`text::read_lossy`), a
mapped file is `stat`ed by its raw name (the decoded one names no file), and a
non-UTF-8 argument is refused in one line. The fuzz targets had not found any
of it because they decoded their input *before* the parser, so the read — the
part that failed — was never fuzzed; `proc_maps` now drives the byte parser
directly. Porting-kit LESSONS #067, which also fixes the kit's fuzz template
and skeleton, both of which taught the same shape.

**DECISION — what an undecodable byte looks like.** lsof-rs's model holds a
command or a name as a `String`, so a byte that is not UTF-8 becomes U+FFFD;
the C prints it as `\xff`. The process, the socket and the mapping are listed,
which is the part that matters; the display differs. In the COMMAND column,
which escapes every non-ASCII byte, U+FFFD takes 12 columns, so a name that
starts with such a byte shows an empty cell at the default 9-column width and
in full under `+c 0` or `-F c`. Holding raw bytes would need a byte-string
model through every renderer, and is not worth it for a display. The fixture-X
cases compare what does not depend on the display.

## Fixed by implementing `-H`, which was never a headers toggle (2026-09-19)

`-H` was not ledgered here. It was **waived**, in
`coverage/feature-inventory-lsof-rs.toml`, as

```toml
id = "opt:H"
reason = "legacy \"headers\" toggle on certain dialects"
```

with **no `platforms` key**, so it excused both backends. In lsof 4.99.6 `-H`
is *human-readable sizes*, it works, and lsof-rs answered
`lsof: unsupported option: -H` on every platform. The gate that exists to
catch a missing feature had been green over this one since before Linux
existed, because the waiver's reason was wrong rather than expired — nothing
about the port changing could ever have falsified it.

### What the C actually does

`human_readable_size()` in `print.c`, measured on sparse files of exactly these
lengths rather than read off the source:

| bytes | C prints | why it is not the obvious answer |
|---:|---|---|
| `1023` | `1023B` | under 1024 is a raw count with a `B`, not `1.0K` |
| `2125328` | `2.0M` | the divide **truncates before it scales** — `2075/1024`, not `2.0263` |
| `25847420` | `24.6M` | same rule; plain `sz/unit` in floating point says `24.7M` |
| `174336` | `170.2K` | exactly `170.25`, and `%.1lf` rounds half-to-**even** |
| `1048575` | `1024.0K` | the **suffix is chosen before rounding**, so just under a boundary it prints 1024 of the smaller unit rather than `1.0M` |
| `u64::MAX` | `16.0E` | the C's last loop step overflows and is never read; Rust must not panic there |

Three of those six are rules a tidy-up would "fix". They are pinned by name in
`golden.rs`, and all three survive as mutations only if the test is weak — the
pure-floating-point mutation **did** survive the first draft, which is why
`25847420`, `161533414` and `415288979` are in the table: they are the values
that separate the two orders of operation, and the oracle was asked for each.

### Scope, which is narrower than it looks

`-H` scales the **SIZE cell and nothing else**. The C humanises inside the
`sz_def` branch of `print.c` alone, so:

* an **offset stays `0t<dec>`** — including the offset a row falls back to when
  it has no size, and including `-o -H`;
* **`-F` is untouched** (`lsof -H -Fs` is byte-identical to `lsof -Fs`);
* **JSON is untouched** — the C's `-J` output with and without `-H` diffs
  clean, so lsof-rs's `-J`/`-j` stay in raw bytes too. A machine-readable
  format that silently switches to `1.5M` is a worse bug than the missing
  option was.

Three differential cases cover exactly these three claims against the C, on
fixture A's new sparse fds 7/8/9. The Windows smoke suite gains the same pair,
because this is a `lsof-core` change and lands on both backends.

### What else the pass corrected

Four waivers that asserted something untrue, found by reading each one against
the oracle rather than against the port:

* **`opt:m` and `opt:M`** were `DEBT (L2)`. This C answers `-m not supported`
  and `illegal option character: M` on Linux — the port owes nothing the
  reference implementation does not do. Rescoped as absent from the dialect.
* **`opt:f` / `+f`** were waived as needing `/proc/mounts`. They have worked
  since the mount table landed; the waiver outlived its reason.
* **`type:EVENTFD`, `SHM`, `UNNM`, `UNSP`** were `DEBT (L2)`. They exist in
  `lib/print.c`'s shared table and `include/lsof.h`'s enum, but **nothing under
  `lib/dialects/linux/` ever sets them** — an eventfd is `a_inode` here and
  `/dev/shm` is a plain `REG`. Unreachable, not owed.
* **`type:DEL`** was in the same group and is simply done: measured identical
  to the C on a deleted mapping, and now covered by the differential. Worth
  noting it is an **FD** code on Linux, not a TYPE — the C puts `DEL` where
  `mem` would go — though the inventory files it under types.

`type:UNKNdel` and `type:UNKNmem` moved to the `UNKN*` entry below, where they
belong: they are the error-reporting gap, not the mappings one, and grouping
them with `mem` rows hid that for months.

> **Corrected 2026-09-25:** they are neither. Every `UNKN*` code is what `-e`
> prints for a row it exempts from `stat`; an unreadable link is TYPE
> `unknown`. See "Fixed by reporting what could not be read" above, and item
> 40 for the two that are still owed.

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

### Observe-first, then promoted (2026-09-13)

It landed non-blocking on the kit's promotion rule (LESSONS #13): consecutive
green runs read from the **step log** rather than the job status. This one
could not be validated locally the way the miri job was — there is no Windows
here, and every detail of it (the nightly's ASan support on the MSVC target,
the `vswhere` path to `clang_rt.asan_dynamic-x86_64.dll`, GitHub's pwsh
appending `exit $LASTEXITCODE` to a step whose command is *supposed* to fail)
was written blind. Observe-first was doing real work here rather than ceremony.

Reading the log rather than the status is not pedantry on this job: its status
is green in BOTH the working case and the silently-not-instrumenting case. That
is the whole reason the canary step exists, and it means a promotion could
never have been taken from the status alone.

Three runs, on PR #77's heads `a29e4ff`, `0965875` and `e506b1a`, each showing:

    ASan runtime dir: …\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64
    ==NNNN==ERROR: AddressSanitizer: heap-buffer-overflow … asan_canary.rs:33
    canary caught: ASan is live.
    test result: ok. 10 passed

`CANARY SURVIVED` appeared in none of them except as the echoed script source.
`continue-on-error` is gone; the job blocks like every other.

### The gate that was missing, and is now there (2026-09-13)

The promotion first landed with `progress.json` still reading `differential`
for `lsof-backend-windows`, because the kit's order is **ported → differential
→ fuzzed → sanitized → unsafe_audited** and the `fuzzed` gate had never run for
that crate: no fuzz target imported it, and unlike `lsof-backend-linux` it
exposed no `fuzz_api` to import.

That gap was the one LESSONS #21 was written about — its rule is the six-gate
loop **per backend crate**, "one fuzz target per text-parsing module" — and the
Windows backend does parse text the OS hands it. `check_ledgers.py` counts fuzz
targets, found nine, and reported the ledger `present` the whole time: counting
artifacts is not covering the crates they are artifacts of.

It is closed now. `crate::names` holds the crate's whole text-parsing surface —
`device_to_dos`, `drive_of`, `normalize_final`, `pipe_display`,
`win_type_to_filetype`, `short_type_code`, `wide_to_string` — in portable safe
Rust, **deliberately not `cfg(windows)`**, because the `cargo fuzz` job runs on
Linux and none of those functions needs Windows to run. The `windows_names`
target drives all seven; 10M runs clean, and 2.35M more in the full-suite pass
at CI's own 45-second budget.

Moving them also means their unit tests run on **every** platform instead of
only the Windows job: `cargo test` on Linux went from 0 tests in this crate to
8.

With that gate real, the row is `unsafe_audited`, and every step of it is a
green CI gate rather than a claim:

| gate | evidence |
|---|---|
| differential | the Windows socket differential vs `Get-NetTCPConnection`, plus the 65-case smoke suite |
| fuzzed | `windows_names`, in the `fuzz smoke (every target)` job |
| sanitized | `asan-windows`, now a hard gate, canary-verified |
| unsafe_audited | `audit_unsafe.py crates/lsof-backend-windows/src` — 139 blocks, 139 documented |

### The harness needed the same scepticism as the code

The fuzzer refuted the target's own assertions twice inside the first minute,
before it ever said anything about the crate:

* it sliced `text[..len/2]`, which panics mid-code-point on a `&str` from
  `from_utf8_lossy`. A target that panics on its own input reports a false
  positive forever.
* its `device_to_dos` invariant compared the result against the tail of the
  **first** map entry, and the fuzzer produced a string the **second** entry
  matched instead. That is the sixth over-strong invariant on this project
  (LESSONS #26) — and the first one a machine caught before a human did.

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

## Fixed by measuring the five small options (2026-09-20)

P4 of `docs/linux-l2-plan.md`: `-Z`, `-N`, `-x`, `-X`, `-e`. The plan sized
them S/S/M/M/M and called them "the small options". **Every one was larger than
that, and two were live defects rather than missing features.** Each was
measured against the oracle before a line was written.

### `-X` does not do what it is documented to do

`machine.h:502` defines its usage text as "skip TCP&UDP* files". It skips
nothing:

```
6u IPv4 14197 0t0 TCP 127.0.0.1:58679 (LISTEN)              without
6u sock  0,9  0t0 14197 can't identify protocol (-X specified)   with
```

It suppresses the **lookup**. `dsock.c:4155` is an if/else — under `-X` the C
enters that fixed string *instead of* reading `system.sockprotoname` — so the
port skips the namespace fallback rather than performing it and discarding the
answer. Which tables it gates was measured, not read: `tcp`, `tcp6`, `udp`,
`udp6` and `raw6` yes; `/proc/net/{raw,packet,unix}` no. The v4/v6 raw split is
the C's own (`:3530` has no guard where `:3761` does) and is reproduced.

`lsof -X -i` is fatal in both, same line and status.

### `-x` is the switch for a `+d` rule this port had backwards

`arg.c` lstats each directory entry and applies two tests: skip an entry whose
`st_dev` is not the directory's unless `-x`/`-x f` (`:1029`), and **skip a
symbolic link outright** unless `-x`/`-x l` (`:1038`). lsof-rs did neither —
`identify_path` uses `metadata()`, which follows. On a directory holding one
link pointing out of it, at a file open under its real name:

```
C:   (nothing)
rs:  python3 6241 root 3r REG 254,0 4 1908956 .../outside/target.txt
```

`+d` had been over-selecting since the path work landed. The filesystem half
needed a new `Backend::path_fs_device` hook, because the device cell
`identify_path` returns is `st_rdev` for a device node — `/dev/null` is `1,3`,
not the devtmpfs it sits on.

### `-e` is a row shape, not argument validation

Pinned through `-F`, because the table hides half of it:

| | without | with `-e /` |
|---|---|---|
| `a` access | `r` | **blank** |
| `t` TYPE | `REG` | `UNKNfd` |
| DEVICE | `D 0xfe00` | `d UNKNOWN` |
| `s` size, `i` inode, `k` links | present | **absent** |
| `o` offset, `n` name | present | present, name + ` (-e /)` |

`-e` means **do not stat**. Membership is therefore a path-prefix test costing
a readlink and no stat, which is the whole point of an option whose reason is a
hung NFS server. Two bugs the oracle caught and reading would not: `cwd`/`rtd`/
`txt` have no fdinfo position and must print an empty cell, not `0t0`; and an
fd whose target is `socket:[N]` is on no file system, so `-e /` must not
swallow it.

### `-N` and `-Z`: what this host cannot prove

`-N` is a search item (`main.c:1768`, `Fnfs < 2`), and all four shapes match —
including `lsof -N -p P`, which lists P's files *and* exits 1. Finding it
exposed that `SelKinds::FILE`, the mask deciding a process with no surviving
rows is not a result, did not contain `NFS`: selection was correct and 78
processes still printed a bare `unk unknown` line.

**There is no NFS mount here or on a GitHub runner**, so the positive path has
no oracle. It is not unexercised, though: pointing the same filter at `ext4`
makes 276 rows appear, so the device matching, row selection and emptiness rule
all run. What is unverified is narrow — that the strings `nfs`/`nfs4` match a
real NFS mount.

`-Z`'s gate matches, and the check is not the obvious one:
`is_selinux_enabled()` asks whether **selinuxfs is mounted**, not whether
`/sys/fs/selinux` exists. Here the directory exists, empty, unmounted — so a
presence check answers "enabled" where the C answers "disabled". The CONTEXT
column is **not** implemented and that is a decision, not an omission: it lives
among the process columns with a width grown to the longest value
(`print.c:902`), no available host can show its position, and a guessed layout
fails silently on exactly the hosts that use it. lsof-rs exits 1 with
`-Z (SELinux context) is not implemented` instead.

### A waiver that described a different option

`opt:X`'s coverage reason read *"epoll bridge, needs anon_inode+fdinfo
correlation"*. That is not `-X`. Like `opt:H` before it, the entry was wrong
from birth and no code change could ever have falsified it.

### What the gate gained, and the two cases that could not fail

Eleven differential cases, 95 → **107**. Three mutants were run against them,
and **two survived on the first attempt because the cases were wrong**:

* the `+d` symlink case used a link pointing at a file *inside* the same
  directory. The target is then already in the expansion under its own name,
  so following the link changes no selection. Rebuilt against a directory whose
  only entry is a link pointing **out** of it, it kills the mutant.
* the `-N` case looked unable to fail too — and that diagnosis was **wrong**.
  The mutation had silently not applied: `cargo fmt` had reformatted the
  constant, and `str.replace` returns the input unchanged when its pattern is
  absent. Applied for real it produces 78 rows against the C's 0 and **two**
  cases fail. Recorded as LESSONS #059, because a mutation that does not happen
  is indistinguishable from a gate that does not catch.

## Fixed by reading /proc/net/packet (2026-09-20)

P3 of `docs/linux-l2-plan.md`. An `AF_PACKET` socket — what `tcpdump` opens —
was the second of the two rows that measurably differed from the C on a
thirteen-descriptor fixture. It is the one that needed no decision: the table
exists, and reading it is one more parser alongside the seven `net.rs` already
had.

```
C:   9u pack  11426  0t0  ALL  type=SOCK_RAW
rs:  9u SOCK  0,9    0    11426  socket:[11426]        <- before
rs:  9u pack  11426  0t0  ALL  type=SOCK_RAW           <- after
```

lsof spends the three cells differently here than for any other family
(`dsock.c:3622`): DEVICE holds the **inode**, NODE holds the **ethernet
protocol**, and NAME is only the socket type, because a packet socket has no
address to print.

### The protocol table was transcribed, then measured

`ethernet_proto_to_str()` is 93 `#if defined(ETH_P_…)` arms. Rather than trust
a transcription, a fixture opened **one packet socket per protocol** — all 93,
plus seven values the table does not carry — and every NODE cell the C printed
for the resulting 100 rows was compared against the port's:

```
checked 100 protocols against the C, 0 disagreements
```

Three things that reading alone would have got wrong, and the case that pins
each:

| | the C | why |
|---|---|---|
| `ETH_P_LOOPBACK` → `LOOPBAC` | **7 bytes, not 8** | `Lf->iproto` is `char[IPROTOL]`, `IPROTOL == 8`, written with `"%.*s", IPROTOL - 1`. The C's own comment above that function promises "should not exceed 7 characters" and its table breaks it exactly once. |
| `0x1234` → `4660` | decimal, from a hex column | an unnamed protocol falls back to its number, and `/proc/net/packet` writes the column as `%04x` |
| `ETH_P_PPP_MP` → `PPP MP` | a **space inside the cell** | one of the C's names contains one |

The socket type has its own rule: `type=SOCK_RAW` for the seven the kernel
defines, and `type=unknown` — not `type=SOCK_unknown` — for anything else,
because the C picks the prefix on the same flag that picks the word.

### The header line is checked, not skipped

This table is read by fixed column index, and the C guards that with the
labels (`get_pack()`). A kernel that reordered the columns would otherwise be
read as if it had not — `Proto` in the `Type` slot is still a number, so it
parses, and the row comes out wrong rather than absent. The whole table is
dropped on a mismatch, as the C does; the C also prints
`WARNING: unsupported format` on stderr, which this port has no channel for
from inside a backend table read.

One asymmetry is deliberate and matches the C: an unreadable **`Type`** keeps
the row (the C reads it with `atoi()`, which cannot fail, yielding 0 and
`type=unknown`), while an unreadable **`Proto`** drops it (`strtoul` with a
full-consume guard).

### Item 24 — the kernel's name, not ours

Adding the packet parser made a second, older row reachable: a packet socket
in a *foreign* network namespace, which neither binary can resolve from
`/proc/net` and both name by falling back. Measured on five families at once:

```
3u sock … protocol: PACKET        4u sock … protocol: UNIX-STREAM
5u sock … protocol: TCP           6u sock … protocol: UDP
7u sock … protocol: NETLINK       <- still item 22
```

The fallback added for item 16 answered with `info.protocol`, which is `TCP`
and `UDP` for the two families the netns fixture held — and `unix` and
`packet` for the two it did not. The C reads `system.sockprotoname`, which is
the kernel's name for the socket's `struct proto`, so a stream AF_UNIX socket
is `UNIX-STREAM` while a dgram *and a seqpacket* one are both `UNIX`. That is
now a separate field on the table entry rather than a reuse of the protocol,
and each parser sets its own.

### What the gate gained

Two fixtures, because the capability split them:

**K(packet)** holds four packet sockets in this namespace — one per branch of
the NODE cell — and covers the `pack` row itself. `AF_PACKET` needs
`CAP_NET_RAW`, which a GitHub runner does not have, so its three cases are
**skipped there**, by name, on stderr. They are not gated in CI, and saying so
is the point of the message.

**L(userns sockets)** holds a packet socket and two AF_UNIX sockets inside
`unshare --user --map-root-user --net`, which grants `CAP_NET_RAW` *inside* the
new user namespace and so needs no privilege on the host. Its two cases are the
only ones in the harness that reach the xattr-name path at all.

**They skipped on the runner at first**, which this section originally claimed
they would not. Measured on head `195d7eb`:

```
SKIP (no unprivileged user namespaces for `unshare --user --net`):
  userns-sockets-show-the-kernels-protocol-name,
  userns-sockets-kernel-protocol-name-fields
87 cases, 0 unexplained divergence(s)
```

Ubuntu 24.04 ships `kernel.apparmor_restrict_unprivileged_userns=1`, which
blocks `unshare --user` for an unconfined binary. The differential job now
clears it on the ephemeral runner VM and probes the exact command before
running. **Measured again on head `d8e2160`, it works:**

```
kernel.apparmor_restrict_unprivileged_userns = 1
kernel.apparmor_restrict_unprivileged_userns = 0
probe OK: unprivileged user+net namespaces work, fixture L will run
[MATCH             ] userns-sockets-show-the-kernels-protocol-name
[MATCH             ] userns-sockets-kernel-protocol-name-fields
89 cases, 0 unexplained divergence(s)
```

89, up from 87: exactly the two cases fixture L contributes. **Item 24 is
gated in CI**, which matters because both of its mutants pass all 160 unit
tests. Fixtures J and K stay skipped — `unshare --net` wants real
`CAP_SYS_ADMIN` and `AF_PACKET` wants real `CAP_NET_RAW`, and a user namespace
grants neither — so the runner reaches 89 of the 95 cases this host runs, with
the other six named on stderr every time.

What decides is the harness's own `SKIP`/`MATCH` line, printed by name, and
not the step that tries to enable the capability: a step reporting success and
a gate actually running are different claims, which is the whole reason the
87 above was caught at all.

**DECISION, 2026-09-20.** Clearing that sysctl is CI relaxing a kernel security
setting, which is not a porting call, so it went to the repository's owner:
*keep it*. Recorded here and in the workflow because two other sessions are
working this tree, and a step that lowers an AppArmor restriction is exactly
the kind of thing a later reader removes on sight — silently un-gating item 24
in the process.

Every new assertion was mutated. Six against the unit tests (no truncation,
DEVICE/NODE swapped, hex instead of decimal, `type=SOCK_unknown`, no header
check, a strict `Type` parse) and each was caught by the test written for it.
Three against the differential:

| mutant | cases it kills |
|---|---|
| no 7-byte truncation | `packet-socket-row`, `packet-socket-fields` |
| packet's kernel name lowercased | the two `userns-sockets-*` cases |
| AF_UNIX loses its `-STREAM` | the two `userns-sockets-*` cases |

The second and third are worth naming: **no unit test kills them.** Reverting
the namespace fallback to `info.protocol` passes all 159 of them, because that
path needs a live foreign namespace to execute. Fixture L is the only thing in
the repository that can fail for it.

### Cost

One more `read_to_string` and one more parse per namespace, against the binary
built from the commit before this change, 25 interleaved runs of each, minimum
taken because this host's median moved by more than the effect being measured
(the same binary spanned 38–57 ms across repeats):

| | before | after | the C |
|---|---:|---:|---:|
| whole host, **no** packet sockets | 37.0 ms | 36.8 ms | 62.8 ms |
| whole host, **100** packet sockets | 35.7 ms | 35.1 ms | 45.4 ms |
| `-i` | 15.0 ms | 15.1 ms | — |

Peak RSS is **identical** in every row (7.5 MB loaded, 8.6 MB idle; meter
validated against a known 200 MB allocation at 207.7 MB). The protocol table
is a `match` over `&'static str`, so it is in the binary and allocates
nothing; a row costs the same three `String`s an AF_UNIX row costs.

### And one hole in the fuzz target, found by mutating it

`proc_net` gained `parse_packet`, and a panic planted in the row loop proved
the arm was **unreachable**: the header check wants ~60 specific bytes before a
single row is read, and a corpus grown from empty does not guess them.

```
with the header prepended     panic found in seconds
without it                    81,567 runs / 46 s, never reached
```

The target now parses the input twice — bare, which exercises the header check,
and with the real header prepended, which exercises everything behind it. A
fuzz target that cannot reach the parser it names is LESSONS #019 in a new
costume, and the only way to see it is to plant a fault and watch.

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
| 6 | `-o` → header `OFFSET`, blank when unknown | ~~header unchanged, falls back to size~~ **resolved 2026-09-25** | renderer, both platforms; see "Fixed by measuring the SIZE/OFF column's three modes" above. The `files-offset-o` ledger entry is gone — the case MATCHes, and a stale entry would now fail the gate. |
| 7 | `8uW` — `W` marks a write lock on the fd | ~~`8u`~~ **resolved on Linux 2026-09-05** | lock column, from `/proc/locks`. Windows still shows none: `FsRtlGetNextFileLock` is kernel-mode and nothing in user mode enumerates another process's locks (`docs/known-limitations.md`). |
| 8 | `TYPE a_inode`, NAME `[eventpoll:7,9,…]` | ~~`unknown`, `anon_inode:[eventpoll]`~~ **resolved 2026-09-05** | Linux: named anon_inode kinds; see "Fixed by naming anonymous inodes" above |
| 9 | a directory fd from `opendir` shows access `u` | `r` | **open question** — fdinfo `flags` say read-only; find how the C derives `u` before deciding which side is right |
| 10 | non-printable bytes in a name are escaped (`safestrprt()`) | ~~printed raw~~ **resolved 2026-09-04** | renderer, both platforms. Found by the `proc_status` fuzz target: a `\r` in `Name:` survives the parser verbatim, as it must (the kernel escapes only `\n` and `\\` there), and reached the COMMAND column raw — a process named with an ANSI escape sequence drove the terminal of whoever ran lsof-rs. Closed as the C does it; see "Fixed by the renderer escaping" above. |
| 11 | `-F` emits the `f` marker only when selected (`-Fcn` → `p`, `c`, `n` lines) | ~~`f` on every file, whatever the selection~~ **resolved 2026-09-05** | `-F` renderer. Lsof.8: only `p` is "always selected". Found while writing the hostile-name `-F` cases, which select `f` explicitly (`-Ffc`, `-Ffn`) so they compare the escaping and not this. Windows `-F` output loses an `f` line per file when the selection omits it — which is the point. |

| 12 | option parsing **stops at the first non-option argument**, so `lsof FILE -iTCP:N` reads `-iTCP:N` as a second *filename*, does not find it, and exits 1 | permutes: `-iTCP:N` is an option wherever it appears | `lsof-cli`'s argument parser. Found by the `or-semantics-*` cases, whose first draft put the path first and diverged for this reason rather than the one they test. **DECISION** — matching the C would make command lines that work today stop working, so it is recorded rather than changed alongside the selection fix. Since 2026-09-25 a case holds it (`options-after-a-name-are-still-options-in-lsof-rs`, ledgered and pinned); every other case puts its names last, so nothing had. Item 34 recorded this same behaviour again as open, and is folded in here. |

| 13 | `lsof -c ^name` **exits 1** even on a successful listing (1522 rows here), while `lsof -u ^name` exits 0 | both exit 0 | exit status. The C enters a `-c ^` value in the list it reports on and never marks it (`main.c` checks `str->f`, never `str->x`), which reads as an accident, not a design. **C-DEFECT, not reproduced — confirmed and widened 2026-09-25**: the same bookkeeping marks only the **first** matching `-c` value (`is_cmd_excl()` returns on it), and `is_nw_addr()` does the same for `-i`, so `-c py -c python` and `-iTCP:80 -iTCP` exit 1 for a process that matches both. Three ledgered cases pin the three. The reason this row used to give for `-c ^sleep -p <that sleep>` exiting 1 in both was wrong about the C: it counts that pid as located (it marks `-p` before it tests `-c ^`) and exits 1 only because of the `^` value — `-V` names the command, not the pid. See "Fixed by making every search item one" above. |

| 14 | a **path argument matches by `(device, inode)`**, and `+d` is one directory level where `+D` is the tree | ~~one lowercased string-prefix match for all three~~ **resolved 2026-09-05** | see "Fixed by matching a path by what the file is" above |
| 15 | naming a **mount point** selects every file on the filesystem mounted there (Lsof.8: "it matches a mounted\-on directory name reported by `mount(8)`") | ~~matches only the mount point itself, so it **under-reports**~~ **resolved 2026-09-07** | Waited for `OpenFile::fs_device`, since the DEVICE cell is `st_rdev` for a device node and matching on it over-reported. Also brought `-f`/`+f` and the block-device mount source; see "Fixed by reading the mount table" above. |
| 16 | a socket in **another network namespace** shows `sock` / `protocol: TCP`, with the OFFSET rather than a size | ~~`SOCK` / `socket:[14902]`, and a size~~ **resolved 2026-09-12** | see "Fixed by asking the socket's own namespace" above. This entry's stated cause was **wrong**: it said the C reads the target's own `/proc/<pid>/net/*`, and framed the fix as a cost-model change. The C reads the `system.sockprotoname` extended attribute instead (`dsock.c`), which is why it prints a protocol and no address. Reading the namespace's own table reaches the same answer in safe, dependency-free Rust; measured cost is **+1.0 ms** on `lsof -i` and **+0.8 ms** whole-host on a two-namespace host, and nothing at all where every socket resolves locally. |

| 22 | a socket family with **no `/proc/net` table at all** is still named: `protocol: AF_VSOCK` | `SOCK` / `socket:[3467]` | the C's `system.sockprotoname` xattr names any socket, table or no table; item 16's namespace fallback can only name families that have one. Measured on this host, which holds one AF_VSOCK socket **in the same namespace as the caller** — so this is not a namespace problem and item 16 does not cover it. **DECISION PENDING** — `getxattr` has no `std` API, so closing it means adding `unsafe` FFI or a dependency to a crate whose doc says "nothing here needs FFI" and that carries `#![forbid(unsafe_code)]`. That is a posture change for one NAME cell, and it is the owner's call rather than a porting decision. **Wider than one family, measured 2026-09-25:** a TCP socket that is bound but neither listening nor connected is in no `/proc/net` table either, so the C names it `sock … protocol: TCP` and lsof-rs prints `SOCK socket:[N]` — any server between `bind()` and `listen()`. |

| 18 | on Linux each **task is a process entry of its own** — it repeats the whole file set and the table grows `TID`/`TASKCMD` columns — and the C lists them **whenever nothing else is selected**; `-K` forces it on, `-K i` off | ~~lists processes only; `-K` opts in, and the two columns do not exist~~ **resolved 2026-09-07** | see "Fixed by listing tasks the way the C decides to" above. This entry's own wording was **wrong**: it said the C lists threads "by default", full stop. It does not — give it any selector at all (`-p`, `-u`, `-c`, `-i`, `-d`, a path) and tasks disappear, columns included. The whole-host row count that made the claim (1052 vs 261) was consistent with either reading, which is why writing the ledger from one measurement is not enough. |

| 19 | a path argument that cannot be `stat()`ed is reported and **dropped**, and if NO argument survived the run exits before listing anything; `-Q` mutes both the message and the status | ~~reported exit 1 but still printed what the other selectors matched, and `-Q` muted only the message~~ **resolved 2026-09-12** | see "Fixed by making the search-item contract the C's" above. This entry was also imprecise: it said the failure is fatal full stop. It is fatal only when EVERY path argument fails — `lsof /a/real/file /nope` prints the first file's rows and exits 1, and lsof-rs already matched there. |

| 20 | a bare path argument alongside `+d`/`+D` makes the C **silently lose the expansion's entries**, keeping only the directory itself | both are listed | `lsof +d DIR` prints `DIR` and its open entries; `lsof ANY_PATH +d DIR` prints `DIR` alone. Measured 2026-09-12 on a directory with one open entry (1 row vs 0) and again on fixture A (4 entry rows lost), with an existing, readable bare path — so it is not about the stat failure that found it. A correct result is dropped because of an unrelated argument. **C-DEFECT**, not reproduced; the `search-plus-d-supplies-a-surviving-item` case names `{ASUB}`, which is empty, precisely so it measures the abort rule and not this. |

| 21 | `-c`, `-u` and `-g` are **search items**: a value that matches nothing exits 1, and `-V` says `command not located:` / `no user use located:` etc. | ~~they select, but never counted as unlocated, so the run exits 0~~ **resolved 2026-09-25** | every one of the C's ten `not located` messages audited; `-c`, `-u`, `-g`, `-p ^`, each `-i` specification and the order of the lines fixed, `-s` and `-K` recorded as items 32 and 33. See "Fixed by making every search item one" above. |

| 25 | `-X` does **not** skip TCP and UDP files — it degrades them to `sock … can't identify protocol (-X specified)` | ~~option unsupported~~ **resolved 2026-09-20** | see "Fixed by measuring the five small options" below |

| 26 | a `+d`/`+D` expansion **skips a symbolic link** unless `-x`/`-x l`, and skips an entry on another file system unless `-x`/`-x f` | ~~followed every link, and never checked the device~~ **resolved 2026-09-20** | a live over-report, not a missing feature: `+d DIR` selected a file that only a link inside DIR pointed at. `identify_path` uses `metadata()`, which follows. |

| 27 | `-e <fs>` means **do not `stat`**: the row keeps name, flags and offset and loses access, TYPE, DEVICE, size, inode and link count, gaining ` (-e <fs>)` | ~~option unsupported~~ **resolved 2026-09-20** | part of the `UNKN*` DEBT closed by a deterministic trigger; the other half (an unreadable link reported with its errno) is unchanged |

| 28 | `-N` is a **search item** like `-i`: it ORs with other selecters, and the run exits 1 unless an NFS file was located | ~~option unsupported~~ **resolved 2026-09-20** (negative path) | the positive path has no oracle here — see below |

| 29 | `-Z` is gated on `is_selinux_enabled()`, a **mounted-selinuxfs** test, and prints `-Z limited to SELinux` with exit 1 where it is not | ~~option unsupported~~ **gate resolved 2026-09-20; the CONTEXT column is DEBT, deliberately** | `print.c:902` puts CONTEXT among the process columns with a grown width, and no host here has SELinux enabled, so its position cannot be observed. lsof-rs refuses loudly rather than guessing a layout. |

| 23 | an **AF_PACKET** socket is a `pack` row: the inode in DEVICE, the ethernet protocol in NODE, `type=SOCK_RAW` as the whole NAME | ~~`SOCK` / `socket:[11426]`, with a size~~ **resolved 2026-09-20** | see "Fixed by reading /proc/net/packet" below |

| 24 | a socket named through the **`system.sockprotoname` xattr** reports the KERNEL's name for it, which is not the family: `UNIX-STREAM`, `UNIX`, `PACKET` | ~~`unix`, `unix`, `packet`~~ **resolved 2026-09-20** | a latent defect in item 16's fix, which answered with the port's own `info.protocol`. That is right for TCP and UDP, where the two strings coincide, and wrong for the two families where they do not — and the netns fixture held only a TCP listener, so nothing measured it. Found while adding the packet fixture, because the same code path names a packet socket in a foreign namespace. |

| 30 | whole-host **peak RSS** was ~2.9x the C and grew with the host (9.8 MB against 29.0 MB at 1075 processes) | ~~2.9x and growing~~ **resolved 2026-09-24: 0.84x, 0.85x, 0.87x of the C at 76, 575 and 1075 processes** | **The cause recorded here in P5 was wrong.** It said the C streams each row and forgets it, and that closing the gap meant a streaming redesign of the `Backend` seam. It never read the C, which does not stream: `main.c` gathers every process into `Lproc[]` (`gather_proc_info()`, line 1343), `qsort`s it (1365) and only then prints and frees (1515–1522) — LESSONS #038's "only the oracle knows", ignored by the entry that closed P5. Both programs hold every row. A heap profile (massif, 1079 processes) put the real cost in three places, and none needed a redesign: the renderer held the table **three times** — the rows, a `Vec<Vec<String>>` of every cell (7 MB of `String` headers alone), and the whole output as one `String` — fixed by sizing the columns in one pass and writing each line in a second (22.95 → 8.57 MB); each process's `Vec<OpenFile>` kept its growth slack for the whole run (13.8 MB of capacity for 5.9 MB of rows) — trimmed after the walk (29.5 → 25.3 MB); and every row carried a 136-byte `SocketInfo` inline, used by about one row in eighteen — boxed, `OpenFile` 320 → 192 bytes (25.3 → 23.0 MB). Output byte-identical. The resource gate's whole-host ceiling drops from 3.50x to 1.30x. |
| 31 | a selected process with **no readable files** (a zombie) is **not listed**: `lsof -p <zombie>` prints nothing and exits 1, and `-V` says `lsof: process ID not located: <pid>` | ~~prints a bare `unk unknown` row and exits 0~~ **resolved 2026-09-25** | the C skips a process in state `Z` but still walks its tasks; lsof-rs now does both, and reads a task's mapped files from the task. See "Fixed by not listing zombies" above. |
| 32 | `-s TCP:<state>` is a **search item** (`TCP state not located: X`); an unknown state or protocol is fatal (`unknown TCP state name: X`, `unknown -s protocol: "x"`); and on Linux the TCP list tests every TCP **and UDP** socket by the kernel's number, UDP's being `CLOSE` or `ESTABLISHED`, and nothing else | ~~none of the three: any text accepted, the last `-s` kept, and `-sTCP:…` drops every non-TCP socket~~ **resolved 2026-09-25** | see "Fixed by making `-s` the C's state filter" above. This row had said a TCP filter "leaves UDP and unix sockets alone": **wrong about UDP**, which it filters, and corrected by measuring before the fix. The C's own defect is not copied: every `-s UDP:<state>` segfaults it (ledgered, `states-udp-names-crash-the-c`), and lsof-rs refuses the value. |
| 33 | `-K` is a search item (`no tasks located`), and `-K -a -p <a single-threaded process>` lists **nothing** — the main process is entered as a task only when it has one of its own (`dproc.c`: `Fand && ht && pidts`) | lists the process's own rows and exits 0 | **OPEN — found 2026-09-25 by the item-21 audit.** The measurement behind `SelKinds::TASK`'s `-a` exemption was made on a multi-threaded process, where the two agree. Seen again 2026-09-25: `lsof -K -w -p P`, P multi-threaded and unreadable, prints nothing in both and exits **1** in the C — `-w` leaves no task a row, so no task is located. |
| 34 | ~~option parsing stops at the first file name~~ | — | **a duplicate of item 12**, recorded 2026-09-25 by an audit that had not read the table it was adding to. Folded into 12, which now has the case this row said was missing. |
| 35 | every column is **right-aligned** but COMMAND and TASKCMD (`print.c`: `" %*s"`), FD is the descriptor right-aligned plus its access and lock characters, and NAME follows one space unpadded | ~~USER, FD, TYPE, DEVICE and NODE left-aligned~~ **resolved 2026-09-26** | see "Fixed by laying the table out as `print.c` does" above. The item named four of the five columns. Every case now compares whitespace, and that found one more difference, a space after every packet-socket NAME. |
| 36 | a UID with no password entry, or any UID under `-l`: no `-F L` field, the number eight wide in USER, and `lsof: no pwd entry for UID N` on stderr | ~~prints `L<uid>`, and a bare number~~ **resolved 2026-09-26, but for the stderr line** | the table and `-F` now match (measured with UID 65000 and with `-l`). The C writes the stderr warning once per row it prints, unless `-w`; lsof-rs writes none. |
| 37 | under `-w`, and so under `-t` (which sets it), the rows for files that cannot be read are never made, so a process whose every file is unreadable is not listed — yet still located: `lsof -t -p 1` prints nothing on this host, and exits 0 | ~~the blank row, and `-t` prints the pid~~ **resolved 2026-09-25** | see "Fixed by reporting what could not be read" above. The fast path still skips the file walk; it asks whether one link reads. |
| 38 | `-c /regex/`, and `-i` host names (`@localhost`) and service names (`:http`), which the C resolves | refused, with an error | **DEBT — recorded 2026-09-25.** Refusing replaced a silent wrong answer: `-c /re/` was a literal that matched nothing, and `-i:http` matched every Internet file. A regex engine is new attack surface; a resolver contradicts "No hostname or service resolution" below. |
| 39 | `-u <name>` resolves through NSS (`getpwnam(3)`) | reads `/etc/passwd` only, so an LDAP/SSSD account cannot be named — its UID can | **DEBT — recorded 2026-09-25**, the limit the USER column already has. |
| 40 | `-e <fs>` exempts **mapped files** too: each `mem` row under it is `UNKNmem` (a deleted one `UNKNdel`), built from the maps line alone, never `stat`ed | stats the mapped file and prints `REG` | **DEBT — found 2026-09-25**, measured with `-e /`, by the coverage ledger's `UNKN*` waiver, which had given another reason for it. The cwd/rtd/txt/fd half of `-e` has matched since 2026-09-20. |
| 41 | `-L` **disables** the NLINK column (the default) and takes no number (`no number may follow -L`); `+L` enables it, and `+L <n>` enables it and selects files with fewer than `n` links | `-L` **shows** the column, and a bare `+L` is refused: `option +L requires a count`, or, followed by another option, `invalid +L count: -a` | **OPEN — found 2026-09-26** by the layout work. Lsof.8: "enables (`+`) or disables (`-`)". The Windows smoke case `link-count-dash-L` asserts lsof-rs's reading, so fixing it changes Windows too. |
| 42 | `+L1` selects only files whose link count `stat` recorded and found below 1 (`dnode.c`: `SB_NLINK && nlink < Nlink`). A socket's inode reports 1, so no socket is selected | a row whose count lsof-rs never read (every socket built from `/proc/net`) passes the filter | **OPEN — found 2026-09-26.** `lsof +L1 -a -p P` on a process holding two deleted files: the C lists those two, and lsof-rs lists them plus its unix socket. |
| 43 | `-F` takes its field list as the **next word** too: `lsof -F pL -p P` prints `p` and `L` | reads `pL` as a file name: `status error on pL` | **OPEN — found 2026-09-26.** The same shape as `-s`'s and `-i`'s optional values, fixed for those two in DIVERGENCES 6 and 21. |
| 17 | the NAME cell shows **the name you asked about**: `lsof /a/hard.txt` prints `hard.txt` for an fd the process opened as `f.txt` | prints the name the process actually opened | renderer. Both find the same fd on the same inode. The C's choice also makes its exit status order-dependent: with two names for one inode in a `+d` expansion it binds the row to one and reports the other unlocated, exiting 1. **DECISION** — printing what the process opened is the more truthful answer, and it does not inherit that bookkeeping artefact; ledgered as `path-bare-hardlink`. |

Items 4–9 were found by the Linux differential in one afternoon, on fixtures of
a dozen open files. None was visible to the Windows smoke suite or the golden
tests, because a golden test pins what its author believed the C emits.

## Deliberate, and staying

- **No hostname or service resolution.** lsof-rs behaves as if `-n -P` were
  always given; both flags are accepted as no-ops. Resolution costs DNS traffic
  from a diagnostic tool, which is a poor default for where this runs. The
  differential passes `-n -P` to the C for parity.
- ~~**Inaccessible files are omitted, not reported with an errno.**~~ Not
  deliberate, and not staying: fixed 2026-09-25 — see "Fixed by reporting
  what could not be read". The obstacle this entry gave was never real.

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

