# Threat model — lsof-rs

Scopes what "secure" means for this port, and tells the port loop which modules
touch untrusted input (fuzz those first) and which cross a privilege boundary
(audit those hardest). Written against the tree as of 2026-09-20, and checked
against the code again on 2026-10-04, when a drift audit corrected the claims
below that had stopped being true. Every claim was checked against the code
rather than inferred from the C's design.

`lsof` reports which files processes have open. It is an **observer**: it has no
network listener, and the one process it starts is, on Linux, its own bounded
helper (the same binary, re-executed; §2, DIVERGENCES 94). On Linux it writes
nothing but that helper's command name. On Windows two opt-in paths change
transient state: an elevated `-T q` or `-T w`
turns EStats collection on for each selected TCP connection — other processes'
included — reads it, and turns it off again; and `--etw` (which `-U`, `-iICMP`
and `-iRAW` imply) starts and stops a named ETW session for about two seconds.
Its risk is therefore asymmetric — almost all of it is in *reading hostile data*
and in *what it discloses*, not in what it changes.

## 1. Assets — what are we protecting?

**The integrity of the reporting process itself.** Every byte lsof-rs parses is
supplied by something it does not control: another user's process name, a
filename someone chose, a `/proc/net` table the kernel formats from packets that
arrived from the network. A crash is a denial of the tool; memory corruption in a
tool people run as root is worse. This is the primary asset and the reason the
fuzz gate exists.

**The confidentiality boundary the kernel already draws.** lsof-rs must not widen
it. What an unprivileged user can see through lsof-rs should be exactly what that
user could see by reading `/proc` themselves — no more. The port takes no
privilege on Linux at all (§3), so this holds by construction there rather than
by care.

**The accuracy of the report.** Not confidentiality, but a real asset: this tool
is used during incident response. A row that is silently wrong, or an entry
silently dropped, can send an investigation the wrong way. Several of the
C-defects in §6 are exactly this failure — output that is quietly incomplete
rather than visibly broken. Accuracy is therefore in scope for the differential
gate, not just correctness-as-taste.

**The host it runs on.** Only indirectly: lsof-rs changes nothing on the host
but the two transient Windows states above and, on Linux, a helper killed on a
timeout, which stays in state D holding the descriptor its call opened until the
file system answers (§2, DIVERGENCES 123), so this reduces to not being a vector — not executing attacker data, not passing it
to a shell (the one subprocess is lsof-rs's own bounded helper on Linux: the
same binary, a fixed argument, no shell and no environment; §2, DIVERGENCES
94), and not corrupting its own memory.

## 2. Trust boundaries — where does untrusted data cross in?

Every row is an input this process does not control. The "fuzz target" column is
the answer to "what proves we survive hostile bytes here", and an empty cell in
it is a gap, not a formatting choice.

| Entry point | Source | Trust | Ported module | Fuzz target |
|---|---|---|---|---|
| CLI args, the selection grammar | invoking user or a calling script | untrusted | `lsof-cli`, `lsof-core` | `parse_args` |
| `/proc/PID/status`, `/proc/PID/task/TID/status` (the command is the `Name:` line) | **any local user's process** | **hostile** | `lsof-backend-linux::process` | `proc_status` |
| `/proc/PID/fd/N` symlink targets | filesystem, any local user | **hostile** | `lsof-backend-linux::files` | `render_escape` |
| `/proc/PID/{cwd,root,exe}` symlink targets | filesystem, any local user | **hostile** | `lsof-backend-linux::files` | `render_escape` |
| `/proc/PID/ns/{net,mnt}` (compared by inode, never parsed), `/proc/self/status` | kernel | untrusted | `lsof-backend-linux::net`, `::maps`, `::process` | not applicable |
| `/proc/PID/fdinfo/N` | kernel, per-fd | untrusted | `lsof-backend-linux::files` | `proc_fdinfo` |
| `/proc/PID/maps` | kernel + mapped filenames | **hostile** | `lsof-backend-linux::maps` | `proc_maps` |
| `/proc/net/{tcp,tcp6,udp,udp6,raw,raw6,packet,unix}`, and the same under `/proc/PID/net/` for another network namespace | kernel, shaped by **remote** traffic | **hostile** | `lsof-backend-linux::net` | `proc_net` |
| `/proc/self/mounts` | kernel + mount namespace | untrusted | `lsof-backend-linux::mounts` | `proc_mounts` |
| each mount directory, `stat`ed (an NFS, FUSE or automount point among them) | whoever serves that file system: a remote server, a FUSE daemon a local user runs | **hostile** to availability | `lsof-backend-linux::mounts` | not applicable: a liveness hazard, not a parser; see below |
| a bound AF_UNIX socket's path, `stat`ed when a path argument is given | filesystem, any local user | **hostile** to availability | `lsof-backend-linux::net` | not applicable; see below |
| `/proc/locks` | kernel | untrusted | `lsof-backend-linux::locks` | `proc_locks` |
| `/etc/passwd` | operator, but arbitrary bytes | semi-trusted | `lsof-backend-linux::users` | `passwd` (`parse_passwd`); none for `parse_passwd_names`, behind `-u NAME` |
| the bounded helper's frames, both ways over its pipes (the names and link targets inside are any local user's), and `/proc/PID/cmdline` of a process named as lsof is, read to recognise another run's helper | lsof-rs's own helper; the kernel | untrusted | `lsof-backend-linux::safefs` | none — see below |
| path arguments, `+d`/`+D` trees, and the symbolic links along them | **any local user** (link targets) | **hostile** | `lsof-core::readlink`, `lsof-cli` (the walk) | none — see below |
| Windows handle table, object names | **any local process** | **hostile** | `lsof-backend-windows::handles` (enumeration), `::names` (parsing) | `windows_names` (covers `names`; the enumeration runs under ASan, not a fuzzer) |
| Another process's PEB, via `ReadProcessMemory` | **the target process** | **hostile** | `lsof-backend-windows::peb` (the Win32 calls), `::peb_walk` (the walk) | `windows_peb` (covers `peb_walk`) |
| ETW AFD event payloads (`--etw`, `-U`, `-iICMP`, `-iRAW`; Administrator) | **any process's socket activity** | **hostile** | `lsof-backend-windows::etw` | none — see below |
| Toolhelp process names (`szExeFile`), module paths (`szExePath`), mapped-file names (`GetMappedFileNameW`) | **any local process** | **hostile** | `lsof-backend-windows::process`, `::modules`, `::mapped` | `windows_names` (covers `wide_to_string`) |
| account names (`LookupAccountSidW`), Restart Manager results | the OS, a domain controller | untrusted | `lsof-backend-windows::process`, `::restart` | none |
| IP Helper tables, TCP EStats | kernel, shaped by **remote** traffic | **hostile** | `lsof-backend-windows::sockets`, `::tcpinfo` | none: fixed-layout OS structures, bounds-checked |
| reverse DNS names (`GetNameInfoW`), on by default; `-n` turns it off | **whoever answers for the peer's PTR record** | **hostile** | `lsof-backend-windows::resolve` | none; see below |
| `LSOF_RS_TRACE`, `WINLSOF_TRACE` | operator | trusted-ish | tracing setup | not applicable |

Three things about this table are worth saying out loud, because they are the
difference between it being a security document and being a diagram.

**"Hostile" is not rhetorical.** Any local user can start a process whose `comm`
and `cmdline` are bytes of their choosing, and open a file whose *name* is bytes
of their choosing. On Linux a filename is a NUL-terminated byte string with no
encoding guarantee — it is not UTF-8, and assuming it is has been a real bug in
this family of tools. `/proc/net/tcp` is one step further out: its contents are
shaped by whoever sent packets to this host. These are not "semi-trusted config
files"; they are adversary-controlled inputs reached without authentication.

**The PEB walk follows pointers the target wrote.** `peb.rs` reads another
process's memory at documented `RTL_USER_PROCESS_PARAMETERS` offsets via
`ReadProcessMemory`, for both 64-bit and WOW64 targets. The *target* process can
write its own PEB, so the length and pointers read there are attacker-chosen.
The walk is the portable `peb_walk.rs`: every address is computed with
`checked_add` after `usize::try_from`, and one that does not fit is no `cwd`
row, as a failed read is. Until 2026-10-09 this row had no fuzz target, and the
walk added its offsets with a plain `+`: a `ProcessParameters` above
`0xFFFF_FFFF_FFFF_FFC7` wrapped, so lsof read the `DosPath` from an address in
`0x0..0x37` (with overflow checks on, it panicked that pid's worker instead).
With a stand-in reader on Linux, a string planted there named the row; whether
a Windows process can map those first bytes was not measured. Now the
`windows_peb` fuzz target runs the walk on Linux over arbitrary memory images
and checks that every read is at the unwrapped address, unit tests pin the
wrapped pointer, and `clippy::arithmetic_side_effects` is denied in `peb.rs`
and `peb_walk.rs`.

**Four later rows have no fuzz target.** `lsof-core::readlink` spells a
path as the C's `Readlink()` does, following links whose targets any local user
chooses. It is bounded (20 links, 4096 bytes), and when it landed it was compared
with the C's own function over 543,840 random spellings, but that was a one-off
run: no cargo-fuzz target drives `resolve_with`, although it is pure and could
be. `etw.rs` parses AFD event payloads (`parse_afd_create`, `parse_afd_address`,
`parse_sockaddr`) that any process's socket activity shapes; the parsing checks
its bounds, but it is Windows-only code and no fuzzer reaches it.
`users::parse_passwd_names`, behind `-u NAME`, follows `parse_passwd`'s rules for
a malformed line, but only `parse_passwd` has a target. The bounded helper's
frame decoders (`read_frame`, `decode_stat`, `decode_error`, `decode_names`)
check every length before they allocate and are unit-tested with malformed,
short, oversized and foreign frames (DIVERGENCES 94), but no fuzzer drives
them.

**A mapped file is `stat`ed by a name its owner chose.** Each distinct
mapping in `/proc/PID/maps` is described by a `stat`: of its path, or, for a
process in another mount namespace (the inodes of `/proc/self/ns/mnt` and
`/proc/PID/ns/mnt` differ), of its link under `/proc/PID/map_files/`, which the
kernel follows into that namespace for `CAP_SYS_ADMIN` alone; to anyone else
the row says `(stat: Operation not permitted)`, as the C's does. Two of the C's
habits here lsof-rs does not keep (DIVERGENCES 102, 103). The C `stat`s a
mapping's name that is no path, such as `anon_inode:[io_uring]`, relative to
its own working directory, so a file planted under that name in the directory
lsof runs in, often a shared one like `/tmp`, is described in the mapping's
place, and a link planted there into a hung file system stops the run;
lsof-rs never `stat`s such a name. And the C ends a mapping's name at a TAB,
so a library its owner named `libssl.so`, a TAB and more passes for the real
`libssl.so`; lsof-rs keeps the whole name. A `stat` of a real path can still
block on a hung file system, as an fd's can: a process's own files are
`stat`ed in lsof with no limit, as the C `stat`s them when its mount table
lists no NFS mount (DIVERGENCES 124), and `-b` guards in both only the paths a
user names and the mount table, not these. `-e` exempts by a plain prefix of
the path, as the C does, so `-e /mnt` exempts `/mnt2` as well.

**A mount directory is `stat`ed on every run, through a bounded helper**
(DIVERGENCES 110; its timeout half fixed 2026-10-09 by 94). The C reads the
mount table only when a run needs it, `stat`s each directory through a child
process under a 15 s `alarm()`, skips `autofs`, `pipefs`, `sockfs` and
automounter sources, and never `stat`s an `-e` mount; under `-i` alone it
`stat`s none. Its alarm works once per run (118), so a mount that never answers
hangs it all the same. lsof-rs `stat`s every mount directory on every run but
`-f`, `-i` included, and since 2026-10-09 makes each `stat` and each source's
`readlink` in a helper process that gets `-S` seconds (15) for it: a hung NFS
or CIFS server, or a FUSE daemon that never answers (measured with
`differential/fuse_hang.py`), costs a run that limit per call that meets it —
the mount, a path argument on it, each walk entry there; one `Readlink()`
costs at most one — and lsof exits, is reaped, and closes its output; the
helper it killed waits in the kernel instead, with one of lsof's threads
reading its pipe until lsof exits. `-b` makes no such call. The `stat` opens the path `O_PATH`,
which, like `stat(2)`, mounts no automount point, where std's `statx` did.
What stays open is the rest of 110, the next piece of work: lsof-rs still
reads the table under `-i` alone, so a hung server costs `lsof -i :22` the
limit where it costs the C nothing; it still `stat`s an `-e` mount and the
types the C skips; and it says nothing of a mount it drops (87). A bound
AF_UNIX socket's path, like a process's files, is `stat`ed in lsof with no
limit (124).

**The bounded calls run in a second process** (DIVERGENCES 94, 123). lsof
re-executes its own image, `/proc/self/exe` — never the binary's path, which
anyone who can write its directory could replace between lsof's start and
the helper's; run through the dynamic loader, the loader is that image and is
given the program's path, as lsof was — with one fixed argument, an empty
environment, lsof's working directory (as the C's forked child has it, so a
relative path names the same file), `/dev/null` as stderr and two pipes as
stdin and stdout.
The helper serves only on pipes; every frame is length-checked on both sides
before anything is allocated, and lsof takes no reply from a process that did
not greet it with the protocol's magic and version. A user who runs the
hidden argument by hand gets nothing they could not do anyway: the helper
`stat`s and reads links as its caller, and lsof-rs is never setuid on Linux
(§3). The helper names lsof's `/proc/PID` for `/proc/self`, however a path
spells its way there, by the pids procfs gives (DIVERGENCES 89). One killed
on a timeout can stay in state D until the file system answers or its
connection is aborted, holding its pipes, `/dev/null`, and any descriptor
lsof was given without close-on-exec, which std cannot close: a reader waiting
for EOF on such an inherited pipe waits as long. The C's child, a fork, holds
the same. It also holds what its call opened, which the C's child does not:
the `O_PATH` descriptor of a `stat` (std's one `stat` that mounts no
automount point) or a directory it was listing, on the file system that did
not answer. **Whatever `stat`s `/proc/HELPER/fd/N` meanwhile waits there
too**: measured, before lsof-rs learned to skip them, its own whole-host run
hung on its killed helper's fd 3, and the C's `lsof -p HELPER` does. lsof-rs
neither `stat`s nor lists a helper's close-on-exec descriptors — exactly the
ones it opened; its pipes, `/dev/null` and what it inherited are not — for
this run's helpers by pid and another run's when it runs the same file
(`/proc/PID/exe`) with the helper's argument; a program that only names
itself so is not skipped. Another tool, the C's lsof, or an lsof-rs that is
not the same file, waits on it until the file system answers; so does any of
them on an lsof `-O` waiting in its own `stat`, which holds the same
descriptor (119).

**A `+d`/`+D` entry was `stat`ed twice** (DIVERGENCES 111, resolved
2026-10-10). The walk `lstat`ed each entry, then `stat`ed the same path again,
following links, to identify it. A local user who could rename in the walked
directory could swap a link in between, so the entry took another file's
identity, even on another device past `-x f`, and the processes holding that
file were listed under the walked tree (measured: a file renamed into a link to
a file on a tmpfs, during the first call). It mattered most for root walking a
directory others can write, such as `/tmp`. Now an entry is what its one
`lstat` says, as the C's (`arg.c:1014,1077`): its identity, the `-x f` test,
whether it is a link and whether `+D` descends into it all come from that call,
an `O_PATH|O_NOFOLLOW` open and a `stat` of the descriptor, which a rename
after it cannot change, and never from the listing's `d_type`. A link `-x l`
follows gets one `stat` more, whose result stands for the entry. The directory
itself is the option's one `stat`. `differential/walk_race.py` renames entries
while strace holds that call, before it runs and after, and the directory while
strace holds its listing, and lsof-rs does what the C does in each.

Two exposures remain, both the C's as well, since both walk by name:

- **A directory is listed by its name, after its `lstat`.** One that is
  swapped for a link between the two is listed through the link, wherever the
  renamer points it, by the C's `opendir()` as by lsof-rs's listing (measured:
  `walk-race-dir-to-link-descends`). Each entry found there is still `lstat`ed
  and held to the top directory's file system unless `-x f`, and the
  directory's own item keeps the identity its `lstat` saw. Opening it
  `O_NOFOLLOW` and comparing identities would close this beyond the C; it is
  not done.
- **The top directory's identity is taken when the option is parsed, and its
  listing made later.** For the first `+d`/`+D` both read the mount table in
  between: the C's `ck_file_arg()` reads and `stat`s it before `OpenDir()`
  (`arg.c:184,915`; 117 calls between the two here, 30 `stat`s and 86
  `readlink`s, measured with strace), lsof-rs once its options are parsed
  (67). For a later one the C has the table already and opens the directory
  straight after its `stat`, where lsof-rs lists it after the table and every
  walk before it, since it walks after parsing (DIVERGENCES 82). A directory
  renamed in that window is listed as whatever is then at the name, under the
  identity the `stat` saw (measured: `walk-race-top-to-link`, the same in
  both).

**A path argument named files on other file systems** (DIVERGENCES 101,
resolved 2026-10-09). lsof-rs identified a file by its DEVICE cell and inode,
and a device node's DEVICE cell is the device it names, which nodes on other
file systems name too. So `lsof -t /dev/pts/N`, which an operator may hand to
`kill`, also gave every process holding pty N of another devpts instance:
devpts numbers pty N inode N+3 in every instance, and any local user who can
make a user namespace can mount one and open pty N there (measured as
`nobody`). A container's own `/dev/null` was the host's too. And a mapping of
a node the C could not `stat` was missed, so `lsof /dev/zero` run as non-root
said nothing of a container's. The identity is now the C's, `st_dev` and the
inode, a node's on the file system that holds it, so another instance's pty
is another file.

**An `-i` error message prints its argument raw** (DIVERGENCES 112). Every
other message that quotes an argument escapes it, as the C's `safestrprt()`
does; `-i`'s parser does not, so `lsof -i "$untrusted"` can write terminal
control sequences to stderr.

**Reverse DNS on Windows tells a resolver which peers the host talks to.** It
is the default there, as in the C (Linux behaves as if `-n` were always given).
The names that come back are chosen by whoever answers for the peer's address,
and they are escaped like any name; each lookup is bounded to 2 s.

**Memory under input someone else sizes** (found 2026-10-04, from the code, not
yet measured at scale). lsof-rs reads `/proc/net/*`, `/proc/PID/maps` and each
`fdinfo` whole, where the C reads them a line at a time; it keeps two strings
per socket and, for each foreign network namespace, that namespace's whole
socket table until the run ends, although only the protocol name is read from
it; its maps reader removes repeats with a linear scan per mapping, as the C
does, but over lines it has already copied; and listing a process's tasks
copies the process's rows for each task before discarding them. A host with a
million sockets, a process with 65,530 mappings of long names, an epoll fd
watching a million fds, or a JVM with a thousand threads makes these costs
visible; the resource gate's 400 synthetic processes cannot. DIVERGENCES 30
and 81 hold what was measured.

**The environment surface is two variables.** The C `lsof` reads considerably
more, including the personal device-cache path; lsof-rs's whole environment
surface is the two trace switches above. The device cache is not ported (it is a
Unix kernel-memory-access feature this port does not need — see §5), so the class
of issues around a user-writable cache file consulted by a privileged binary does
not exist here.

## 3. Privilege transitions

**Linux: there are none.** This is the single largest security difference from
the C, and it is structural rather than careful.

The C `lsof` ships **setgid** (to the group owning the kernel memory files) and
sometimes setuid-root, opens what it needs, then relinquishes the power —
`src/main.c` carries `Setgid` and the "relinquish the setgid power" path, and
`00DCACHE` documents the model, including that `lsof` never drops setuid-root
because it keeps needing it. That design exists because the C reads kernel
memory. lsof-rs's Linux backend reads **only `/proc`**, so it needs no such
privilege: it is installed as an ordinary unprivileged binary, never calls
`setuid`/`setgid`/`seteuid`, and enumerates exactly what the invoking user is
already permitted to read. Verified by grep across the crates: no `setuid`
and no `setgid` anywhere in non-test code, and one `Command::new`, the bounded
helper's (§2, DIVERGENCES 94): the same binary as the same user, with nothing
gained.

The backend is additionally `#![forbid(unsafe_code)]`, as are `lsof-core` and
`lsof-cli`, so the Linux path cannot reach libc's privilege calls even by
accident. When lsof-rs shows fewer rows than the C, that is usually this
difference and not a defect.

**Windows: just-in-time, scoped, and never for the common case.**
`lsof-backend-windows::privilege` implements the kit's `PrivilegeGuard` RAII
pattern: a named privilege (`SeDebugPrivilege`) is enabled for *only* the
lifetime of the guard and removed on drop. It is enabled around the specific call
that needs it, only when the switches in use require system-wide data — never
globally, and never at all for queries like `-i` that work in the plain user
context. `is_elevated()` reads `TokenElevation`. Its answer picks the
user-facing hint, and it gates the guard: `handles::enumerate` enables
`SeDebugPrivilege` only when the token is already elevated and the query is not
`-i` or `-U` alone, and EStats collection (§ above) needs the same. Nothing
elevates the process itself.

The audit hotspots on Windows are therefore: the guard's drop path (a privilege
left enabled is the failure), `handles.rs` where the guard is taken, and `peb.rs`
where elevation buys the ability to read another process's memory. That crate
holds all of the port's `unsafe` — 137 blocks by `audit_unsafe.py`, every one
documented; the other three crates forbid it — which is why the unsafe-audit and
sanitizer gates are pointed at it.

## 4. Attacker capabilities we defend against

- **Supplies arbitrary bytes at any boundary in §2** — a process name of raw
  high bytes, a filename that is not valid UTF-8, a `/proc/net` line with
  unexpected field counts. Defence: no panic and no UB on any input. Enforced by
  the fuzz gate over every target listed above, plus `forbid(unsafe_code)` on
  the three portable crates.
- **Supplies bytes chosen to break the renderer rather than the parser.** Column
  widths are computed from attacker-controlled strings. Getting this wrong
  corrupts the *table*, not the process, which makes it quiet — and it is exactly
  the live C defect in §6. Defence: `render_escape` fuzz target, and the
  differential's byte-level comparison, which since this refresh distinguishes
  `\xff` from `\xfe` instead of collapsing both to U+FFFD.
- **Supplies pathological sizes** — implausible lengths or pointers in a PEB,
  huge fd counts, a very long path, a tree of links to itself. Defence: bounded,
  checked reads in `peb_walk.rs`; a `+d`/`+D` walk stops after 200,000 entries
  or 16 MiB of their names, and says so (DIVERGENCES 81); `Readlink()`'s own
  limits, 20 links and 4096 bytes. Arithmetic on values from other processes
  and the kernel is checked: the PEB walk, the query-buffer growth in
  `handles.rs` and the TDH bounds check in `etw.rs` (both through `sizes.rs`),
  and the ETW callback's counters saturate, since a panic cannot unwind out of
  that callback. A query buffer larger than the call's `u32` length can
  describe is the query failing: told a truncated length, the call never
  succeeded, and each round allocated twice the last. The release profile
  sets `overflow-checks`, so an overflow the audit missed panics rather than
  wraps; CI and the release workflow fail a build where any workspace crate,
  or the binary, lacks them (`differential/overflow_gate.py`). A panic is
  still a denial of service: exit 101 in the main thread, the loss of a pid's
  `cwd`, module and mapped rows in a Windows per-pid worker.
  `clippy::arithmetic_side_effects` is denied in `peb.rs`, `peb_walk.rs`,
  `sizes.rs`, `handles.rs` and `etw.rs` only, not workspace-wide (the Windows
  clippy job is the only one that lints `peb.rs`, `handles.rs` and `etw.rs`,
  which nothing on Linux compiles), and it does not see variable shifts, `abs`, `pow` or `sum`,
  so review still has to. (This line once claimed the lint was denied
  workspace-wide; it never was.)
- **Races the enumeration.** `/proc/PID` is inherently racy: a process can exit
  between `readdir` and the read of its entries, and a PID can be recycled.
  Defence: treat every per-process read as fallible and skip, never abort the
  listing and never report a partial row as complete. This is a correctness
  requirement that is also a denial-of-service defence.
- **Is the process being inspected.** On Windows the target controls its own PEB
  contents; on Linux it controls its `comm`, `cmdline` and the names of files it
  opens. The inspecting process must not trust any of it beyond "bytes to render
  safely".

## 5. Explicit non-goals

Stated so reviewers do not assume coverage that is not there.

- **We do not defend against an operator who already holds our privileges.**
  Someone who can run lsof-rs as root can read `/proc` as root directly; lsof-rs
  is not a confinement mechanism.
- **lsof-rs is not a security boundary between the invoking user and the
  kernel.** It shows what the caller is already permitted to see. It deliberately
  adds no access of its own on Linux (§3), so there is no "lsof-rs told me
  something I was not allowed to know" threat to defend against there.
- **No side-channel resistance.** Timing, memory-usage and ordering differences
  between runs are not treated as leaks. The tool's whole purpose is disclosure
  to an authorised caller.
- **Kernel memory access is out of scope, permanently.** The C reads kernel
  memory on several platforms and carries the setgid model and the device cache
  to support it. This port reads `/proc` and documented Windows APIs instead.
  That is a deliberate capability reduction, not an unfinished feature.
- **We do not defend the accuracy of data the platform will not give us.**
  Where an API cannot supply a field, lsof-rs reports it as unknown rather than
  fabricating it. `docs/known-limitations.md` enumerates these; the Windows
  socket-to-handle join is the main one.
- **The Windows backend's `unsafe` FFI is in scope for review but not for
  formal proof.** It is audited (`audit_unsafe.py`, every block documented) and
  sanitized (ASan on Windows, miri on the portable crates), not verified.

## 6. C-defect inventory

Two sources feed this: divergences the differential surfaced, and the Phase-0
flaw scan. Both are now present; the scan was the gap this section used to name
against itself.

### 6a. Confirmed defects, already triaged

The kit's rule is that the C is a specification which may itself be buggy, and
that a defect found in it is triaged rather than faithfully re-implemented.
[`DIVERGENCES.md`](DIVERGENCES.md) records each one as **`C-DEFECT`**, naming the
C code so the triage can be checked. The ones that bear on this model:

- **`hostile-comm-utf8-table`** — the C mis-sizes a table column when a process
  `comm` contains bytes ≥ 0x80. The scan below independently re-finds this at its
  root, `lib/misc.c:1369`. This is the §4 "breaks the renderer, not the parser"
  capability, live, in the tool's most attacker-reachable string. Not reproduced.
- **`lsof -c ^name` exits 1 on a successful listing** while `lsof -u ^name`
  exits 0, for two options the man page describes identically. lsof-rs copies
  the half that is defensible and not the asymmetry.
- ~~**A bare path argument alongside `+d`/`+D` makes the C silently lose the
  expansion's entries.**~~ **Withdrawn 2026-10-04: not a defect.** The C ends
  its options at the first name, so in `lsof FILE +d DIR` the words `+d` and
  `DIR` are two more path arguments, and `DIR` is searched for as a plain
  directory. With `+d` first, the C expands DIR (DIVERGENCES 12, 20).
- **`lsof ''` makes the C read memory it never wrote.** `Readlink()` never
  enters its loop for an empty path, then compares and copies a stack buffer it
  never initialised. In practice it searches for the previous argument's
  spelling again (DIVERGENCES 79). Undefined behaviour on an input any caller can
  pass. Not reproduced: lsof-rs `stat`s the empty path and reports the error.
- **`Readlink()` keeps a link count across arguments** after one gives up as
  too long, so the next argument's chain of 20 links is refused (DIVERGENCES 80).
  Not reproduced.
- **`-F M` prints a thread's name raw** while `c` and the TASKCMD column are
  escaped (DIVERGENCES 59). Any process can name a thread, so the C lets it write
  an escape sequence to the terminal of whoever runs lsof — the §4 renderer
  capability again. Not reproduced: lsof-rs escapes it as it escapes `c`.
- **`-s UDP:` with any state name segfaults the C** (ledgered as
  `states-udp-names-crash-the-c`, item 32). Not reproduced: lsof-rs refuses the
  value.
- **The bounded calls are bounded once per run** (DIVERGENCES 118):
  `handleint()` `longjmp`s out with `SIGALRM` left blocked, so after the first
  timeout a `stat` on a file system that does not answer hangs the C; under
  `-O` a call that outlives the limit and returns crashes it (119); a timed-out
  `readlink` is read as a one-byte link from a buffer nothing filled (120); and
  `avoiding stat(P)` prints a path raw (122). None reproduced: every call is
  bounded on its own, and the path is escaped.
- **`-u 4294967296` selects root's processes**: `enter_uid()` sums digits into a
  `uid_t` with no overflow check (`search-u-overflow-wraps-to-root-in-the-c`).
  `-p` and `-g` wrap the same way. Not reproduced: lsof-rs refuses a number that
  does not fit.
- **Quietly wrong rows**, the accuracy asset of §1: a task's PID hidden under
  `-t` (57), a socket path cut at its first space (66), an argument `socket`
  finding every unbound AF_UNIX socket (67), and `/proc/self` read as the
  child the C forks (89). None reproduced.

### 6b. The Phase-0 flaw scan

Report: [`coverage/c-flaw-scan.json`](coverage/c-flaw-scan.json), from
`python3 porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py src lib/*.c
lib/dialects/linux --json`, run from the repository root.

The harness says of itself that it is "deliberately noisy: every hit is a
*question* for the porter". So the raw count is not a finding; the triage is.

The first run produced **113** hits. Triaging them found a fifth of the output was
text that never executes, so the scanner was fixed before the numbers were written
down (§6d) — the report above is the post-fix run, **98** hits.

**28 of those are in code this platform does not compile.** Verified in the headers
rather than assumed:

- `lib/dvch.c` — the whole body is inside `#if defined(HASDCACHE)`, and
  `lib/dialects/linux/machine.h` carries `/* #define HASDCACHE 1 !!!DON'T
  ENABLE!!! */` with a caution paragraph. Dead on Linux. (This is also why the
  device cache is a §5 non-goal: the port does not implement a feature the
  reference build does not compile.)
- `lib/rnam.c`, `lib/rnch.c`, `lib/rnmh.c` — each guarded by
  `HASNCACHE && USE_LIB_RN{AM,CH,MH}`, all four commented out for Linux. Dead.
- `lib/rmnt.c`, `lib/rnmt.c` — guarded by `USE_LIB_READMNT` and by `HASNCACHE &&
  USE_LIB_RNMT`, both commented out for Linux (`machine.h`). Dead. (This page
  counted them live until 2026-10-04.)
- `lib/dialects/linux/tests/ux.c` — a test program, not linked into `lsof`.

That leaves **70 in the binary the differential actually compares against**:

| Category | Live | Triage |
|---|---|---|
| `int-overflow-mul` | 41 | **0 confirmed.** 14 are `calloc(n, sizeof(T))` with compile-time constants, and C11 requires `calloc` to detect the product overflowing. The rest are `realloc(ptr, len)` — one size argument, no multiplication at the call, so not the pattern this category describes. Whether the arithmetic *upstream* can overflow is a real question the scanner did not ask and this pass did not answer; the `dsock.c` address-assembly sites (`plen + len + 2`, from `/proc/net` data) are where I would start. |
| `toctou` | 18 | **0 confirmed.** All 18 are now real calls — the 15 that were comments and string literals are gone with the scanner fix. About half are `stat`/`lstat` on `/proc` paths; the rest are on `/dev`, `/etc/passwd`, mapped-file and socket paths, and the path-argument wrappers, and `misc.c:994` is `access()`. A race there needs a PID recycled between the stat and the open; §4 already names it, and the consequence for a read-only reporter is a wrong or missing row, not a compromise. |
| `unbounded-copy` | 4 | **0 confirmed.** The two in `dproc.c` are bounded three lines above the call, where the scanner cannot see: `:1815` copies into a buffer `malloc`'d to `strlen(p)+1` on the preceding line; `:1919` appends a postfix into space `snp_eventpoll` reserved up front (`len -= (tfd_count == EPOLL_MAX_TFDS) ? 4 : 1`, plus the NUL). `dsock.c:1091` copies a string literal. `dmnt.c:307` copies into a field sized from the source length. |
| `format-string` | 4 | **0 confirmed.** `ACCESSERRFMT` is a string-literal macro (`lib/common.h:273`). `SzOffFmt_dv` and `InodeFmt_d` are non-literal but program-constructed — built by `sv_fmt_str()` in `src/main.c` from compile-time `SZOFFTYPE` options, never from input. The `src/usage.c` hit is the scanner joining lines across an `#if`. |
| `signed-char-compare` | 3 | **1 confirmed, 1 latent, 1 false.** Detail below — this is the category that earns the scan. |

### 6c. The one category that paid for the whole scan

Three hits, three different answers, which is the argument against reporting a
count:

- **`lib/misc.c:1311`, `if (c < 0x20)` — false positive.** `safepup` declares
  `unsigned int c`. The comparison is unsigned; there is no sign bug.
- **`lib/misc.c:1369`, `if ((*sp < 0x20) || ((unsigned char)*sp == 0xff) || …)`
  — CONFIRMED, and it is the root of `hostile-comm-utf8-table`.** `safestrlen`
  takes `char *sp`, and `char` is signed on x86-64 Linux, so `*sp < 0x20` is
  **true for every byte 0x80–0xFF**. Those take the `len += 2` branch when
  `safepup` will actually render them as `\xNN`, four characters — so the width
  is under-counted by two per high byte, and the column is sized too small. The
  tell is in the same expression: the author cast for `(unsigned char)*sp ==
  0xff` and not for the `< 0x20` test beside it. Attacker-reachable through any
  `comm` or filename. Already ledgered; the scan re-found it from the source
  rather than from output, which is the stronger form of the same evidence.
- **`src/print.c:174`, `else if (val < 0x20)` — latent, and benign here.**
  `json_print_char` takes `char val`, so on x86-64 every byte 0x80–0xFF is
  "< 0x20" and takes the `printf("\\u%04x", (unsigned int)(unsigned char)val)`
  branch — which escapes it correctly. The accident produces the *safe* output.
  On a platform where `char` is unsigned (AArch64 Linux, where lsof also builds)
  the branch flips to `putchar(val)` and a raw high byte lands in the JSON
  document, which is not valid UTF-8. Not reproduced by lsof-rs and not
  reproducible by it: `render/json.rs` escapes a control character as
  `\u{:04x}` over UTF-8 `char`s, and `render/escape.rs` prints a byte it cannot
  print as `\xNN`; neither has a signed-byte branch to get wrong.

### 6d. What the scan says about the scanner

The first run's noise was not spread evenly — it was concentrated in two
mechanical classes, which made it fixable rather than something to live with:

- **10 `toctou` hits were the word `stat` inside a string literal**
  (`"%s: WARNING: can't stat() "`), and **5 were inside a comment opened on a
  code line and closed on a later one** (`int *ss /* stat(2) status result…`).
  The scanner already blanked *trailing* comments — a previous pass had fixed
  that after it accounted for 20 of 47 hits — but an unterminated `/*` needs
  `*/` on the same line to match, so continuation lines were scanned as code,
  and string literals were never considered at all.

This is the same "a comment is not code" defect `control-coverage` had in this
kit until it was fixed to search `executable_text` instead of raw bytes.
`LESSONS #002` is why it matters rather than being cosmetic: a noisy Phase-0
scanner gets ignored, and skimming is how the one real hit in this run would
have been missed.

So the scanner was fixed in the same change: `_uncommented` now carries block
state across lines and blanks string and character literal *contents*, leaving
the quotes so the format-string rule — which runs separately over the raw source
and must see whether an argument starts with a quote — still works. Both
directions of that rule are pinned, along with the two new cases and the real
call that must still be caught.

**And the fix found a blind spot, not just noise.** The old heuristic skipped any
line starting with `*`, meaning to skip comment continuations. A pointer
dereference assignment starts that way too, so `*bp = (char *)realloc(*bp, sz)`
in `src/print.c:2414` and `*cbf = (char *)realloc(*cbf, len)` in
`dproc.c:195` — both real, both executable — had never been scanned. Removing the
heuristic brought them back. A filter tuned for quiet was also suppressing
signal, which is the argument for fixing noise at the parser rather than by
narrowing what gets looked at.

Net on this tree: **113 → 98** hits, 17 of them text that never executes, minus 2
recovered false negatives. Pinned by eight self-test checks so neither the noise
nor the blind spot can come back.

**Scope note.** This is a heuristic grep, and the harness says so — it does not
replace a real SAST pass (clang analyzer, CodeQL, cppcheck). Nothing here should
be read as "the C has one defect". It should be read as: the eight classes this
scanner knows about, over the Linux-built sources, produced one confirmed defect,
one platform-latent one, and a list of questions that are now written down.
