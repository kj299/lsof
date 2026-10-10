# lsof-rs — known limitations

What lsof-rs does **not** show, or shows differently from the C, and why. Each
item links to the engineering spike record in
[`research-roadmap.md`](research-roadmap.md) where applicable. The Windows
omissions are platform-API limits, not implementation bugs — emitting fabricated
data would be misleading, so we don't. The complete list of differences from the
C, with each one's status, is [`../DIVERGENCES.md`](../DIVERGENCES.md); the ones
a user is likely to meet are summarised under [Open differences from the
C](#open-differences-from-the-c) below.

On **Linux** the first three sections do not apply: a socket row carries its fd
number, `-U` and raw sockets come from `/proc/net` without Administrator (and
`--etw` is accepted and ignored), and the lock column is read from
`/proc/locks`.

## Sockets

### On Windows, socket rows show `unk` for FD

Internet sockets are enumerated via `GetExtendedTcpTable` /
`GetExtendedUdpTable`, which give the owning **PID** and the endpoint
addresses/state but **not the handle value**. The handle table contains
`\Device\Afd` entries owned by the same processes, but joining them to a
specific endpoint requires reading the AFD endpoint's address — only reachable
through undocumented AFD IOCTLs (what Process Hacker / TCPView do at a
driver-adjacent level).

**What we show instead:** the FD cell is `unk`, with no access letter: the table
prints one only after a descriptor number (DIVERGENCES 35). `-F`'s `a` field and
JSON's `access` key report `u`. The owning PID, protocol, addresses, ports, and
TCP state are all accurate.

**Path forward:** none in user mode. The ETW spike
([`research-roadmap.md`](research-roadmap.md) §5) found no event that carries
the handle value; mapping an AFD endpoint to a handle needs a kernel driver.

### On Windows, `-i` covers TCP and UDP by default; raw/ICMP/AF_UNIX are ETW-sourced

There is no public IP Helper table for raw sockets (`SOCK_RAW`), ICMP, or
AF_UNIX endpoints. Those families are recoverable through a short ETW capture
against the `Microsoft-Windows-Winsock-AFD` provider: `--etw` adds every
non-TCP/UDP socket observed during the capture window as extra `-i` rows,
`-U` narrows the output to AF_UNIX, and `-iICMP` / `-iRAW` filter to those
families directly (each of the three implies the capture on its own). All
need Administrator (ETW session), and only sockets with AFD activity during
the ~2 s window are seen — it is a sample, not a table dump.

## Files

### On Windows, no byte-range lock column

lsof shows lock state (`R`/`W`/`r`/`w`/`u`/`X`/`x`) for ranges held via
`fcntl`/`flock`. On Windows, the only API that **enumerates** a file's locks is
`FsRtlGetNextFileLock`, a **kernel-mode** routine inside a file-system driver.
User-mode `LockFileEx`/`NtLockFile` only *create* locks; nothing in user mode
lists existing locks, and another process's share-access mode isn't queryable
either. A true lock display would require a kernel driver or an ETW FileIO
trace — out of scope for a user-mode tool.

**What we show instead:** the access character (`r`/`w`/`u`) from the
granted-access mask, which is accurate but coarser than lsof's lock state.

### `OFF` is best-effort

The `OFFSET` column (`-o`) uses `NtQueryInformationFile(FilePositionInformation)`
on a duplicated handle (which shares the owner's file object). It works for
seekable files; Windows reads a position only for disk files, so pipes,
sockets and character devices show a blank OFFSET, where the C on Linux shows
`0t0`. Since 2026-09-25 `-o` is lsof's
column on every platform — headed `OFFSET`, blank where there is no offset
rather than falling back to the size (DIVERGENCES 6).

## Visibility

### Some processes are inaccessible without elevation

By design — lsof-rs runs as the current user (as invoker, the MSVC default) and
never auto-elevates. Protected processes, processes owned by other users, and
processes for which the token can't `OpenProcess` simply don't appear in the
results. The CLI prints a one-line hint about re-running as Administrator
when a system-wide switch is used; `-V` reports how many processes were
inaccessible. This mirrors Unix `lsof` without root.

On **Linux** a process the user cannot read is listed as the C lists it: a row
for each of `cwd`, `rtd` and `txt` saying what could not be read and why
(`/proc/1/cwd (readlink: Permission denied)`), and a `NOFD` row for its fd
table. `-w`, and `-t`, leave those rows out, and then a process with nothing
readable is not listed at all (DIVERGENCES 37).

### `cwd` / `txt` / `mem` collection is time-bounded

Gathering a process's working directory, loaded modules and mapped files means
reading a *foreign* process (PEB reads, `CreateToolhelp32Snapshot`,
`VirtualQueryEx`), any of which can block indefinitely on a wedged process. That
whole phase therefore runs concurrently under a **single 5-second budget**;
whatever has not reported by then is omitted, and the run continues.

In practice every process reports in well under the budget. It can bite on a
heavily loaded machine *when elevated*, because an administrator's token makes
these reads genuinely succeed against hundreds of processes rather than failing
fast (`SeDebugPrivilege` is enabled later, for the handle scan alone) —
so a few processes may show no `cwd`/`txt`/`mem` rows. Set `LSOF_RS_TRACE=1` to
see a `per-process extras N/M within budget` line whenever anything was dropped.
(On a binary from v1.0.1 or earlier the variable is `WINLSOF_TRACE`, the name
this shipped under before the rename; current builds accept either.)

The alternative is worse: before 1.0.1 this phase waited on each process in turn
for up to 2 seconds apiece, so its cost scaled with process count — a measured
`lsof +D %TEMP%` took **214 seconds** on a normal desktop. Bounded-and-complete
is not available here; bounded-and-slightly-incomplete beats unbounded.

## Distribution

### Released `lsof.exe` is unsigned

Signing is deferred by choice (see [code-signing.md](code-signing.md)), so the
distributed binary triggers:

- **Windows SmartScreen** on first run ("More info → Run anyway"), and
- **Microsoft Defender** PUA / hacktool false-positives, which can block the
  launch entirely. Heuristic AV flags handle-enumeration tools that enable
  `SeDebugPrivilege` and read process memory; Sysinternals' own
  `handle.exe` / Process Explorer get the same treatment.

The binary itself is fine — verify the download against the published
`lsof.exe.sha256`. Workaround for a blocked launch is documented in the
[README](../README.md) (Defender exclusion via `Add-MpPreference`). A
locally built binary is not internet-marked and is usually not flagged.

## Rendering divergences from the C, found by the Linux differential

These are **not** Linux-specific and **not** introduced by the Linux backend.
They live in `lsof-core`'s renderer, so they have always applied to the Windows
output too — nobody could see them because Windows has no C `lsof` to compare
against. The moment a backend landed on a platform where the reference
implementation runs on the same host, all three fell out of a single
side-by-side run.

All three have since been **fixed**, and each turned out to be larger than the
one-line entry suggested. They are kept here because the change is visible on
Windows too, where there is no C to compare against:

| # | The C, now matched | what lsof-rs did before |
|---|---|---|
| 1 | `(LISTEN QR=0 QS=0)` — **one** parenthesised group, space-separated, in `print_tcptpi()`'s own order | one group per fact: `(LISTEN) (QR=0) (QS=0)` |
| 2 | `-T`'s letters **select**: `-T q` is the queues *instead of* the state, a bare `-T` annotates nothing, and `+T` restores the state-only default | treated them as additive, and rejected `+T` outright |
| 3 | `COMMAND` is capped at 9 characters (`CMDL`) unless `+c` says otherwise | printed the whole name |

Two further `-T` rules came out of the same measurement: `-T` takes a value, so
`lsof -T q` with a space works (lsof-rs read `q` as a filename and exited 1);
and `w` is not a letter the **Linux** C accepts, so `-T w` is a hard error
there while staying valid on Windows, which can actually read the window. `+c`
likewise gained two: the cut happens at the resulting **column width**, never
narrower than the `COMMAND` header — so `+c 5` prints seven characters — and a
`+c` wider than the longest command name the system can report is an error.

`-T` does not gate JSON: `-J` / `-j` remain the full structured dump, with
`state` and `tcp_*` keys whenever the model holds them. `-T` is about the
table's NAME annotation and `-F`'s `T` tokens, which is where the C applies it.

Since 2026-09-02 the Linux differential runs as a CI gate and keeps the full
list in [`../DIVERGENCES.md`](../DIVERGENCES.md), which adds six more found the
day it landed. The largest have since been **fixed**:

* lsof's **OR-by-default list semantics** — lsof-rs applied file-level selectors
  unconditionally, so `lsof -d ^mem -p PID` listed one process where the C lists
  the whole host. It now models the C's rule exactly. Add `-a` to any command
  that relied on the old intersection behaviour.
* the **`-F` field set**. `-F` is the scripting format, so a missing field or a
  reordered stream is a broken script rather than a cosmetic difference. Bare
  `-F` now matches the C byte-for-byte. Three of the eight changes are visible
  on Windows: the `f` fd marker is emitted only when it is selected (`-Fcn`
  yields `p c n`, not `p c f n`); `a` and `l` are emitted **empty** rather than
  omitted, so every file record has the same shape; and a socket's state has
  moved out of the `n` (name) field into its own `TST=` token, where the C keeps
  it. The table still shows ` (LISTEN)` — it was being reported twice.

Read that file as the authoritative ledger; this section is the narrative for
the first three, which are now closed as well.

One entry in that ledger has since been **closed rather than recorded**, because
it was a security fix and not a compatibility choice: control characters in
COMMAND and NAME were printed raw, so a process or file named with an ANSI
escape sequence drove the terminal of whoever ran lsof-rs. Both cells (and
USER) now go through the C's `safestrprt()` rules on every platform. The
deliberate differences: the backslash stays a path separator on Windows, and two
C defects are not copied — the C prints a thread name raw under `-F M`
(DIVERGENCES 59), and mis-sizes a column holding a byte ≥ 0x80
(`hostile-comm-utf8-table`). A newline in a command name (58) and the escaping
of a login name (70) are still open.
`+c 0`, which the C documents as "print every character", was also read as a
cap of zero and is now unlimited. Both are checked against the C oracle by the
differential's hostile-name fixtures.

A fourth difference is deliberate and stays: **on Linux, lsof-rs never resolves
host names or service names**, so it behaves as though `-n -P` were always
given, and both flags change nothing there. The core renders the numeric form it
is handed (`model::SocketInfo::display_name`), and resolution is a backend
concern. The C resolves by default, so `192.0.2.2:43378->160.79.104.10:443` here
is `192.0.2.2:43378->api.anthropic.com:https` there. Resolution costs DNS
traffic from a diagnostic tool, which is a poor default for the environments
this runs in. **On Windows** lsof-rs resolves both by default (reverse DNS
through `GetNameInfoW`, bounded at 2 s), and `-n` and `-P` turn that off. On
both, an `-i` address or port must be numeric: `-i@localhost` and `-i:http` are
refused (DIVERGENCES 38).

## Open differences from the C

The rows of [`../DIVERGENCES.md`](../DIVERGENCES.md) a user is most likely to
meet. Each number is a row there, with the measurement behind it.

- **Refused, where the C works:** `-c /regex/`, and host or service names in
  `-i` (38); a path argument that is not UTF-8 (92); `-Z`, where SELinux is
  mounted (29: the CONTEXT column is not built).
- **Linux, and worth knowing before running it on a busy host:** every run but
  `-f` `stat`s every mount point, `-i` included, where the C skips them under
  `-i` alone (110). Since 2026-10-09 each such `stat`, each `readlink` of a
  path it was given, and a `+d`/`+D` walk's calls are made in a helper process
  that gives each `-S` seconds (15): a hung NFS server or FUSE daemon costs a
  run that limit per call that meets it (the mount, then a path argument on
  it, then each walk entry there) and not the run, and no automount point is
  mounted (94, 118). The helper it killed then waits in the kernel, as `lsof`
  in state D, until the file system answers or goes away, holding the
  descriptor its call opened there, and it is in lsof's own listing (123).
  lsof-rs never `stat`s that descriptor; the C's lsof listing the host, or any
  other tool that `stat`s `/proc/PID/fd/N`, waits on it. A process's own
  files are `stat`ed in lsof with no limit, as the C does without an NFS mount
  (124), and `-O` makes every call that way. lsof-rs drops a mount it cannot
  `stat` without the C's warning (87), and under `-b` names each mount it
  avoids once where the C names it with four lines. Under `-i` alone the
  helper is a cost the C does not pay: under a descriptor limit with no room
  for its pipes `lsof -i` ends `can't open pipes` (110). A `+D` walk makes
  one helper round trip per entry, its `lstat`, and one more for a link `-x l`
  follows: about 0.08 ms an entry, 1.6 times the C's (`+D /usr/lib`, 17,742
  entries, 1.39 s against 0.86 s; `-O` 0.13 s; 94, 111).
- **Linux:** `-E`/`+E` are accepted and ignored (56); AF_VSOCK, ping and
  unbound netlink sockets, and a TCP socket that is bound but not listening,
  show as `SOCK` `socket:[N]` (22, waiting on a decision), and an `O_PATH`
  descriptor on a socket file as `SOCK` and its path, where the C says `sock`
  and `can't identify protocol` (126); a raw socket is `IPv4`/`IPv6` and a
  bound netlink socket `SOCK`, where the C reads their tables (108, 109); a
  login name is read from `/etc/passwd` only, so an LDAP or SSSD account can
  be named by its UID alone (39); `-f` with `-e` is refused (113); a file
  named by a path argument and its file system named by another locate both,
  where the C's row locates the file alone and the run exits 1 (125).
- **Output shape:** the JSON from `-J`/`-j` has lsof-rs's own schema, not the
  C's (91), and under `-K` a task's object repeats its process's (61); a byte
  that is not UTF-8 prints as U+FFFD, where the C prints `\xff` (93); `-F`,
  `-J` or `-j` with `-t` is accepted, where the C refuses it (90); `-h` writes
  its help to stdout, where the C writes the usage to stderr (114).
- **Deliberate:** options after the first file name are still options (12);
  NAME shows the name the process opened, not the one you asked about (17); a
  `+d`/`+D` walk stops at 200,000 entries or 16 MiB of names, and says so (81).
- **Rarer:** large UIDs (68) and the padding of a multibyte login name (71).
  The rest, including the stderr-only differences, are in the ledger.

## Where these limitations are tracked

- **Spike records** (closed gates with the engineering reasoning):
  [`docs/research-roadmap.md`](research-roadmap.md) §1 (socket-FD /
  AF_UNIX / raw), §2 (byte-range locks), §5 (ETW: no handle value in any event).
- **Open differences from the C:** the rows of
  [`../DIVERGENCES.md`](../DIVERGENCES.md) marked OPEN, DEBT or DECISION
  PENDING.
- **Signing:** deferred by choice; see the
  [code-signing tracking doc](code-signing.md).
