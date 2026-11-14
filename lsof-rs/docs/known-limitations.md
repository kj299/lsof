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
`--etw` is accepted and ignored; a raw socket is the C's `raw` row, and `-i
icmp` and `-i raw` are refused there, as the C refuses them), and the lock
column is read from `/proc/locks`.

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

### On Windows, socket host names cost up to 2 s per distinct address

Like the C, lsof-rs on Windows names each socket's hosts by reverse DNS by
default (`GetNameInfoW`, which sends a PTR query); `-n` turns it off. Each
lookup is waited on for at most **2 s**, after which the address is shown
numerically. Each distinct address of the run is looked up **once** (a host's
sockets repeat a handful: `127.0.0.1`, `::1`, its own, a few peers), on a pool
that dispatches at most **8 lookups at a time**, so a resolver that never
answers costs about `ceil(distinct / 8) x 2 s`, not 2 s per endpoint. The 8
bounds the lookups waited on, not the PTR queries in flight: a lookup abandoned
at 2 s returns, but its `GetNameInfoW` call may run on in the background until
the OS resolver gives up, which can take longer, so a silent resolver can have
more than 8 outstanding. The threads stay bounded by the distinct addresses
plus the 8 workers, and none of them delays exit. Before this was fixed it was
2 s per endpoint, serially: measured on a Windows 11 host, an unelevated `lsof`
with 145 socket endpoints spent 83 s here, and `lsof -N -V` 66 s.

A run whose output can show no socket NAME looks nothing up: `-t`, a path or
`+d`/`+D` argument, and `-N` alone or under `-a` (no socket is on an NFS file
system); nor does `-n`. `LSOF_RS_TRACE=1` prints `resolve hosts start (N
distinct)` and `done (answered, named)` around the phase. Where even that is
too slow, `-n` skips it.

### On Linux, a socket's host name may cost a DNS query

As in the C, each address a printed socket row holds is named once a run
(across `-r`'s cycles too), in print order: from `/etc/hosts`, or from DNS
where `/etc/nsswitch.conf` says so (`files dns` where it says nothing), by
lsof-rs's own PTR query (`std` has no reverse lookup, and the three
`forbid(unsafe_code)` crates cannot call `getnameinfo()`). The query follows
glibc 2.39's resolver in every rule measured against the C (DIVERGENCES 154):
`/etc/resolv.conf`'s first three name servers in turn, `attempts` rounds,
each server waited for `timeout << n` seconds, divided by the servers'
count but for the first, one second at least; `RES_OPTIONS` read after the
file; `rotate`, `use-vc`, `edns0`, `trust-ad`. So a name server that does not
answer costs each such address what it costs the C: by that rule 10 s with
glibc's defaults and one server, 20 s with two, `attempts:N` times the
round (measured: 10.04 s for three servers at `timeout:2`). `-n`
asks nothing; so do `-t`, `-F` without `n`, and JSON, which print no host
name. A run with no Internet socket row asks nothing.

What is not followed, and why: a source other than `files` and `dns` in
`hosts:` (`mdns`, `resolve`, `myhostname`, `sss`) cannot be asked without
the C library and is taken as not installed (`UNAVAIL`), as row 38 takes
one; nscd is not asked; `/etc/resolv.conf` is read once a run, where glibc
reads it again when it changes; the names found are kept for the whole run,
as the C keeps them, with no cap on how many; an `edns0` query whose server answers
`FORMERR` is not asked again without EDNS, as glibc would; an IPv6 name
server's `%scope` naming an interface is looked up in
`/sys/class/net/NAME/ifindex`. A TCP exchange after a truncated reply,
which glibc waits on without a limit, has the time the same server's
datagram attempt had. IPv6 sockets are named by glibc's rules (`ip6.arpa`,
an IPv4-mapped end as IPv4) but could not be measured: this project's
test host has no IPv6.

### On Windows, `-i` covers TCP and UDP by default; raw/ICMP/AF_UNIX are ETW-sourced

There is no public IP Helper table for raw sockets (`SOCK_RAW`), ICMP, or
AF_UNIX endpoints. Those families are recoverable through a short ETW capture
against the `Microsoft-Windows-Winsock-AFD` provider: `--etw` adds every
non-TCP/UDP socket observed during the capture window as extra `-i` rows,
`-U` narrows the output to AF_UNIX, and `-iICMP` / `-iRAW` filter to those
families directly (each of the three implies the capture on its own). All
need Administrator (ETW session), and only sockets with AFD activity during
the ~2 s window are seen — it is a sample, not a table dump. `-iICMP` and
`-iRAW` are this port's Windows extension: on Linux, as in the C, they are
`unknown protocol name`, and a raw socket is listed as the C's `raw` row
(DIVERGENCES 108).

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

`-T` does not narrow default JSON: `-J` / `-j` print every `tcp_info` member
the model holds, as the C does (it applies its default field set after every
option). Under a `-F` selection, `-T` narrows `tcp_info` as it narrows `-F`'s
`T` tokens (since 2.0.0, the C's schema).

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

A fourth difference was deliberate until 2026-11-14 and is gone: **on Linux,
lsof-rs names a socket's hosts and ports as the C does** (DIVERGENCES 154).
`192.0.2.2:43378->160.79.104.10:443` is `192.0.2.2:43378->api.anthropic.com:https`
in both, `-n` keeps the hosts numeric, `-P` the ports, and `+n`/`+P` name them
again, the last of each winning. It had printed numbers whatever was given,
because a name costs a DNS query from a diagnostic tool; it now costs what it
costs the C (see [On Linux, a socket's host name may cost a DNS
query](#on-linux-a-sockets-host-name-may-cost-a-dns-query)), and `-n` is the
way to pay nothing. The maintainer can make numbers the default again in one
line, `LINUX_NAMES_BY_DEFAULT` in `crates/lsof-cli/src/args.rs`. **On
Windows** lsof-rs names both by default as before (reverse DNS through
`GetNameInfoW`, bounded at 2 s, each distinct address once: see
[Sockets](#on-windows-socket-host-names-cost-up-to-2-s-per-distinct-address)),
and `-n`/`-P`/`+n`/`+P` read the same flags. On FreeBSD nothing is named.

What lsof-rs does resolve, on every platform, is a name it is **given**: `-i
@localhost` and `-i :http` are looked up where the option is read, as the C
looks them up (DIVERGENCES 38). On Linux a host name comes from `/etc/hosts`
by glibc's rules, and one the file does not hold from the system's resolver
(`getaddrinfo()`), so such a name can cost one DNS lookup, under
`/etc/resolv.conf`'s timeouts; an address, a number (`@127.1`) and a name the
file holds cost none. A service name comes from `/etc/services`.

## Open differences from the C

The rows of [`../DIVERGENCES.md`](../DIVERGENCES.md) a user is most likely to
meet. Each number is a row there, with the measurement behind it.

- **Refused, where the C works:** a back-reference in `-c /regex/` (38:
  `\(a\)\1`), and an expression past lsof-rs's bounds: a compiled size of
  8 MiB (`.{32767}`, `\w{0,800}`), 64 of the locale's large classes or
  65,536 characters, groups and repetitions nested 100 deep (every other
  POSIX expression glibc takes is taken); a value that is not UTF-8, in a command line that
  also holds one of U+10FF00..U+10FFFF as text (92); `-Z`, where SELinux is
  mounted (29: the CONTEXT column is not built).
- **Names only the files know** (38, 39, 154): a service name is read from
  `/etc/services` and a login from `/etc/passwd` (where `/etc/nsswitch.conf`
  has glibc read it), so one that only LDAP, SSSD, NIS or a `db` map serves
  is unknown; its port or UID works. A host name given to `-i` does reach DNS
  and the other NSS sources, through the system's resolver, but one
  `/etc/hosts` holds for IPv4 alone is not asked of DNS for IPv6, as the C
  asks it. A socket's host is named from `/etc/hosts` and DNS alone (154):
  another source in `hosts:` is not asked. nscd is not asked.
- **Linux, the time a name costs** (154): a socket row's host that
  `/etc/hosts` does not name is asked of DNS once a run, as the C asks it,
  under `/etc/resolv.conf`'s timeouts (above); `-n` asks nothing.
- **`-r m<fmt>`, `+m m` and their residues** (152, 153): a `TZ` naming a
  zone with daylight time and no rule (`EST5EDT`) takes the United States'
  rule (glibc reads `posixrules`, which is that rule where it links to
  `America/New_York`); a zone file past 1 MiB, or one that is no regular file,
  is no zone; the zone is read once a run, where glibc's `localtime()`
  looks at `/etc/localtime` again at each marker. A mount supplement that is
  a FIFO or a device, or past 16 MiB, is `error reading` it and is never
  opened, where the C waits on a FIFO or reads `/dev/zero` forever, and an
  empty one, which kills the C, names no mount; its bad lines, and what `+m`
  prints, are quoted escaped, so a directory holding a control byte prints in
  a form `+m m` cannot read back.
- **Linux, and worth knowing before running it on a busy host:** a run that
  needs the mount table — every run but `-i` alone, and that too with `-e` —
  reads it as the C does, and `stat`s each mount point once (again for a
  later row of one it could not `stat`, as the C does), never an automount
  (`autofs`) one nor an `-e`/`+e` one (110). Each such `stat`, each
  `readlink` of a path it was given, and a `+d`/`+D` walk's calls are made in
  a helper process that gives each `-S` seconds (15): a hung NFS server or
  FUSE daemon costs a run that limit per call that meets it (the mount, then
  a path argument on it, then each walk entry there) and not the run, with
  the C's `can't stat()` warning for the mount, and no automount point is
  mounted (87, 94, 118); the C's own timeout works once per run and then
  hangs. `-i` alone starts no helper and asks no mount anything. The helper it
  killed then waits in the kernel, as `lsof` in state D, until the file system
  answers or goes away, holding the descriptor its call opened there, and it
  is in lsof's own listing (123). lsof-rs never `stat`s that descriptor; the
  C's lsof listing the host, or any other tool that `stat`s
  `/proc/PID/fd/N`, waits on it. A process's own files are `stat`ed in lsof
  with no limit, as the C does without an NFS mount; with one listed they go
  through the helper too, and under `-b` are avoided, as the C's are (124);
  `-O` makes every call in lsof. Each call that meets a hung server leaves
  a killed helper waiting, with a pipe and a thread of lsof's, until the
  server answers; past 16 of them every further call fails at once,
  `Resource temporarily unavailable`, with one warning (118). A file-system argument
  names a file on its device as the C's Linux hack does: an NFS file only
  where its own NFS mount's directory starts the argument's, a plain prefix
  with no regard to a path component (so, with an NFS mount at `/mnt/a`,
  the files under a directory `/mnt/ax` on the same device, which is no
  mount, are `/mnt/a`'s NFS files, and an argument naming a mount at
  `/mnt/ax` on that device names `/mnt/a`'s files as well as its own),
  and any other file only through a file system that is not NFS (151). A `+D` walk makes one helper round trip per entry, its
  `lstat`, and one more for a link `-x l` follows: about 0.08 ms an entry, 1.6
  times the C's (`+D /usr/lib`, 17,742 entries, 1.39 s against 0.86 s; `-O`
  0.13 s; 94, 111).
- **Linux:** `-E`/`+E` name every end the C names (56), and where no
  netlink socket can be made (a sandbox without `AF_NETLINK`) end the run
  as the C does, exit 1, nothing listed; their output grows with the square
  of an object's holders, as the C's does (2,000 processes on one pipe
  print 276 MB; THREAT-MODEL §2) [2026-11-07; an `O_PATH` descriptor on
  a socket file is the C's `sock` row (126); 2026-10-30: AF_VSOCK, ping and
  unbound sockets are named as the C names them, from
  `system.sockprotoname` (22), and a bound netlink socket from its table
  (109)]; a login name is read from `/etc/passwd` only, by glibc's `files`
  rules, so an LDAP or SSSD account can be named by its UID alone (39, 70),
  and a control byte in one is escaped where the C prints it raw (70).
- **Output shape:** `-J`/`-j` print the C's schema since 2.0.0 (91), but an
  Internet row keeps a `name` (134) and DEL, C1 and U+2028/2029 are escaped
  (135), both C-DEFECT; a byte that is not UTF-8 prints as U+FFFD in NAME,
  TASKCMD and JSON, where the C prints `\xff` (COMMAND, USER and their `-F`
  fields print it as the C; 93); the `lsof: no pwd entry for UID N` warnings
  (Linux) are written before the listing, so on a merged stream (`2>&1`)
  whose listing passes 4 KiB they sit where the C's do not (the C writes the
  printing pass's where its stdout buffer flushes, mid-line), though each
  stream alone is byte-identical (36, not emulated).
- **Deliberate:** options after the first file name are still options (12); a
  `+d`/`+D` walk stops at 200,000 entries or 16 MiB of names, and says so (81).
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
