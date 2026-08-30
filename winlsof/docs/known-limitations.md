# winlsof — known limitations

What v0.1.0 deliberately does **not** show, and why. Each item links to the
engineering spike record in [`research-roadmap.md`](research-roadmap.md) where
applicable. The omissions are platform-API limits, not implementation bugs —
emitting fabricated data would be misleading, so we don't.

## Sockets

### Socket rows show `unk` for FD

Internet sockets are enumerated via `GetExtendedTcpTable` /
`GetExtendedUdpTable`, which give the owning **PID** and the endpoint
addresses/state but **not the handle value**. The handle table contains
`\Device\Afd` entries owned by the same processes, but joining them to a
specific endpoint requires reading the AFD endpoint's address — only reachable
through undocumented AFD IOCTLs (what Process Hacker / TCPView do at a
driver-adjacent level).

**What we show instead:** the access character is rendered as `u` (read/write),
which matches lsof's display for sockets. The owning PID, protocol, addresses,
ports, and TCP state are all accurate.

**Path forward:** an ETW (`Microsoft-Windows-TCPIP`) consumer is the safe,
public-ish path and is the next open roadmap item — see
[`research-roadmap.md`](research-roadmap.md) §5.

### `-i` covers TCP and UDP by default; raw/ICMP/AF_UNIX are ETW-sourced

There is no public IP Helper table for raw sockets (`SOCK_RAW`), ICMP, or
AF_UNIX endpoints. Those families are recoverable through a short ETW capture
against the `Microsoft-Windows-Winsock-AFD` provider: `--etw` adds every
non-TCP/UDP socket observed during the capture window as extra `-i` rows,
`-U` narrows the output to AF_UNIX, and `-iICMP` / `-iRAW` filter to those
families directly (each of the three implies the capture on its own). All
need Administrator (ETW session), and only sockets with AFD activity during
the ~2 s window are seen — it is a sample, not a table dump.

## Files

### No byte-range lock column

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

`SIZE/OFF` under `-o` uses `NtQueryInformationFile(FilePositionInformation)` on
a duplicated handle (which shares the owner's file object). It works for
seekable files; non-seekable handles (pipes, sockets, character devices)
report blank, which matches lsof's behavior.

## Visibility

### Some processes are inaccessible without elevation

By design — winlsof runs as the current user (`asInvoker` manifest) and never
auto-elevates. Protected processes, processes owned by other users, and
processes for which the token can't `OpenProcess` simply don't appear in the
results. The CLI prints a one-line hint about re-running as Administrator
when a system-wide switch is used; `-V` reports how many processes were
inaccessible. This mirrors Unix `lsof` without root.

### `cwd` / `txt` / `mem` collection is time-bounded

Gathering a process's working directory, loaded modules and mapped files means
reading a *foreign* process (PEB reads, `CreateToolhelp32Snapshot`,
`VirtualQueryEx`), any of which can block indefinitely on a wedged process. That
whole phase therefore runs concurrently under a **single 5-second budget**;
whatever has not reported by then is omitted, and the run continues.

In practice every process reports in well under the budget. It can bite on a
heavily loaded machine *when elevated*, because `SeDebugPrivilege` makes these
reads genuinely succeed against hundreds of processes rather than failing fast —
so a few processes may show no `cwd`/`txt`/`mem` rows. Set `WINLSOF_TRACE=1` to
see a `per-process extras N/M within budget` line whenever anything was dropped.

The alternative is worse: before 1.0.1 this phase waited on each process in turn
for up to 2 seconds apiece, so its cost scaled with process count — a measured
`lsof +D %TEMP%` took **214 seconds** on a normal desktop. Bounded-and-complete
is not available here; bounded-and-slightly-incomplete beats unbounded.

## Distribution

### Released `lsof.exe` is unsigned

Until [code signing](code-signing.md) lands, the distributed binary triggers:

- **Windows SmartScreen** on first run ("More info → Run anyway"), and
- **Microsoft Defender** PUA / hacktool false-positives, which can block the
  launch entirely. Heuristic AV flags handle-enumeration tools that enable
  `SeDebugPrivilege` and read process memory; Sysinternals' own
  `handle.exe` / Process Explorer get the same treatment.

The binary itself is fine — verify the download against the published
`lsof.exe.sha256`. Workaround for a blocked launch is documented in the
[README](../README.md) (Defender exclusion via `Add-MpPreference`). A
locally built binary is not internet-marked and is usually not flagged.

## Where these limitations are tracked

- **Spike records** (closed gates with the engineering reasoning):
  [`docs/research-roadmap.md`](research-roadmap.md) §1 (socket-FD /
  AF_UNIX / raw), §2 (byte-range locks).
- **Open work items**: §5 (ETW-based socket→FD correlation),
  plus the [code-signing tracking doc](code-signing.md).
