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

### `-i` covers TCP and UDP only

There is no public IP Helper table for raw sockets (`SOCK_RAW`), ICMP, or
AF_UNIX endpoints. The same ETW route under consideration for socket↔FD
correlation would unblock raw/ICMP visibility as well.

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
