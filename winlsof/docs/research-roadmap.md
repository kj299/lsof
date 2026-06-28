# winlsof — research-grade gaps: phased approach

These are the Phase 1–4 findings that can't be closed with a small, well-trodden
change. Each has a **spike → implement → polish** plan with an explicit
**decision gate** (so we don't sink effort into a dead end), and memory-safety
notes. Investigation showed two of these are actually achievable with public
APIs (📈 **offset**, 📈 **mapped data files**); two are genuinely API-limited
(sockets beyond TCP/UDP, byte-range locks).

Effort: S/M/L. Confidence = likelihood a *safe, public-API* solution exists.

---

## 1. Socket FD correlation + AF_UNIX / raw / ICMP  — 🔬 SPIKE COMPLETE (documented) (Effort L, Confidence Low)

**Goal:** show a real FD/access for sockets (today `unk`), and list AF_UNIX,
raw, and ICMP sockets (today only TCP/UDP via IP Helper).

**Why hard:** IP Helper tables give the owning PID but no handle; the handle
table's `\Device\Afd` entries have no address. Joining them, and reading an
AF_UNIX path or a raw socket, requires the socket's address from the AFD
endpoint — only reachable via **undocumented AFD IOCTLs** (what Process Hacker /
TCPView do at a near-driver level). `WSADuplicateSocket` needs target
cooperation, so a duplicated AFD handle can't simply be `getsockname`'d.

**Phased:**
- **P1 — spike (S):** From the existing handle table, isolate `\Device\Afd`
  handles per PID. Attempt, on a duplicated AFD handle, `DeviceIoControl` with
  the AFD "get address"/"get TDI info" IOCTLs to recover local/remote addresses.
  Measure: does it work unprivileged? for AF_UNIX? is it stable across Win10/11?
- **Decision gate:** if no safe/stable method → **stop**; ship only an
  *AFD-handle count* per process and keep TCP/UDP from IP Helper (documented).
- **P2 — correlate (M):** if viable, match AFD endpoints to the IP Helper rows
  by (PID, local addr, remote addr) to attach the real handle value/access to
  each socket row; surface AF_UNIX bound paths.
- **P3 — raw/ICMP (M):** no public table exists; evaluate an **ETW** consumer
  (`Microsoft-Windows-TCPIP`) or WFP for raw/ICMP visibility — likely a separate
  opt-in feature, not default.

**Memory safety:** all IOCTL output parsing in small audited `unsafe` wrappers
over `Vec<u8>` with length checks; no raw pointer arithmetic in the hot path.

**Spike conclusion (2026-06-15):** Confirmed against Microsoft docs —
`GetExtendedTcpTable` / `GetExtendedUdpTable` cover only TCP/UDP (PID or MODULE
owner); there is **no public IP Helper table** for raw/ICMP (`SOCK_RAW`) or
AF_UNIX endpoints, and no public way to map an `\Device\Afd` handle to its
address. Per-endpoint FD correlation and AF_UNIX/raw therefore require
undocumented AFD IOCTLs (driver-adjacent) or an ETW `Microsoft-Windows-TCPIP`
consumer — both out of scope for a safe, public-API tool. **Decision: gate
closed → documented limitation.** Shipped the one safe, accurate change:
Internet sockets now report `u` (read/write) access, matching lsof. If pursued
later, the ETW route would be a separate opt-in feature.

---

## 2. File byte-range locks  — 🔬 SPIKE COMPLETE (documented) (Effort M, Confidence Low)

**Goal:** lsof's lock indicator (e.g. `1uW`) for `LockFileEx` byte-range locks.

**Why hard:** the kernel tracks locks per file object, but there is **no public
query** for the lock list of a file or process. `NtQueryInformationFile` exposes
position/mode/name but not locks.

**Phased:**
- **P1 — spike (S):** survey what *is* observable: share-access mode and
  read/write access from the granted-access mask (we already have it), and
  whether `NtQueryInformationFile(FileProcessIdsUsingFileInformation)` plus the
  access mask lets us infer *exclusive* opens. Determine if "exclusive vs shared"
  is a useful approximation of lsof's lock column.
- **Decision gate:** true byte-range lock enumeration needs a **kernel driver or
  ETW (FileIO) trace** — out of scope for a user-mode tool. If P1 yields only the
  exclusivity approximation, ship that as a coarse lock hint and document the gap.
- **P2 — approximation (M):** render an `X`/`x` style hint for handles opened
  with no share access (likely-exclusive); clearly mark it as heuristic.

**Memory safety:** read-only `NtQueryInformationFile` calls behind safe wrappers;
no new attack surface.

**Spike conclusion (2026-06-15):** Confirmed against Microsoft docs — the only
API that *enumerates* a file's byte-range locks is `FsRtlGetNextFileLock`, a
**kernel-mode** routine (ntifs.h) that needs the file's `FILE_LOCK` structure,
available only inside a file-system driver. User-mode `LockFileEx` / `NtLockFile`
only *create* locks; nothing in user mode lists existing locks, and a handle's
share mode isn't queryable from another process. **Decision: gate closed →
documented limitation** (true lock display would need a kernel-mode driver or an
ETW FileIO trace). No safe user-mode code to add — emitting a fabricated lock
column would be misleading, so we don't.

---

## 3. `mem` for memory-mapped data files  — ✅ IMPLEMENTED (Effort M, Confidence High 📈)

**Goal:** show `mem` rows for data files mapped via `CreateFileMapping` /
`MapViewOfFile`, not just loaded modules (DLLs/EXE).

**Why feasible:** **public APIs exist** — walk the target's address space with
`VirtualQueryEx`; for each region with `Type == MEM_MAPPED`,
`GetMappedFileNameW` returns the backing file's NT path.

**Phased:**
- **P1 — spike (S):** for a known process that maps a data file, confirm
  `VirtualQueryEx` + `GetMappedFileNameW` returns its path; confirm
  `MEM_IMAGE` (already covered by the module snapshot) can be excluded to avoid
  duplicate `txt`/`mem` rows.
- **P2 — implement (M):** add a `mapped.rs` that walks regions per in-scope
  process (reusing the selection-scoping we built), maps the device path to a
  drive (existing `device_to_dos`), de-dups by file, and emits `mem` entries.
  Needs `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` (same rights as `cwd`).
- **P3 — polish (S):** merge/dedupe with module-based `mem`; bound the region
  walk; only run when not in `-i`/path mode (consistent with current scoping).

**Memory safety:** bounded `VirtualQueryEx` loop (advance by region size, cap
iterations); fixed-size wide buffer for the name.

---

## 4. File offset (`-o`)  — ✅ IMPLEMENTED (Effort S–M, Confidence High 📈)

**Goal:** lsof's current file position in the SIZE/OFF column under `-o`.

**Why feasible (key finding):** `DuplicateHandle` duplicates a handle to the
**same file object**, which carries the current byte offset. So
`NtQueryInformationFile(FilePositionInformation)` on our duplicate returns the
*live* offset of the owning process's handle — no extra access needed beyond
what we already have for naming.

**Phased:**
- **P1 — spike (S):** on a duplicated disk-file handle, call
  `NtQueryInformationFile(.., FilePositionInformation /*14*/, ..)` →
  `FILE_POSITION_INFORMATION { CurrentByteOffset: i64 }`; verify it tracks the
  owner's seek position on Win10/11.
- **P2 — implement (S–M):** in `handles::describe` for disk files, query the
  position and set `OpenFile.offset`; add the `-o` flag so SIZE/OFF shows
  `0t<offset>` (the model + table already support `offset`).
- **P3 — polish (S):** best-effort (skip on failure / non-seekable); add the
  `o` field to `-F` output.

**Memory safety:** one read-only `NtQueryInformationFile` per disk handle behind
a safe wrapper; reuses the existing duplicate.

---

## 5. ETW-based socket → FD correlation  — 🟡 OPEN, P1 SPIKE READY (Effort L, Confidence Medium)

**Goal:** show real handle / access values on socket rows (replacing today's
`unk`), and gain visibility into raw / ICMP endpoints — **without** the
undocumented AFD IOCTLs that closed item §1. The roadmap explicitly flagged
ETW as the safer follow-up route; this item formalizes it.

**Why feasible:** the `Microsoft-Windows-TCPIP` ETW provider emits events on
socket create / connect / disconnect / close that carry the owning process ID,
the endpoint (addr+port), and — in several event IDs — the kernel object /
handle. A short-lived ETW consumer can build a `(PID, local, remote) → (handle,
access)` index at gather time, then join with the existing IP Helper rows to
attach a real handle value to each socket row. The provider also exposes raw /
ICMP events, which gives item §1's AF_RAW visibility as a follow-on.

**P1 spike — ready to run.** See [`etw-spike.md`](etw-spike.md): instead of
writing the Rust consumer first, use the built-in `logman` + `tracerpt` to
capture 10 seconds of TCPIP + AFD events on Windows and dump them to CSV. That
answers the real gating question (do the events even carry handle data?) in
minutes, at zero code cost. If positive → P2; if not → close item §5 the way
§1 and §2 closed, with the artifact in hand.

**P2 — implement (M):** add `etw.rs` with a bounded realtime session (cap
duration, cap event count, drop unknown events) that populates an in-memory
index; thread the lookup into `sockets::collect`. New unsafe surface confined
to ETW buffer parsing in small audited wrappers; everything else safe Rust.
Use `windows-sys`'s `Win32_System_Diagnostics_Etw` feature for the FFI types,
matching the rest of the backend's "raw windows-sys + thin unsafe wrappers"
style — no new high-level wrapper crate.

**P3 — extend (M):** surface raw / ICMP rows on `-i` (likely as a separate
`-iRAW` / `-iICMP` flag, since the upstream lsof doesn't unify them).

**Memory safety:** ETW is a *consumer* surface — we don't emit; we parse
read-only buffers behind length-checked `Vec<u8>` wrappers. No new
network/handle attack surface.

**Open questions captured by the spike:**
- Does the modern provider include the socket handle on any of the
  TCP/UDP/AFD events, or only the (PID, endpoint) pair (which we already have)?
- Does starting an ETW realtime session require Administrator, or does
  *Performance Log Users* membership suffice? Determines whether P2 can be
  default-on or has to be opt-in / elevated.

---

## Suggested order

1. ~~`-o` offset~~ — ✅ done (`NtQueryInformationFile(FilePositionInformation)`).
2. ~~mapped-data `mem`~~ — ✅ done (`VirtualQueryEx` + `GetMappedFileNameW`).
3. ~~byte-range locks spike~~ — 🔬 done: gate closed, documented (needs a kernel driver / ETW).
4. ~~socket FD / AF_UNIX / raw spike (undocumented IOCTLs)~~ — 🔬 done: gate closed, documented; sockets now show `u` access.
5. **ETW-based socket → FD correlation** — 🟡 next open item: safer public path to attach real handle/access to socket rows, and unblock raw/ICMP visibility.

Items 1–2 shipped in v0.1.0. Items 3–4 are platform-limit gates with the future
path recorded. Item 5 is the next concrete spike — start with P1 to validate
the ETW event shape before committing to code.
