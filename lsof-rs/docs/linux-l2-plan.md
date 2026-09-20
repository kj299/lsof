# lsof-rs — what is actually left for the Linux backend

Written 2026-09-15, after measuring rather than reading. Companion to
[`linux-backend-scope.md`](linux-backend-scope.md), which scoped L0–L3 before
any of it existed; this document replaces its L2 row with what the tree and the
C oracle actually say today.

**Headline: L2 as scoped is delivered. What still carries the "L2" label is
four unrelated kinds of work, and the largest single gap it hides is not a
Linux gap at all.**

## What the scope document promised for L2, and where it stands

| L2 item (scope doc) | Status | Evidence |
|---|---|---|
| `maps` → `mem` rows | **done** | `mem REG … /usr/lib/x86_64-linux-gnu/libc.so.6`, byte-identical to the C |
| `/proc/locks` → lock column | **done** | DIVERGENCES item 7, closed 2026-09-05 |
| named anon inodes | **done** | `[eventfd:6]`, `[eventpoll]`, `[timerfd]`, `[signalfd]`, `inotify`, `[pidfd:1153]` — all byte-identical |
| raw / netlink | **partly — see §3** | raw is resolved; packet landed 2026-09-20 (P3), netlink is the one remaining row |

Plus two items L2 acquired later and also delivered: the mount table
(`mounts.rs`, DIVERGENCES 15) and per-namespace socket reads (DIVERGENCES 16).

### The measurement behind that table

A fixture process holding thirteen deliberately awkward descriptors — eventfd,
epoll, timerfd, signalfd, inotify, netlink, packet, POSIX shm, an unlinked
regular file, a memfd, and a pidfd — diffed against the C on the same host:

```
29 rows emitted by each binary.  27 identical.  2 differ.
```

The two are the netlink and packet sockets (§3). Every anon-inode kind, the
`(deleted)` marking, the memfd, `/dev/shm`, and all sixteen `mem` rows match
the C character for character.

## 1. The gate row — the one genuinely incomplete thing

`progress.json` today:

```
lsof-backend-linux   fuzzed              ← two gates short
lsof-backend-windows unsafe_audited
lsof-cli             unsafe_audited
lsof-core            unsafe_audited
```

The Linux backend is now the **only** crate not at `unsafe_audited`, and the
reason recorded in CI for that is wrong. The `miri` job says:

> the Linux backend reads live `/proc`, which miri cannot interpose

It can. Measured on this host, `nightly` + `-Zmiri-disable-isolation`:

```
test result: FAILED. 48 passed; 2 failed         (324 s)
```

Both failures are miri shim artefacts, not crate defects:

| test | miri says | the host says | why |
|---|---|---|---|
| `device_nodes_report_their_own_number_not_the_filesystem` | DEVICE `0,0` | `/dev/null` is `rdev=259` → `1,3` | miri's `stat` shim leaves `st_rdev` zero |
| `fdinfo_reports_access_and_the_kernel_file_position` | wrong `AccessMode` | correct | miri emulates its own fd table, so `as_raw_fd()` does not name the same fd in the host's `/proc/<pid>/fdinfo` |

Same class as the `strerror` shim that forced `errno_text`'s test to be
rewritten — the interpreter is the odd one out, not the code.

**What this gate is worth — corrected 2026-09-20, by measuring it.** This
section previously called it a *weak* gate, reasoning that a
`#![forbid(unsafe_code)]` crate with 0 unsafe blocks gives miri almost no UB
surface. That reasoning was sound and the conclusion was wrong, because UB is
not all miri checks. Mutated against the real crate:

| mutation | result |
|---|---|
| a leaked allocation in `parse_mounts` | `error: memory leaked`, **exit 1** |
| an out-of-bounds read, with `forbid(unsafe_code)` lifted | `error: Undefined Behavior: in-bounds pointer arithmetic failed`, **exit 1** |
| neither | exit 0 |

The **leak** case is the one that matters, and no other gate here covers it:
this crate caches, `NetnsTables` holding a `RefCell<HashMap>` per namespace and
per pid. The UB case only bites if someone lifts the attribute — and the first
attempt at that mutation was stopped by the attribute itself, so miri is the
second line there, not the first.

Still true: the fuzz suite and the C differential carry most of the weight for
this crate. Not true, and withdrawn: that the miri arm adds almost nothing.

`unsafe_audited` then follows immediately: `audit_unsafe.py` reports
`unsafe blocks: 0  documented: 0  undocumented: 0`.

## 2. The bookkeeping is now actively misleading

The coverage gate reports **`features: 163  covered: 50  waived: 114
UNCOVERED: 0`** on Linux. Three separate defects hide in those 114.

### 2a. `opt:H` — a real feature gap on BOTH platforms, behind a wrong reason

```toml
[[waive]]
id = "opt:H"
reason = "legacy \"headers\" toggle on certain dialects"
```

No `platforms` key, so it excuses Windows too. And the reason is simply not
true of lsof 4.99.6, where `-H` is **human-readable sizes**:

```
without -H:  txt REG 254,0  6639992 114493 /usr/bin/python3.11
with    -H:  txt REG 254,0     6.3M 114493 /usr/bin/python3.11
```

lsof-rs answers `lsof: unsupported option: -H`. This is the single most
valuable item in this document: it is a working, cross-platform, renderer-level
feature (`lsof-core`, so one implementation serves both backends), it has
nothing to do with Linux, and the gate that exists to catch exactly this has
been green over it since the Windows-only days.

### 2b. Waivers whose reason has expired

| waiver | claim | measured |
|---|---|---|
| `opt:f`, `+f` | "needs `/proc/mounts`; unimplemented and untested" | both work today |
| `type:a_inode` and the anon-inode set | "DEBT (L2) … named `anon_inode` kinds" | byte-identical to the C |
| `type:UNKNmem`, deleted marking, `mem` rows | "DEBT (L2)" | `mem` rows and `(deleted)` both shipping |

### 2c. Waivers for things the C does not do here either

```
$ lsof -m /proc/mounts    →  lsof: -m not supported
$ lsof -M                 →  lsof: illegal option character: M
```

Both are waived as `DEBT (L2)` / `DEBT (L2+)`, which asserts a debt this port
does not owe. They should be waived as *not present in the Linux dialect*.

### 2d. And the crate's own header

`lsof-backend-linux/src/lib.rs` still opens **"Phase L1"** and lists `maps`,
`/proc/locks`, anon inodes, deleted marking and the mount options under *"What
it does not cover yet — deferred to L2"*. All five ship.

## 3. The two object-type rows that really do differ

```
C:     8u sock  0,9    0t0  11425  protocol: NETLINK
rs:    8u SOCK  0,9    0    11425  socket:[11425]

C:     9u pack  11426  0t0  ALL    type=SOCK_RAW
rs:    9u SOCK  0,9    0    11426  socket:[11426]
```

These two look alike and are not.

**Packet is closeable today, dependency-free.** — **done 2026-09-20**, see
DIVERGENCES item 23. What follows is the measurement that scoped it, kept as
written. One thing it did not anticipate: closing it also exposed item 24, the
*kernel's* name for a socket in a foreign namespace, because a packet socket
could suddenly be held in one. The fixture's inode is in the table:

```
$ awk 'NR>1 && $9==11426' /proc/net/packet
000000009ce56266 3 3 0003 0 1 213467 0 11426
```

`dsock.c:3626` gives the exact shape: TYPE `pack`, the **inode in the DEVICE
column**, the ethernet protocol name in NODE, and `type=SOCK_RAW` in NAME. That
is one more table reader alongside the seven `net.rs` already has.

**Netlink is not.** The fixture's netlink inode is *absent* from
`/proc/net/netlink` — that table held `4 2940 3073 2147 6 28 13 2941 8 5`, and
an unbound netlink socket never appears in it. The C did not name it from the
table; it named it from the `system.sockprotoname` extended attribute:

```
getxattr("/proc/1153/fd/8", "system.sockprotoname") → "NETLINK"
```

which is the same mechanism as DIVERGENCES **16** and the still-open decision
in **22**. So netlink is not separate work — it is more evidence for that one
pending call, and it changes the stakes: item 22 was ledgered as costing "one
NAME cell" for AF_VSOCK. It is not. The xattr is how the C names *every* socket
whose table lookup misses, so the same decision governs netlink, AF_VSOCK, and
every family added later. **This is still the owner's call, not a porting
decision** — `getxattr` has no `std` API, so it means `unsafe` FFI or a
dependency in a crate documented as needing neither.

## 4. The options that are genuinely missing

Swept every option in the C's usage line against both binaries:

| option | what it does | cost | note |
|---|---|---|---|
| `-H` | human-readable sizes | **S** | `lsof-core` renderer; fixes Windows too (§2a) |
| `-Z` | SELinux context | **S** | one read of `/proc/<pid>/attr/current` |
| `-N` | NFS files only | **S** | filter on fs type; `mounts.rs` already parses it |
| `-x [fl]` | cross mount points / symlinks under `+d`/`+D` | **M** | pairs with the path work already done |
| `-X` | skip TCP & UDP files | **M** | measure what the C actually suppresses first |
| `-e s` | exempt a mount point from `stat` | **M** | the C validates the argument against the mount table |
| `-S [t]` | stat/readlink timeout | **L** | needs a watchdog thread; see below |
| `-b` | avoid blocking kernel calls | **L** | only meaningful with `-S` |

`-S`/`-b` deserve a decision rather than an implementation. They exist because
the C `stat()`s paths that can hang on a dead NFS mount. This port reads
`/proc` and stats only what the user named, and adding a thread to a crate that
is currently single-threaded and `forbid(unsafe_code)` is a real posture change
for a narrow case. **Recommend waiving them as a design decision with that
reasoning, not carrying them as debt.**

## 5. Performance and memory

Measured with a `wait4`-based meter validated against a known 200 MB
allocation (207.4 MB observed), median of nine runs, 77 processes on the host:

| | lsof-rs | C | |
|---|---:|---:|---|
| whole host | **62.4 ms** | 65.5 ms | RSS **5.4 MB** both |
| `-i` | **9.4 ms** | 5.7 ms | RSS 5.4 MB both |

Memory is identical and flat. Time is fine whole-host and **65 % worse on
`-i`** — 8.9 ms against 5.3 ms, dropping to 4.6 ms when constrained to one pid,
so the cost is the whole-host fd walk, and it scales with process count. Not a
blocker at 77 processes; worth one profiling pass before it is measured on a
host with thousands.

## 6. Recommended order

**P1 — make the bookkeeping true (½ day).** Fix `opt:H`'s reason and implement
`-H`; rescope `opt:m`/`opt:M` as not-in-dialect; retire the expired waivers;
rewrite the `lib.rs` header. Do this first because every later claim in this
document is read through those files, and one of the four defects is a live
feature gap on both platforms.

**P2 — close the gate row (½ day).** Add a miri arm over
`lsof-backend-linux` with the two shim-bound tests excluded by name and each
exclusion carrying its measured reason; land it observe-first per LESSONS #13,
promote on consecutive log-verified greens. **As its own job, not a step** —
the first attempt put it in the existing miri job and its 25-minute timeout
cancelled that hard gate, because `continue-on-error` is a step property and
`timeout-minutes` is a job one (LESSONS #036).

| head | result | wall |
|---|---|---:|
| `8a4b2ea` | 48 passed, 0 failed, 2 ignored | 2557 s |
| `22a9882` | 55 passed, 0 failed, 2 ignored | 1216 s |

Seven more tests in less than half the time — runner variance, not the suite,
and a reminder that one timing is not a measurement. Locally the same command
is ~295 s; the ~5700 `/proc` warnings account for the gap. **Two consecutive
log-verified greens**, which is what the promotion rule asks for. Then
`unsafe_audited`. Fix the
`miri` job comment, which currently states a falsehood. Extend
`check_ledgers.py` to check the sanitizer ledger **per crate** — it is
satisfied today by any one job existing anywhere in the workflow, which is what
let this row sit open unnoticed.

**P3 — packet sockets (1 day). DONE 2026-09-20.** `/proc/net/packet`, the
`dsock.c:3622` column shape, differential cases, and the `proc_net` fuzz target
extended. Four things the plan did not see coming, each recorded where it
belongs:

* the protocol table needed **measuring, not transcribing** — a 100-socket
  sweep against the C found a 7-byte truncation, a decimal-from-hex fallback
  and a name containing a space;
* `-F P` was being read from `socket.protocol` rather than from the NODE cell,
  which is indistinguishable for TCP and wrong for a packet row;
* item 24 — the namespace fallback was answering with the port's own protocol
  name, right for the two families the netns fixture held and wrong for the two
  it did not. **No unit test kills that mutation**; only the new fixture L does;
* the fuzz target's new arm was **unreachable** until the valid header was
  prepended to the input — proved by planting a panic in the row loop
  (LESSONS #037).

**P4 — the small options (1–2 days).** `-Z`, `-N`, then `-x`, `-X`, `-e`.

**P5 — the `-i` profiling pass**, and a resource gate if one is wanted: peak
RSS and wall time on a whole-host scan, asserted against a ceiling. Nothing
gates either today.

**Not scheduled, and deliberately:** `-S`/`-b` (§4), the `UNKN*` errno rows
(DIVERGENCES, still real debt), DIVERGENCES 21 (`-c`/`-u`/`-g` as search
items), DIVERGENCES 9 (`opendir` access `u`), and DIVERGENCES 22 — which now
carries netlink as well as AF_VSOCK, and is the one item on this page that
needs a decision from the owner before any of it can be written.
