# lsof-rs — scoping a Linux backend

A scoping document, not a commitment. It answers: *what would it take to make
this a genuinely cross-platform, memory-safe `lsof`, and is it worth doing?*

**Short answer: ~2,200 lines of Rust in a new `lsof-backend-linux` crate, one
small `lsof-core` addition, and it unlocks a correctness signal Windows
structurally cannot provide — a real C-vs-Rust differential.**

Recommended sequencing: **after `v1.0.0` is cut.** See [Sequencing](#sequencing).

## Why this is even a small job

`lsof-core` was built as the dialect seam from Phase 0, and the seam holds. A
backend implements exactly one method:

```rust
fn gather(&self, sel: &Selection) -> Result<Vec<Process>, BackendError>
```

Everything downstream is already written, already tested, and platform-agnostic
(`#![forbid(unsafe_code)]`, zero dependencies):

| Reused unchanged | Lines |
|---|---|
| Selection/filter engine (`-p -c -u -a -d -i -s -g +D +L -K` …) | 738 |
| Renderers (table, `-F`, JSON `-J`/`-j`) | 429 |
| Data model (`Process`/`OpenFile` ≈ `lproc`/`lfile`) | 325 |
| `Backend` trait + mock backend + service resolution | 290 |
| **Total free** | **1,851** |

Plus the whole `lsof-cli` argument parser and the golden test suite.

Two model decisions made *for Windows* happen to fit Linux at no cost:

- **`FdType::Root`** already exists. It is N/A on Windows (documented as such)
  but was modeled anyway — Linux simply populates it from `/proc/<pid>/root`.
- **`FileType::Other(String)`**, added to carry Windows kernel object types
  (`SEM`, `JOB`, `IOCP`, …), expresses `netlink`, `packet`, `a_inode` and
  `sctp` with **no core change**.

## Size of the work

The C's Linux dialect, measured in this repo (`lib/dialects/linux/` +
`src/dialects/linux/`):

| C file | Lines | Rust disposition |
|---|---:|---|
| `dsock.c` | 5,003 | → `sockets.rs` (~700). Sockets are **half the dialect**. |
| `dproc.c` | 1,921 | → `process.rs` + `files.rs` (~750) |
| `dnode.c` | 860 | → folded into `files.rs` (stat/type classification) |
| `dmnt.c` | 673 | → mostly **not needed** (mount-table caching; defer namespaces) |
| `machine.h` / `dlsof.h` / `dproto.h` | 953 | → not needed (Rust types) |
| `dfile.c` | 345 | → `lsof-core` selection already does this |
| `dprint.c` | 208 | → `lsof-core` renderers already do this |
| `dlsof.c` / `dstore.c` | 242 | → not needed (no global mutable state) |
| **Total** | **10,205** | **≈ 2,200 Rust** |

For calibration, the Windows backend is **3,963 lines** and had to do NT handle
tables, PEB reads, and an ETW consumer. Linux is overwhelmingly text parsing of
`/proc` — simpler per feature, but with more socket families to cover.

## Module map

| Module | Data source | Est. | Notes |
|---|---|---:|---|
| `process.rs` | `/proc/<pid>/{stat,status}` | 250 | pid, ppid, comm, uid → user name |
| `files.rs` | `/proc/<pid>/fd/*` + `fstat` | 500 | the core loop: `readlink` each fd, stat for dev/inode/size, classify REG/DIR/CHR/**BLK**/FIFO |
| `sockets.rs` | `/proc/net/{tcp,tcp6,udp,udp6,udplite,raw,unix}` | 700 | hex-parse rows; join to fds by `socket:[inode]` |
| `maps.rs` | `/proc/<pid>/maps`, `/proc/<pid>/exe` | 150 | `mem` rows and the `txt` image |
| `locks.rs` | `/proc/locks` | 150 | the lock column — see below |
| `anon.rs` | `anon_inode:` symlink targets | 150 | `eventfd`, `eventpoll`, `timerfd`, `signalfd`, `pidfd` |
| `backend.rs` | orchestration | 300 | scoping, permission handling, race tolerance |
| | | **~2,200** | plus ~400 lines of test harness |

## Required `lsof-core` changes

Deliberately small — the seam is doing its job.

1. **Lock state (the one real addition).** The model has no lock field:
   `fd_cell` renders `3u` (fd + access), but lsof renders `3uW` (fd + access +
   **lock**). Needs `OpenFile.lock: Option<char>`, a `fd_cell` tweak, and the
   `-F l` field code. Windows always leaves it `None` (see
   [`known-limitations.md`](known-limitations.md)); Linux fills it from
   `/proc/locks`.
2. **`FileType::Block`.** Linux has block devices; Windows does not. Worth a
   real variant rather than `Other("BLK")`, since it is a first-class lsof TYPE.
3. **DEVICE column semantics.** Linux renders `maj,min`; Windows renders a drive
   letter. Both are already `Option<String>`, so this is a backend concern — but
   it is a *column meaning* difference worth documenting rather than a code
   change.

Nothing in the selection engine or the renderers needs to change.

## The strategic payoff: a real differential

This is the argument that carries the proposal.

The entire [oracle-substitution differential](../differential/README.md) exists
because **the C `lsof` cannot run on Windows**, so lsof-rs is compared against
the OS's own socket table (`Get-NetTCPConnection`) instead of against the C.
That was the retrospective's prescribed workaround, and it is strictly weaker
than diffing the two binaries.

On Linux that constraint evaporates. **The C `lsof` in this repository already
builds and self-tests in CI on `ubuntu-24.04` and `ubuntu-22.04`**
(`.github/workflows/build.yml`). So:

```
lsof -F ...   (C, built from ./src)
lsof -F ...   (Rust, lsof-backend-linux)
                     ↓
              byte-level set diff
```

The porting kit's **primary** differential mode — same-binary, C-vs-Rust, over
real system state — becomes available for the first time in this project's
history. That is a categorically stronger correctness signal than anything
Windows can produce, and it retroactively validates `lsof-core`'s selection
engine and renderers against the C's actual output on shared code paths.

**Wire the oracle early.** The kit's own hardest-learned lesson is to establish
the differential *before* translating in bulk. Get the C-vs-Rust harness running
the moment Phase L0 produces any rows.

## Two closed Windows gates open on Linux

Both documented Windows non-goals are ordinary features on Linux:

| Gate | Windows | Linux |
|---|---|---|
| **Socket FD correlation** — FD shows `unk` | Needs undocumented AFD IOCTLs (driver-adjacent) → gate closed | `/proc/<pid>/fd/N → socket:[12345]`, join `/proc/net/*` by inode. **Trivial.** |
| **Byte-range locks** — no lock column | Needs `FsRtlGetNextFileLock`, kernel-mode only → gate closed | `/proc/locks` is a text file. |

So a Linux backend does not merely port the tool sideways: it **ships two
capabilities the Windows build structurally cannot have**.

## What is harder than Windows

- **Socket breadth.** The C handles tcp/udp/udplite/raw × (v4, v6), unix,
  netlink, packet, ax25, ipx, sctp — which is why `dsock.c` is 5,003 lines. The
  MVP should cover **tcp/tcp6/udp/udp6/unix**, and *explicitly waive* the exotic
  families in the coverage matrix with reasons rather than dropping them
  silently (the LESSONS #8 failure mode).
- **`/proc` races.** PIDs vanish mid-scan. Every read must treat `ENOENT` as
  "process exited," not as an error — a pervasive design constraint, not a
  corner case.
- **Permission model.** Unprivileged users can only read their own
  `/proc/<pid>/fd`. This mirrors the Windows elevation story closely enough that
  `wants_privilege_hint()` and the
  [elevation decision record](road-to-1.0.md#decision-record-the-elevation-blind-spot)
  generalize — but the predicate needs a non-Windows arm.
- **Kernel-version variance** in `/proc/net` column layouts.
- **Namespaces / containers.** The C carries `dmnt.c` plus `/proc/<pid>/ns/mnt`
  handling. **Defer and declare** as a known limitation for the first release.

## Phasing

| Phase | Delivers | Est. |
|---|---|---:|
| **L0** | processes + fds + stat + `cwd`/`rtd`/`txt` → `-p -c -u -t -d`, bare paths, `+D` all work | 750 |
| **L1** | sockets + fd join → `-i`, `-s`, and **FD values actually populated** | 700 |
| **L2** | `maps` → `mem`, `/proc/locks` → lock column, anon inodes, raw/netlink | 450 |
| **L3** | **C-vs-Rust differential harness** + coverage-matrix rework | 500 |

L0 + L1 alone is a genuinely useful cross-platform `lsof`. **Start L3's harness
immediately after L0**, per the note above.

## Open decisions

1. **The name.** *(Written when the project was `winlsof`; the rename to
   `lsof-rs` landed after L1 — PR #63.)* The old name stopped being accurate
   the moment Linux landed. The options were: rename the workspace (churns
   every doc and the release-tag prefix), or keep it as the *Windows binary's*
   name under a differently-named workspace. The advice stands for the next
   port: decide **before** L0, not after — deciding after L1 cost one more
   release under the old prefix and a 92-file rename PR (LESSONS #020).
2. **Coverage matrix shape.** The matrix and feature inventory are currently
   Windows-shaped (`feature-inventory-lsof-rs.toml`, 118 waivers reading
   "no Windows analogue"). Cross-platform means either per-platform inventories
   or a `platform` key per waiver. This is a gate-design change, so settle it in
   L3 rather than bolting it on.
3. **Dependencies.** The Windows backend uses `windows-sys`. A Linux backend can
   plausibly be **dependency-free** (pure `/proc` text parsing + `std`), except
   `fstat`/`readlink` details — worth trying `libc`-free first to preserve the
   project's very small dependency surface for `cargo-deny`.
4. **MSRV / CI matrix.** Adds a Linux job that builds *and runs* the native
   backend (today Linux CI only runs the portable core).

## Non-goals for a first Linux release

- macOS/BSD dialects (the same seam would take them later).
- Mount namespaces / container-aware output.
- The exotic socket families (ax25, ipx, sctp) — waived with reasons.

## Sequencing

**Do this after `v1.0.0` is cut.** Two reasons:

1. 1.0 is gated only on the [fuzz soak](road-to-1.0.md#exit-criteria) and needs
   no further code — adding a second backend now would delay a release that is
   otherwise ready.
2. A second backend churns the coverage matrix, the naming, and the
   "lsof-rs = Windows" framing in every document. That is much cleaner to do
   against a shipped, tagged 1.0 than mid-flight.
