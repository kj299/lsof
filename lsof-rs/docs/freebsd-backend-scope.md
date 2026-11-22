# lsof-rs — the FreeBSD backend (phases F0 to F2)

> **Status (2026-11-21).** `crates/lsof-backend-freebsd` builds, lints and
> documents for `x86_64-unknown-freebsd` and `i686-unknown-freebsd`; its
> parsers and row rules are tested, fuzzed and run under miri on Linux.
> **It has run on one FreeBSD host**: FreeBSD 14.5-RELEASE amd64, UFS, a
> QEMU guest, beside the C built there with autotools, as a normal user and
> as root (2026-11-21). The first run found the differences DIVERGENCES'
> section "FreeBSD: the first run beside the C" lists; the second and the
> final run, of the tree that fixed them (the helper's `/dev/null` included,
> `2u`, row 144), are recorded in row 140, and the third, after the two
> reviews of that work (section "FreeBSD: the two reviews of the first-run
> fixes"), there too. **Not run:** ZFS, FreeBSD 15.x and 13.x, i386, NFS,
> nullfs, jails. The CI task that would run it on
> every change (`.cirrus.yml`, `lsof_rs_task`) needs Cirrus CI connected to
> this repository, which it is not
> (`porting-kit/harnesses/platforms/platforms.toml`); until then the run is
> made by hand with `differential/freebsd-check.sh`.

This is the scoping note `porting-kit/PROMPTS/20-new-backend.md` asks for
before a new platform's code. It was written alongside the code, not before it,
and says so where that matters.

## What a third platform changes

| | Change |
|---|---|
| `lsof-core` | `FdType::Ctty` (`ctty`) and `FdType::Jail` (`jld`, selected by `-d jd.`, as the C's table spells it). `TcpState::FinWaitOne` and `FinWaitTwo` (`FIN_WAIT_1`, `FIN_WAIT_2`) and `FREEBSD_TCP_STATES`, which is `tcp_state_table()` on FreeBSD. Nothing else. FreeBSD's vnode types (`VREG`, `VDIR`, `VCHR`, …) are `FileType::Other`. |
| `lsof-cli` | Links the backend on `target_os = "freebsd"`. `+c` is capped at 19 (`MAXSYSCMDL` is `MAXCOMLEN` there). `-T w` is refused (no `HASTCPTPIW`). |
| `lsof-backend-windows` | One match arm: the two new states map to the same EStats numbers as Windows' own spellings. |
| `lsof-backend-linux` | Untouched. |

**The name.** Not a question this time: the project was renamed from
`winlsof` to `lsof-rs` when the Linux backend landed (LESSONS #020).

**The coverage inventory's waivers.** Not yet scoped. The gate runs for
`windows` and `linux`. A `--platform freebsd` run is phase F1's first step,
before any waiver's reason is trusted for this platform (LESSONS #018).

## The data source

The C's FreeBSD dialect (`lib/dialects/freebsd/`) reads `sysctl(3)`, and since
FreeBSD 14 it reads nothing through `kvm(3)` for the rows it prints. So this
backend reads the same records:

| What | sysctl | Record | Layout |
|---|---|---|---|
| processes | `kern.proc.proc`; under `-K` `kern.proc.all`, a record a thread | `kinfo_proc` | per architecture: 1088 bytes on amd64, 768 on i386 |
| a process's files | `kern.proc.filedesc.<pid>` | packed `kinfo_file` | the same everywhere (1392 bytes at most) |
| locks | `kern.lockf` | `kinfo_lockf` | the same everywhere |
| TCP state, AF_UNIX peers | `net.inet.{tcp,udp}.pcblist`, `net.local.{stream,dgram,seqpacket}.pcblist` | `xtcpcb`, `xinpcb`, `xunpcb` | the same everywhere |
| an unnamed kind's file address | `kern.file` | `xfile` | the same everywhere |
| file systems | `statfs(2)`, `getfsstat(2)` | `statfs` | the same everywhere |

`std` has no `sysctl`, so this is the first backend since Windows with FFI of
its own: four libc functions in `src/sys.rs`, the one module allowed `unsafe`.
The alternative was the `libc` crate. It was not taken because `libc`'s
FreeBSD struct definitions are selected per FreeBSD ABI version by `cfg`, and a
backend that casts bytes to them inherits that choice silently. Reading bytes
at measured offsets, behind a size check, does not.

### How the layouts were measured

No FreeBSD host was available. The offsets in `src/layout.rs` come from a
probe file that `offsetof()`s each field. clang compiled it to LLVM IR with
`-target x86_64-unknown-freebsd14` (and `i686-…`, and `…15`) and `-nostdinc`,
against the `sys/` and `include/` trees of FreeBSD `releng/14.5` and
`releng/15.1`. In IR each offset is a constant to read, so nothing has to run
on the target. All four combinations agree on every record but `kinfo_proc`,
whose layout differs between the two architectures. The parser checks each
record's `ki_structsize` against the layout it expects, and refuses a
mismatch rather than misread it.

On 2026-11-21 the amd64 layouts met a real kernel (14.5): every row of the
host was the C's. `ki_tid`'s offset, added for `-K`, was measured there with
the system's own compiler and headers (600 on amd64; 520 on i386 by
`cc -target i386-unknown-freebsd14`, which no i386 kernel has confirmed).

## Phases

| Phase | Scope | State |
|---|---|---|
| **F0** | processes, every `kinfo_file` kind the C decodes (vnode, socket, pipe, PTS, kqueue, eventfd, SHM, procdesc), `cwd`/`rtd`/`jld`/`txt`/`ctty`, locks, TCP state, AF_UNIX naming, nullfs, procfs types, device names from `/dev`, the mount table, `-u` names | **done; run on 14.5 amd64** (2026-11-21) |
| **F1** | the first run on FreeBSD, and triage of what it shows into DIVERGENCES; `lsof_rs_task`'s side-by-side made the FreeBSD differential; `-K`; the coverage gate run with `--platform freebsd` | **partly done** (2026-11-21): the first run and its triage (DIVERGENCES 140-148, 180-185); what it showed fixed (a socket's ends and `-i`, 180, 181; what a run reads and starts, 182; `-K`, 141; the option letters and `-D`, 183, 148); `differential/freebsd-check.sh` is the side-by-side, run by hand. **Left:** host and service names (185); the other systems of row 140; a FreeBSD differential that is a gate, which needs a runner; the coverage gate with `--platform freebsd` |
| **F2** | `+f c/f/g/G/n` from `kern.file`; `-T f` socket options and TCP flags; the mount point's `stat` (and every bounded call) through a helper under `-S`; KQUEUE's DEVICE from `kern.file`; `readdev()`'s device table | **done; measured on 14.5 amd64** (2026-11-21): DIVERGENCES 142–147; the helper's timeouts and a file system that does not answer are still from source (143, 144); `statfs` of a vnode's path stays unbounded, as the C's (143) |

Estimate against actual: the Linux scope note estimated about 2,200 lines for
L0–L1. F0 here is about 3,100 lines, of which about 830 are tests, against
a C dialect a third of Linux's size (3,700 lines against 10,200) with no
`/proc` text to parse. Most of the difference is documentation of each rule's
source in the C.

## Gates

| Gate | State |
|---|---|
| `ported` | yes: `progress.json` says `ported` |
| `differential` | **no gate yet**: the C was diffed against it by hand, on one host (2026-11-21, `differential/freebsd-check.sh compare`, as a user and as root: the first run, before the fixes; the second and the final run after them; the third after the two reviews; DIVERGENCES 140 has the counts). Nothing runs it on every change: the side-by-side in `lsof_rs_task` calls the same script and is not a gate while Cirrus CI is not connected. |
| `fuzzed` | `fuzz/fuzz_targets/freebsd_kinfo.rs`: every parser and the row rules on arbitrary bytes. 8.7 million runs locally, and in the CI smoke loop. |
| `sanitized` | the miri job runs `-p lsof-backend-freebsd`: the pure modules, on Linux. The FFI itself has no sanitizer run. |
| `unsafe_audited` | `audit_unsafe.py` covers `src/`: seven blocks, each with `// SAFETY:` (the 2026-11-21 work added none). The crate is `#![deny(unsafe_code)]` with one `#[allow]`, so the `forbid` gate does not apply to it, as it does not to the Windows backend. |

The progress row stays at `ported` until a differential runs as a gate. A
side-by-side made once by hand shows what the two printed that day on that
host; it is not a gate passed.

The crate's tests ran on FreeBSD too (`cargo test -p lsof-core -p lsof-cli
-p lsof-backend-freebsd --no-fail-fast`, 14.5 amd64): the first run had nine
failures, each a test that stated Linux's expectation; each now states what
FreeBSD does, as measured, or is gated with its reason (DIVERGENCES 140).
`crates/lsof-cli/tests/freebsd.rs` and the backend's `live` tests run only
there.

## Field checkpoint

LESSONS #015 asks for the release artifact on real hardware, in every
privilege mode, with a time ceiling per case. For FreeBSD that means a root run
and an unprivileged run on 14.x and 15.x, on amd64 and on i386: eight runs.
Two have been made, and not on hardware: 14.5 amd64 in an emulated guest,
root and unprivileged, with no time ceiling a slow emulator could make
meaningful (2026-11-21).
