# lsof-rs — the FreeBSD backend (phase F0)

> **Status (2026-10-31).** Phase F0 has landed: `crates/lsof-backend-freebsd`
> builds, lints and documents for `x86_64-unknown-freebsd` and
> `i686-unknown-freebsd`. Its parsers and row rules are tested, fuzzed and run
> under miri on Linux. **It has not yet run on FreeBSD.** The CI task that would
> run it (`.cirrus.yml`, `lsof_rs_task`) needs Cirrus CI connected to this
> repository, which it is not (`porting-kit/harnesses/platforms/platforms.toml`).
> Until a run on a real host, every row this backend prints is the C dialect's
> rule as read from its source, not as measured (DIVERGENCES 140).

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
| processes | `kern.proc.proc` | `kinfo_proc` | per architecture: 1088 bytes on amd64, 768 on i386 |
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

## Phases

| Phase | Scope | State |
|---|---|---|
| **F0** | processes, every `kinfo_file` kind the C decodes (vnode, socket, pipe, PTS, kqueue, eventfd, SHM, procdesc), `cwd`/`rtd`/`jld`/`txt`/`ctty`, locks, TCP state, AF_UNIX naming, nullfs, procfs types, device names from `/dev`, the mount table, `-u` names | **done, unrun** |
| **F1** | the first run on FreeBSD, and triage of what it shows into DIVERGENCES; `lsof_rs_task`'s side-by-side made the FreeBSD differential; `-K`; the coverage gate run with `--platform freebsd` | needs a FreeBSD runner |
| **F2** | `+f c/f/g/G/n` from `kern.file`; `-T f` socket options and TCP flags; `statfs` and mount-point `stat` bounded by `-S` (no helper process yet on FreeBSD) | open: DIVERGENCES 142–144, 147 |

Estimate against actual: the Linux scope note estimated about 2,200 lines for
L0–L1. F0 here is about 3,100 lines, of which about 830 are tests, against
a C dialect a third of Linux's size (3,700 lines against 10,200) with no
`/proc` text to parse. Most of the difference is documentation of each rule's
source in the C.

## Gates

| Gate | State |
|---|---|
| `ported` | yes: `progress.json` says `ported` |
| `differential` | **no**: the C has never been diffed against it on a host. The side-by-side in `lsof_rs_task` is not a gate yet. |
| `fuzzed` | `fuzz/fuzz_targets/freebsd_kinfo.rs`: every parser and the row rules on arbitrary bytes. 8.7 million runs locally, and in the CI smoke loop. |
| `sanitized` | the miri job runs `-p lsof-backend-freebsd`: the pure modules, on Linux. The FFI itself has no sanitizer run. |
| `unsafe_audited` | `audit_unsafe.py` covers `src/`: six blocks, each with `// SAFETY:`. The crate is `#![deny(unsafe_code)]` with one `#[allow]`, so the `forbid` gate does not apply to it, as it does not to the Windows backend. |

The progress row stays at `ported` until the differential has run. A gate
that has not run against the C has not been passed.

## Field checkpoint

LESSONS #015 asks for the release artifact on real hardware, in every
privilege mode, with a time ceiling per case. For FreeBSD that means a root run
and an unprivileged run on 14.x and 15.x, on amd64 and on i386. None has been
done.
