# lsof-rs — a memory-safe `lsof` in Rust (Windows, and now Linux)

`lsof-rs` is a from-scratch **Rust** reimplementation of the classic `lsof`
("list open files") utility. It eliminates the memory-unsafety class of bugs
inherent to the original C (buffer overflows, use-after-free, handle leaks) by
construction, and keeps `lsof`'s command-line surface and output formats so
existing scripts keep working.

It ships **two data-acquisition backends** behind one platform seam:

| Backend | Status | Data source |
|---|---|---|
| **Windows** | complete — [v1.0.1](https://github.com/kj299/lsof/releases), field-validated | Win32/NT: Toolhelp, IP Helper, the NT handle table, ETW |
| **Linux** | **phase L2** — processes, fds, `cwd`/`rtd`/`txt`, sockets (`-i`, `-U`), mapped files (`mem`/`DEL`), locks and anon-inode kinds | `/proc` |

Everything above the seam — the selection engine, all three output formats, the
argument parser — is shared and platform-agnostic, which is why adding Linux
took one additive enum variant in the core and no changes anywhere else. See
[`docs/linux-backend-scope.md`](docs/linux-backend-scope.md) for the remaining
phases.

> **Formerly `winlsof`.** The old name dated from when this was Windows-only
> and stopped being true when the Linux backend landed; it was renamed once
> phase L1 made the cross-platform claim real, rather than piecemeal along the
> way. Two things deliberately keep the old name: releases **v0.1.0 – v1.0.1**
> are tagged `winlsof-v*` and stay that way (they are published; rewriting the
> references would only produce dead links), and **`WINLSOF_TRACE` still
> works** as an alias for `LSOF_RS_TRACE`, so a runbook written against a
> shipped binary keeps working. The compiled binary has always been just
> `lsof`, and every crate name was already platform-neutral.

This is the incremental rewrite described in the project plan; it lives
**alongside** the original C `lsof` tree (in `../`) without modifying it. On
Linux that neighbour is also the **differential oracle**: the C builds and runs
on the same host, so the port is diffed against the reference implementation
directly rather than against the substitute oracle Windows forces.

## Why

`lsof` is ~159K lines of C with no Windows support. Memory-unsafety in C/C++ is
behind the majority of security vulnerabilities, and the industry — Microsoft
most visibly — is moving privileged systems code to memory-safe languages like
Rust. A privileged, pointer-heavy enumerator like `lsof` is an ideal candidate.

## Architecture

A Cargo workspace that mirrors `lsof`'s own clean split between machine-
independent code and per-OS "dialect" backends:

| Crate | Role |
|---|---|
| `lsof-core` | Platform-agnostic: data model (`Process`/`OpenFile` ≈ lsof's `lproc`/`lfile`), the selection/filter engine, the output renderers (table / `-F` / JSON), and the `Backend` trait (the "dialect" seam). **Zero dependencies, `#![forbid(unsafe_code)]`, fully unit-tested on any host.** |
| `lsof-backend-windows` | The Windows "dialect": implements `Backend` with native Win32 APIs (`windows-sys`). Processes via Toolhelp, sockets via IP Helper, file handles (Phase 3) via the NT handle table — all behind a strict least-privilege model. Compiled only on Windows. |
| `lsof-backend-linux` | The Linux "dialect": implements `Backend` over `/proc`. **Dependency-free and `#![forbid(unsafe_code)]`** — `/proc` is a filesystem and `std::os::unix::fs::MetadataExt` supplies every stat field, so no FFI is involved at all. Compiled only on Linux. |
| `lsof-cli` | The `lsof` binary: lsof-compatible option parsing and rendering. Picks the native backend per platform, falling back to a mock backend elsewhere (so the pipeline runs/tests anywhere). |

### Mapping Unix concepts to Windows

| lsof / Unix | Windows replacement (native API) |
|---|---|
| `/proc` PID scan, COMMAND, PPID | `CreateToolhelp32Snapshot` + `Process32NextW` |
| owner uid → USER | process token → `GetTokenInformation(TokenUser)` → `LookupAccountSidW` |
| `/proc/net/{tcp,udp}{,6}` (`-i`) | `GetExtendedTcpTable` / `GetExtendedUdpTable` (`*_OWNER_PID`, v4+v6) |
| `/proc/<pid>/fd/*` open files | `NtQuerySystemInformation` + `NtQueryObject` *(Phase 3)* |
| inode / `st_ino` | `GetFileInformationByHandle` file index *(Phase 3)* |

## Status

### Windows backend — complete

- ✅ **Phase 0** — workspace, `Backend` trait, least-privilege scaffolding, CI.
- ✅ **Phase 1** — process + owner enumeration; `-p` / `-c` / `-u` / `-t`.
- ✅ **Phase 2** — TCP/UDP (v4+v6) with owning PID; `-i [46][tcp|udp][@host][:port]`,
  `-n` / `-P`; table, `-F`, and JSON (`-J` / `-j`) output.
- ✅ **Phase 3** — system-wide open *file handle* enumeration via the NT handle
  table (`NtQuerySystemInformation` + `DuplicateHandle` + `NtQueryObject`):
  regular files, directories, named pipes, and char devices, with drive-letter
  mapping (`QueryDosDeviceW`), size/file-index, access mode, and file offset
  (`-o`) — all under just-in-time `SeDebugPrivilege`
  (`lsof-backend-windows/src/handles.rs`). Handles are classified by their NT
  object-type index (avoiding a per-handle `NtQueryObject` type query that can
  block forever on synchronous handles), and the entire per-handle
  classification runs on a worker thread under a timeout, so a wedged pipe/device
  handle can never freeze enumeration.
- ✅ **Phase 4** — mapped modules (`txt`/`mem`); repeat mode (`-r [delay]`);
  `cwd` via the process PEB (`rtd` is N/A on Windows); worker-thread name
  resolution (with timeout) for the hang-prone handles previously skipped; and
  Restart Manager for bare-path / `+D` "who has this open" lookups.

All planned phases (0–4) are implemented and **validated on real Windows 11
hardware in both privilege modes**: the [`smoketest/`](smoketest/) harness runs
61 cases covering every option, output format, and code path, differentially
cross-checked against native Windows oracles (no downloads). The few
skips in any single pass are mode-specific (admin-only features unelevated, and
vice versa) — running an unelevated **and** an elevated pass exercises
everything. Latest field validation: the released **v1.0.1** `lsof.exe`, as
downloaded, on Windows 11 (build 26200) — 51 PASS unelevated and 57 PASS
elevated, zero failures, zero hangs, all 61 cases green in at least one mode.
That checkpoint is not a formality: it is what caught the elevated stall fixed
in 1.0.1, on a build every automated gate had passed. The
[research roadmap](docs/research-roadmap.md) is fully dispositioned — every
item is shipped or a documented closed gate — and the release criteria are in
[`docs/road-to-1.0.md`](docs/road-to-1.0.md).

### Linux backend — phase L2 of 4

- ✅ **L0** — processes and owners from `/proc/<pid>/status`; open files from
  `/proc/<pid>/fd` plus the `cwd`/`root`/`exe` links; types, DEVICE, SIZE,
  NODE and NLINK from `stat`. Enough for `-p`, `-c`, `-u`, `-t`, `-d`, `-a`,
  `-R`, bare paths and `+D`/`+d`.
- ✅ **L1** — sockets. `/proc/net/{tcp,tcp6,udp,udp6,raw,raw6,unix}` is read
  once per gather and indexed by inode; an fd whose target is `socket:[N]`
  resolves by that key into a real TYPE, protocol, addresses and TCP state.
  **`-i` and `-U` work** in every form the core supports, as does `-T q`.
- 🔶 **L2** — three of four parts done. ✅ `mem` and `DEL` rows from
  `/proc/<pid>/maps`; ✅ the lock column (`3uW`) from `/proc/locks`; ✅ named
  `anon_inode` kinds (`[eventpoll:4,6]`, `[eventfd:6]`, `[pidfd:N]`). ⬜ What
  remains is one change wearing two hats: lsof matches a **path argument by
  device and inode**, not by name, which is also why naming a mount point
  selects everything on that filesystem — so `lsof /path/hardlink` finds the
  file opened under its other name, and lsof-rs both misses that and
  over-reports names that merely share a prefix ([`DIVERGENCES.md`](DIVERGENCES.md)
  #14, #15). ⬜ Per-network-namespace socket reads (#16). Both are measured
  against the C, with the exact commands in the ledger.
- ✅ **L3** — the C-vs-Rust differential as a CI gate
  ([`differential/linux_diff.py`](differential/linux_diff.py)): the C built
  from **this tree** and lsof-rs, run against the same fixture process, diffed
  through the porting kit's runner with [`DIVERGENCES.md`](DIVERGENCES.md) as
  the ledger. 26 cases over seven fixtures; every unledgered difference fails
  the build. On its first fixture it found two more fidelity gaps (the offset
  cell for devices and FIFOs, `pipe` in NAME), fixed the same day; its
  hostile-name fixtures then found a defect in the C itself (a signed-`char`
  comparison that truncates non-ASCII commands), which the port deliberately
  does not reproduce.

**A path argument names a file, not a prefix.** `lsof /path/to/file` matches
that file by its `(device, inode)`, so a hard link to it counts and a different
file that merely *starts with* the same text does not. Naming a directory
matches the directory, not everything inside it — `+d <dir>` adds its immediate
entries and `+D <dir>` the whole tree. lsof-rs used one string-prefix match for
all three, which both invented rows and missed them.

**Selection follows lsof's OR rule.** lsof ORs its list options unless `-a`
ANDs them, so `lsof -d ^mem -p PID` lists the whole host in real lsof — and now
in lsof-rs, which used to list one process. Every file carries the set of
selectors it matched, inheriting its process's matches; without `-a` any one
match lists it, with `-a` it needs them all. If you relied on lsof-rs's older
behaviour, add `-a`, which is what you would have had to write for the C
anyway. The consequence to know, verified against the C: `-d ^mem -p PID`
without `-a` still shows that PID's `mem` rows, because they inherit the PID
match even though the fd selector excluded them.

**Names are escaped before they reach your terminal.** A process names itself
and anyone can name a file, so COMMAND and NAME are text a local user chooses.
lsof-rs prints them the way the C's `safestrprt()` does — `^[` for ESC, `\r`,
`\t`, `\x7f`, `\xc2\x9b` for the 8-bit CSI — in the table and in `-F`, and
escapes them per the JSON grammar in `-J`/`-j`, so a process called
`h\x1b[2J` cannot clear the screen of whoever runs `lsof`. The one place
lsof-rs differs from the C on purpose: on Windows the backslash is the path
separator and stays `C:\Windows`, where the C would print `C:\\Windows`. The
rules, byte for byte, are in `lsof-core`'s `render::escape`, pinned by golden
tests, fuzzed (`render_escape`), and checked against the C on every Linux CI
run.

Both phases were diffed by hand against the real C `lsof` 4.95.0 on the same
host, and that diff is the reason to trust them: **`-i`, `-iTCP:443`,
`-i@127.0.0.1`, `-i4` and `-iUDP` all return the same row count as the C, and
`-U` matches it cell for cell.** The differences that remain are recorded in
[`docs/known-limitations.md`](docs/known-limitations.md) rather than left
looking like parity — including three renderer divergences the diff exposed
that had been latent in the **Windows** output since v0.2.0, where no C exists
to compare against.

## Privilege model (least privilege)

Like Unix `lsof`, **no elevation is required to run** — you get a current-user
view, and the system-wide view is a deliberate act by the operator.

**On Windows**, the binary's manifest pins `requestedExecutionLevel=asInvoker`,
so it never triggers a UAC prompt; an administrator must *deliberately* run
elevated. Even then `lsof-rs` never holds privileges globally: it enables a
privilege (e.g. `SeDebugPrivilege`) only just-in-time around the specific call
that needs it, via the RAII `PrivilegeGuard`, and only when the switches in use
actually require system-wide data. Queries like `-i` work entirely in the user
context and never touch privileges.

**On Linux** the same split falls out of the kernel rather than being
engineered: `/proc/<pid>/fd` is readable for your own processes and, as root,
for everyone's. There is nothing to request or drop — no analog of the
`SeDebugPrivilege` enable/disable dance — so the Linux backend asks for no
privilege at all and simply reports what the uid can see.

## Download

Prebuilt **`lsof.exe`** for 64-bit Windows is published on the
[**Releases**](https://github.com/kj299/lsof/releases) page — built natively on a
`windows-latest` runner (MSVC; no runtime install needed on Windows 10/11):

1. Grab `lsof.exe` (and `lsof.exe.sha256`) from the latest release.
2. *(Optional)* verify the download in PowerShell:
   ```powershell
   (Get-FileHash .\lsof.exe -Algorithm SHA256).Hash.ToLower() -eq (Get-Content .\lsof.exe.sha256).Trim()
   ```
   `True` means the binary is intact.
3. Run it from anywhere: `.\lsof.exe -nP -i`.

The binary is **unsigned**, so Windows SmartScreen may warn on first run
(*More info → Run anyway*).

> **Antivirus / Defender note.** Like Sysinternals `handle.exe` and Process
> Explorer, lsof-rs does exactly what an open-files lister must — it enumerates
> every process's handles, enables `SeDebugPrivilege`, and reads process memory
> (for `cwd`/PEB). Heuristic AV (including Microsoft Defender) may therefore
> flag a *downloaded* copy as a "hacktool" / potentially-unwanted program and
> block it from running. This is a **false positive**: verify the download
> against the published `lsof.exe.sha256`, and if you want to run it, allow it in
> Windows Security → Protection history, or add an exclusion in an elevated
> shell: `Add-MpPreference -ExclusionPath <path-to-lsof.exe>`. (A locally built
> binary isn't internet-marked, so it usually isn't flagged.) lsof-rs ships
> **unsigned by design** — a privacy-conscious choice, since a publicly-trusted
> signing certificate would put the maintainer's validated legal name and
> location permanently on every binary, and it would buy only reduced
> download-friction, not the integrity the SHA-256 already gives. Signing is an
> optional future route, not a planned change; see
> [`docs/code-signing.md`](docs/code-signing.md).

Releases are produced by pushing a `lsof-rs-v*` tag, which triggers
[`.github/workflows/lsof-rs-release.yml`](../.github/workflows/lsof-rs-release.yml).
Prefer building from source? See below.

## Build & run

```sh
# On Windows (produces target\release\lsof.exe):
cd lsof-rs
cargo build --release
.\target\release\lsof.exe -nP -i        # network connections + owning process
.\target\release\lsof.exe -p 1234       # files/handles for PID 1234

# On Linux (produces target/release/lsof) — the native backend builds by default:
cd lsof-rs
cargo build --release
./target/release/lsof -p $$             # this shell's open files
./target/release/lsof -t                # every PID
# (-i needs phase L1; see Status.)

# On any other host the CLI falls back to a mock backend, so the
# parse -> select -> render pipeline still runs and is testable:
cargo run -- -i
```

## Test

```sh
cd lsof-rs
cargo test --all                                   # core + CLI + the native backend
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
# Type-check the Windows backend from a non-Windows host:
rustup target add x86_64-pc-windows-gnu
cargo check --target x86_64-pc-windows-gnu
```

On Linux, `cargo test --all` includes the Linux backend's own tests, three of
which read this host's live `/proc` rather than a fixture — the cheapest way to
keep the parsing honest against a real kernel.

Every parser that takes text from outside the process has a cargo-fuzz target
under [`fuzz/`](fuzz/) — the argv parser, and the Linux backend's `/proc/net`
tables, `/proc/<pid>/status`, fdinfo and `/etc/passwd` readers. The contract is
*no panic on any input*; CI smoke-runs all of them on every PR and soaks them
nightly. The `proc_net` target found a real panic in the IPv6 decoder in its
first seconds.

```sh
cargo +nightly install cargo-fuzz
cd lsof-rs/fuzz && cargo +nightly fuzz list          # the targets
cargo +nightly fuzz run proc_net -- -max_total_time=60
```

CI (`.github/workflows/lsof-rs-ci.yml`) runs the lints + tests on Linux and
builds/tests the Windows backend on `windows-latest`.

For end-to-end validation on a real Windows host (concrete commands + expected
output, cross-checked against native oracles — `Get-NetTCPConnection`,
`Get-Process`, the fixtures themselves; nothing downloaded), see
[`docs/windows-validation.md`](docs/windows-validation.md).

## Docs index

- [`CHANGELOG.md`](CHANGELOG.md) — released versions and what changed.
- [`docs/road-to-1.0.md`](docs/road-to-1.0.md) — what 1.0 means, the exit
  criteria checklist, and the elevation blind-spot decision record with the
  per-release manual (unelevated) checkpoint.
- [`docs/linux-backend-scope.md`](docs/linux-backend-scope.md) — scoping study
  for a second (Linux/`/proc`) backend behind the same `Backend` seam: effort,
  module map, and the C-vs-Rust differential it would unlock. A proposal, not a
  commitment.
- [`docs/known-limitations.md`](docs/known-limitations.md) — what lsof-rs
  deliberately doesn't show (socket FD value, byte-range locks, raw/ICMP/
  AF_UNIX), and why; user-facing.
- [`docs/code-signing.md`](docs/code-signing.md) — tracking doc for signing
  the release binary (the SmartScreen / Defender fix).
- [`docs/research-roadmap.md`](docs/research-roadmap.md) — engineering spike
  records and the next open item (ETW-based socket → FD correlation).
- [`docs/etw-spike.md`](docs/etw-spike.md) — step-by-step `logman` + `tracerpt`
  P1 spike for item §5; no Rust needed, answers the gating question first.
- [`docs/windows-validation.md`](docs/windows-validation.md) — manual T1–T20
  validation plan against Windows oracles.
- [`smoketest/README.md`](smoketest/README.md) — live Windows smoke-test
  harness (run against source or a downloaded release binary).

## License / attribution

Original Rust code. Command-line/output-compatible with `lsof` but sharing no
source with it; see `NOTICE`. The original `lsof` is © Purdue Research
Foundation (V. A. Abell) — see `../COPYING`.
