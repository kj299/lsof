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
| **Linux** | **L0–L3 done** — processes, fds, `cwd`/`rtd`/`txt`, sockets (`-i`, `-U`), mapped files (`mem`/`DEL`), locks, anon-inode kinds, mount points, and the differential against the C in CI. Not in a release yet: build from source | `/proc` |

Everything above the seam — the selection engine, all three output formats, the
argument parser — is shared. Adding Linux's first phase took one additive enum
variant in the core; matching the C since has added to the backend trait (path
identity, mounts, user lookup) and to the model (locks, tasks, device files). A few parser rules differ by
platform, as the dialects do: `-c` and `-g` on Windows; the `+c` limit, `-T w`
and `+f g` on Linux. See [`docs/linux-l2-plan.md`](docs/linux-l2-plan.md) for
what is left on Linux, and the OPEN rows of [`DIVERGENCES.md`](DIVERGENCES.md).

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
**alongside** the original C `lsof` tree (in `../`). The oracle builds upstream's
sources unchanged; PR #81 removed only dialects and scripts that do not build
here, and the docs and `Configure` lines that pointed at them. On
Linux that neighbour is also the **differential oracle**: the C builds and runs
on the same host, so the port is diffed against the reference implementation
directly rather than against the substitute oracle Windows forces.

## Why

`lsof` is about 75K lines of C with no Windows support. Memory-unsafety in C/C++ is
behind the majority of security vulnerabilities, and the industry — Microsoft
most visibly — is moving privileged systems code to memory-safe languages like
Rust. A privileged, pointer-heavy enumerator like `lsof` is an ideal candidate.

## Architecture

A Cargo workspace that mirrors `lsof`'s own clean split between machine-
independent code and per-OS "dialect" backends:

| Crate | Role |
|---|---|
| `lsof-core` | Platform-agnostic: data model (`Process`/`OpenFile` ≈ lsof's `lproc`/`lfile`), the selection/filter engine, the output renderers (table / `-F` / JSON), and the `Backend` trait (the "dialect" seam). **Zero dependencies, `#![forbid(unsafe_code)]`, fully unit-tested on any host.** |
| `lsof-backend-windows` | The Windows "dialect": implements `Backend` with native Win32 APIs (`windows-sys`). Processes via Toolhelp, sockets via IP Helper and ETW, file handles via the NT handle table — all behind a strict least-privilege model. Compiled only on Windows, but for its pure name parsers, which are fuzzed on Linux. |
| `lsof-backend-linux` | The Linux "dialect": implements `Backend` over `/proc`. **Dependency-free and `#![forbid(unsafe_code)]`** — `/proc` is a filesystem and `std::os::unix::fs::MetadataExt` supplies every stat field, so no FFI is involved at all. Compiled only on Linux. |
| `lsof-cli` | The `lsof` binary: lsof-compatible option parsing and rendering. Picks the native backend per platform, falling back to a mock backend elsewhere (so the pipeline runs/tests anywhere). **Dependency-free and `#![forbid(unsafe_code)]`** — on both of its crate roots, since a bin and a lib in one package are two crates and the attribute does not cross between them. |

### Mapping Unix concepts to Windows

| lsof / Unix | Windows replacement (native API) |
|---|---|
| `/proc` PID scan, COMMAND, PPID | `CreateToolhelp32Snapshot` + `Process32NextW` |
| owner uid → USER | process token → `GetTokenInformation(TokenUser)` → `LookupAccountSidW` |
| `/proc/net/{tcp,udp}{,6}` (`-i`) | `GetExtendedTcpTable` / `GetExtendedUdpTable` (`*_OWNER_PID`, v4+v6) |
| `/proc/<pid>/fd/*` open files | `NtQuerySystemInformation` + `NtQueryObject` |
| inode / `st_ino` | `GetFileInformationByHandle` file index |

## Status

### Windows backend — complete

- ✅ **Phase 0** — workspace, `Backend` trait, least-privilege scaffolding, CI.
- ✅ **Phase 1** — process + owner enumeration; `-p` / `-c` / `-u` / `-t`.
- ✅ **Phase 2** — TCP/UDP (v4+v6) with owning PID; `-i [46][tcp|udp][@addr][:port]`,
  `-n` / `-P`; table, `-F`, and JSON (`-J` / `-j`) output.
- ✅ **Phase 3** — system-wide open *file handle* enumeration via the NT handle
  table (`NtQuerySystemInformation` + `DuplicateHandle` + `NtQueryObject`):
  regular files, directories, named pipes, and char devices, with drive-letter
  mapping (`QueryDosDeviceW`), size/file-index, access mode, and file offset
  (`-o`) — all under just-in-time `SeDebugPrivilege`
  (`crates/lsof-backend-windows/src/handles.rs`). Handles are classified by their NT
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
a case for every option, output format, and code path, differentially
cross-checked against native Windows oracles (no downloads), and CI runs it on
every PR. The few
skips in any single pass are mode-specific (admin-only features unelevated, and
vice versa) — running an unelevated **and** an elevated pass exercises
everything. Latest field validation: the released **v1.0.1** `lsof.exe`, as
downloaded, on Windows 11 (build 26200), with the 59-case suite of the time — 51
PASS unelevated and 57 PASS elevated, zero failures, zero hangs, all 59 cases
green in at least one mode.
That checkpoint is not a formality: it is what caught the elevated stall fixed
in 1.0.1, on a build every automated gate had passed. The
[research roadmap](docs/research-roadmap.md) is fully dispositioned — every
item is shipped or a documented closed gate — and the release criteria are in
[`docs/road-to-1.0.md`](docs/road-to-1.0.md).

### Linux backend — L0 to L3 done

- ✅ **L0** — processes and owners from `/proc/<pid>/status`; open files from
  `/proc/<pid>/fd` plus the `cwd`/`root`/`exe` links; types, DEVICE, SIZE,
  NODE and NLINK from `stat`. Enough for `-p`, `-c`, `-u`, `-t`, `-d`, `-a`,
  `-R`, bare paths and `+D`/`+d`.
- ✅ **L1** — sockets. `/proc/net/{tcp,tcp6,udp,udp6,raw,raw6,unix}` is read
  once per gather and indexed by inode; an fd whose target is `socket:[N]`
  resolves by that key into a real TYPE, protocol, addresses and TCP state.
  **`-i` and `-U` work** in every form the core supports, as does `-T q`.
- ✅ **L2** — `mem` and `DEL` rows from `/proc/<pid>/maps`; ✅ the lock
  column (`3uW`) from `/proc/locks`; ✅ named `anon_inode` kinds
  (`[eventpoll:4,6]`, `[eventfd:6]`, `[pidfd:N]`); ✅ **path arguments matched
  by device and inode** rather than by name, so `lsof /path/hardlink` finds the
  file opened under its other name ([`DIVERGENCES.md`](DIVERGENCES.md) #14);
  ✅ **naming a mount point selects everything open on that filesystem**, with
  `-f`/`+f` to force the reading either way (#15). A path is spelt as the C's
  `Readlink()` spells it, so only the mount point's own spelling (`/mnt`, or a
  link to it) names the file system; `mnt` from `/` or `/mnt/.` names the
  directory (#65); ✅ sockets in another network namespace are named from
  that namespace's own tables (#16), and packet sockets have their `pack` row.
  ⬜ What remains for sockets: a socket no `/proc/net` table lists, an
  AF_VSOCK, ping or unbound netlink socket, which the C names from an
  extended attribute (#22, waiting on a decision); and two families whose
  tables lsof-rs does not read as the C does, raw sockets (`raw`, #108) and
  bound netlink sockets (`netlink`, #109).
- ✅ **L3** — the C-vs-Rust differential as a CI gate
  ([`differential/linux_diff.py`](differential/linux_diff.py)): the C built
  from **this tree** and lsof-rs, run against the same fixture process, diffed
  through the porting kit's runner with [`DIVERGENCES.md`](DIVERGENCES.md) as
  the ledger. Every case in `linux-matrix.toml`, over self-owned fixture
  processes; every unledgered difference fails the build. On its first fixture it found two more fidelity gaps (the offset
  cell for devices and FIFOs, `pipe` in NAME), fixed the same day; its
  hostile-name fixtures then found a defect in the C itself (a signed-`char`
  comparison that truncates non-ASCII commands), which the port deliberately
  does not reproduce.

**A path argument names a file, not a prefix.** `lsof /path/to/file` matches
that file by its `st_dev` and inode, what `-F D` and `-F i` print, so a hard
link to it counts and a different file that merely *starts with* the same text
does not. A device node is the node: `lsof /dev/zero` finds a mapping of it
lsof could not `stat`, by the maps line's device and inode, and not a node of
the same number on another file system (a container's `/dev`, another devpts
instance's pty). A socket is found by the path it is bound to, and never by
its own device and inode. Naming a directory matches the directory, not
everything inside it — `+d <dir>` adds its immediate entries and `+D <dir>`
the whole tree. lsof-rs used one string-prefix match for all three, which both
invented rows and missed them.

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

**A file system that does not answer costs a run `-S` seconds per call, not
the run.** On Linux every `stat`, `lstat`, `readlink` and directory listing
lsof-rs makes on a path it was given — an argument, a `+d`/`+D` tree, a mount
point — runs in a helper process (the same binary, re-executed) that gets
`-S [t]` seconds for it, 15 by default and at least 2; one that runs out fails
with `Connection timed out` and the helper is replaced. Each such call costs
its limit: a hung mount costs every run that reads the mount table 15 s, a
path argument on it 15 s more. A hung NFS mount or a stuck FUSE daemon used
to stop every run but `-f`, `lsof -i :22` included. `-b` makes none of those
calls and says so, and `-O` makes them in lsof itself with no limit, as the C
documents both. The C's own timeout fires once per run and then hangs;
lsof-rs bounds every call ([`DIVERGENCES.md`](DIVERGENCES.md) #94, #118). A
helper killed on a timeout waits in the kernel until the file system answers,
holding the descriptor its call opened there: lsof-rs never `stat`s it, but
another tool that does — the C's lsof listing the host — waits as well
(#123).

Both phases were diffed by hand against the real C `lsof` 4.95.0 on the same
host, and that diff is the reason to trust them: **`-i`, `-iTCP:443`,
`-i@127.0.0.1`, `-i4` and `-iUDP` all return the same row count as the C, and
`-U` matches it cell for cell.** The differences that remain are rows in
[`DIVERGENCES.md`](DIVERGENCES.md) rather than left looking like parity. The diff
also exposed three renderer divergences that had been latent in the **Windows**
output since v0.2.0, where no C exists to compare against; all three are fixed,
and [`docs/known-limitations.md`](docs/known-limitations.md) records them.

## Privilege model (least privilege)

Like Unix `lsof`, **no elevation is required to run** — you get a current-user
view, and the system-wide view is a deliberate act by the operator.

**On Windows**, the binary runs as invoker — the default for an MSVC build — so
it never triggers a UAC prompt (`crates/lsof-cli/app.manifest` records that
choice; the build does not embed it yet); an administrator must *deliberately* run
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
./target/release/lsof -nP -i            # Internet sockets

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

On Linux, `cargo test --all` includes the Linux backend's own tests, some of
which read this host's live `/proc` rather than a fixture — the cheapest way to
keep the parsing honest against a real kernel.

The parsers of text from outside the process have cargo-fuzz targets under
[`fuzz/`](fuzz/) — the argv parser; the Linux backend's `/proc/net`,
`/proc/<pid>/status`, fdinfo, maps, `/proc/locks`, mount-table and
`/etc/passwd` readers; the Windows backend's name parsers and PEB walk; and the
escaper that every one of them feeds. Three have none, and
[`THREAT-MODEL.md`](THREAT-MODEL.md) §2 names them: the ETW payload parsers, the
path speller (`readlink::resolve_with`) and the `/etc/passwd` name lookup behind
`-u NAME`. The contract is
*no panic on any input*; CI smoke-runs all of them on every PR and soaks them
nightly. The `proc_net` target found a real panic in the IPv6 decoder in its
first seconds.

```sh
cargo +nightly install cargo-fuzz
cd lsof-rs/fuzz && cargo +nightly fuzz list          # the targets
cargo +nightly fuzz run proc_net -- -max_total_time=60
```

CI (`.github/workflows/lsof-rs-ci.yml`) runs eight jobs: lints, rustdoc and
tests on Linux; build, tests, a socket differential and the smoke suite on
`windows-latest`; cargo-deny; a fuzz smoke of every target; the differential
against the C, with its resource gate; Miri over the portable crates and over
the Linux backend; and ASan over the Windows backend. Each blocks a merge but
Miri over the Linux backend, which is observe-first: it reports, and cannot
fail the build.

For end-to-end validation on a real Windows host (concrete commands + expected
output, cross-checked against native oracles — `Get-NetTCPConnection`,
`Get-Process`, the fixtures themselves; nothing downloaded), see
[`docs/windows-validation.md`](docs/windows-validation.md).

## Docs index

- [`CHANGELOG.md`](CHANGELOG.md) — released versions and what changed.
- [`docs/road-to-1.0.md`](docs/road-to-1.0.md) — what 1.0 means, the exit
  criteria checklist, and the elevation blind-spot decision record with the
  per-release manual (unelevated) checkpoint.
- [`DIVERGENCES.md`](DIVERGENCES.md) — every known difference from the C, each
  with its status: fixed, deliberate, a C defect not reproduced, or still open.
- [`THREAT-MODEL.md`](THREAT-MODEL.md) — trust boundaries, privilege, what the
  port defends against and what it does not.
- [`docs/linux-backend-scope.md`](docs/linux-backend-scope.md) — the scoping
  study written before the Linux backend existed; kept as a record.
- [`docs/linux-l2-plan.md`](docs/linux-l2-plan.md) — what was measured as left
  after L1, and where each item stands.
- [`docs/feature-parity-plan.md`](docs/feature-parity-plan.md) — the option
  inventory against the C, as a record.
- [`docs/known-limitations.md`](docs/known-limitations.md) — what lsof-rs does
  not show, or shows differently from the C, and why; user-facing.
- [`docs/code-signing.md`](docs/code-signing.md) — tracking doc for signing
  the release binary (the SmartScreen / Defender fix).
- [`docs/research-roadmap.md`](docs/research-roadmap.md) — engineering spike
  records; every item is shipped or closed.
- [`docs/etw-spike.md`](docs/etw-spike.md) — the `logman` + `tracerpt` P1 spike
  for item §5, as run; a record.
- [`docs/windows-validation.md`](docs/windows-validation.md) — manual T1–T20
  validation plan against Windows oracles.
- [`smoketest/README.md`](smoketest/README.md) — live Windows smoke-test
  harness (run against source or a downloaded release binary).

## License / attribution

Original Rust code. Command-line/output-compatible with `lsof` but sharing no
source with it; see `NOTICE`. The original `lsof` is © Purdue Research
Foundation (V. A. Abell) — see `../COPYING`.
