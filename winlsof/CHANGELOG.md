# Changelog

All notable changes to **winlsof** (the Rust, Windows-native `lsof`
reimplementation under [`winlsof/`](.)). The changelog tracks the new Rust
workspace; the legacy C `lsof` tree in the parent directory is untouched.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`--etw` opt-in flag** (Windows, iteration 1): runs a short
  `Microsoft-Windows-Winsock-AFD` ETW realtime capture and prints a
  per-event-ID histogram to stderr. Needs Administrator (or *Performance Log
  Users* membership). No row emission yet — this is the FFI-verification
  step for the eventual P2 deliverable in
  [`docs/research-roadmap.md`](docs/research-roadmap.md) §5: extending `-i`
  coverage to socket families IP Helper doesn't enumerate (raw, ICMP,
  AF_UNIX). Iteration 2 adds TDH event parsing and the actual row
  emission.

## [0.1.0] — 2026-06-21

First public **prerelease** — a memory-safe, Windows-native `lsof` written in
Rust, validated end-to-end on real Windows 11 hardware in both privilege modes
(36/0/1 elevated and unelevated; output cross-checked against Sysinternals
`handle64.exe`).

### Added

- **Cargo workspace** (`winlsof/`) split along lsof's `core + dialect` boundary:
  `lsof-core` (platform-agnostic data model, selection/filter engine, renderers,
  `#![forbid(unsafe_code)]`), `lsof-backend-windows` (Win32/NT implementation),
  `lsof-cli` (the `lsof` binary).
- **Process enumeration**: `CreateToolhelp32Snapshot` + Process32NextW for PID /
  COMMAND / PPID; owner USER via process-token `LookupAccountSidW`.
- **Open-file-handle enumeration** (`-p`, `-d`, `-t`): system-wide handle table
  via `NtQuerySystemInformation(SystemExtendedHandleInformation)`, classified
  by NT object-type index (learned once from a NUL-device probe) so no
  per-handle `NtQueryObject(type)` is ever issued on the main thread.
  Per-handle work — duplicate, optional type check, `GetFileType`, name
  resolution — runs on a worker thread under a deadline so any synchronous
  pipe/device handle is abandoned instead of freezing enumeration. Names via
  `GetFinalPathNameByHandleW` (disk files, hang-free) or
  `NtQueryObject(ObjectNameInformation)` (pipes/devices) on the worker;
  drive-letter mapping via `QueryDosDeviceW`; size/file-index via
  `GetFileInformationByHandle`; access mode derived from the granted-access
  mask.
- **TCP/UDP socket enumeration** (`-i`): IPv4 and IPv6, with owning PID, via
  `GetExtendedTcpTable` / `GetExtendedUdpTable`. Reverse DNS (`GetNameInfoW`)
  is bounded on a worker thread (2 s) with numeric fallback, and only run for
  sockets that survive the PID filter — system-wide PTR lookups are never paid
  for a scoped query.
- **Current directory** (`cwd`, including 32-bit **WOW64** targets): PEB walk
  via `NtQueryInformationProcess` + `ReadProcessMemory`, with
  `ProcessWow64Information` for the 32-bit PEB on WOW64 processes.
- **Loaded modules** (`txt` for the image, `mem` for libraries): Toolhelp
  module snapshot with transient-failure retry.
- **Memory-mapped data files** (`mem` beyond modules): `VirtualQueryEx` walk
  + `GetMappedFileNameW`, de-duplicated per file.
- **File offset** (`-o`): `NtQueryInformationFile(FilePositionInformation)`
  on the duplicated handle — the duplicate shares the owner's file object, so
  the position is live.
- **Restart Manager** (`<path>` / `+D` / `+d`): `RmStartSession` /
  `RmRegisterResources` / `RmGetList` for "who has this file/dir open"
  lookups without enumerating handles system-wide.
- **Selection engine**: `-p`, `-c`, `-u`, `-d` (`cwd`/`rtd`/`txt`/`mem` /
  numbers / ranges / `^excl`), `-i [46][tcp|udp][@host][:port]`, `-a` AND
  mode, `+D`/`+d` directory trees.
- **Output renderers**: default **table** with `COMMAND PID [PPID] USER FD
  TYPE DEVICE SIZE/OFF NODE NAME`; **`-F[fields]`** field codes (with `-F0`
  NUL-separated); aggregated **JSON** (`-J`) and **JSON Lines** (`-j`);
  terse `-t` (PIDs only); `-R` (PPID column); `-o` (SIZE/OFF prefers
  offset); `-r [delay]` repeat with `=======` separator; `-V` verbose
  (unmatched search items).
- **Least-privilege model**: `requestedExecutionLevel=asInvoker` manifest,
  so no UAC auto-prompt; runs as the current user by default. When a switch
  requires data the current token can't reach, the CLI prints a single hint
  ("re-run as Administrator for a system-wide view") and continues with the
  reduced result set. Even when elevated, `SeDebugPrivilege` is enabled
  just-in-time around the single call that needs it via an RAII
  `PrivilegeGuard` — never globally; `-i` and path lookups never touch
  privileges.
- **Hang-free, fast exit by construction**: every foreign-process / foreign-
  handle / reverse-DNS call is bounded on a worker with a deadline; after
  output flushes, the CLI `TerminateProcess()`-es self via `exit_now` so an
  abandoned kernel-stuck name-query worker can't hold teardown hostage.
- **Performance fast-paths**: terse (`-t`) returns the process list
  immediately and skips system-wide handle/socket/module enumeration that
  the renderer would discard; path/dir queries (`+D`) skip socket reverse
  DNS (sockets have no filesystem path so they can never match the filter).
- **Opt-in tracing** (`WINLSOF_TRACE` env var): per-phase stderr markers
  for field-diagnosing slow or stuck runs.
- **CI** (`.github/workflows/winlsof-ci.yml`): `cargo fmt --check`, `cargo
  clippy -D warnings`, and tests on Linux; build + tests + release-profile
  artifact build on `windows-latest`. The Windows job runs `cargo test
  --all`, which includes `cfg(windows)` runtime integration tests that
  execute the real `lsof.exe`.
- **Live smoke-test harness** (`winlsof/smoketest/`): 37-case PowerShell
  harness that stands up deterministic fixtures (held file at a known
  offset, named pipe, mapped data file, TCP v4/v6 listeners +
  ESTABLISHED pair, UDP v4/v6, child cmd.exe with a known cwd in 64-bit
  and 32-bit WOW64), exercises every option / format / branch with a hard
  per-invocation timeout, auto-fetches Sysinternals `handle64.exe` for a
  differential oracle cross-check, and writes `results.csv` /
  `summary.txt` / per-case logs. Run against any prebuilt binary via
  `-Binary <path>`. A standalone `Test-Lsof.ps1` provides a quick
  ~10-case sanity check with no repo/build dependency.
- **Release pipeline** (`.github/workflows/winlsof-release.yml`): tag a
  `winlsof-v*` (or trigger manually) and the workflow builds a native
  MSVC `lsof.exe` on `windows-latest`, computes its SHA-256, and
  publishes both as a GitHub Release prerelease asset, with usage notes
  and an Antivirus/Defender note built in.

### Known limitations

See [`docs/known-limitations.md`](docs/known-limitations.md). In brief:

- Socket rows show `unk` for FD (no public way to recover the handle
  value from IP Helper data).
- No byte-range lock column (no user-mode API enumerates locks).
- `-i` covers TCP and UDP only (no public table for raw/ICMP/AF_UNIX).
- Released `lsof.exe` is unsigned, so SmartScreen / Defender may warn
  or block on first launch — see the README "Antivirus / Defender note"
  and the [code-signing tracking doc](docs/code-signing.md).

### Documentation

- [`README.md`](README.md): architecture, mapping, build/run, **Download**
  section with SHA-256 verification, Antivirus/Defender note.
- [`docs/known-limitations.md`](docs/known-limitations.md): user-facing
  list of what v0.1.0 deliberately doesn't show, and why.
- [`docs/research-roadmap.md`](docs/research-roadmap.md): the engineering
  spike record (offset and mapped-data `mem` ✅ shipped; locks and
  socket-FD/AF_UNIX/raw spikes closed-and-documented; ETW-based
  socket→FD added as the next open item).
- [`docs/windows-validation.md`](docs/windows-validation.md): T1–T20
  manual validation plan against Windows oracles.
- [`smoketest/README.md`](smoketest/README.md): how to run the harness
  (normal / elevated / against a downloaded binary / with coverage).

### Acknowledgements

A derivative reimplementation of `lsof` (V. A. Abell / Purdue Research
Foundation; see `../COPYING`). No source is shared with the C tree;
behavior and CLI surface are compatible where the concepts map onto
Windows.

[Unreleased]: https://github.com/kj299/lsof/compare/winlsof-v0.1.0...HEAD
[0.1.0]: https://github.com/kj299/lsof/releases/tag/winlsof-v0.1.0
