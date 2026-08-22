# Changelog

All notable changes to **winlsof** (the Rust, Windows-native `lsof`
reimplementation under [`winlsof/`](.)). The changelog tracks the new Rust
workspace; the legacy C `lsof` tree in the parent directory is untouched.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Docs truth pass.** `feature-parity-plan.md` still marked all twelve
  Phase 5A switches 🟡-planned though they shipped in v0.2.0 (now recorded as
  the option inventory + mapping decisions); `windows-validation.md` still
  instructed using Sysinternals `handle64.exe` as the file-handle oracle,
  contradicting the v0.3.0 supply-chain decision that removed downloaded
  oracles from the test path (now native fixtures/`Get-Process` only, and
  version-agnostic); the research-roadmap intro and README pointers now
  reflect that every roadmap item is shipped or a documented closed gate.

### Added
- **`-iICMP` / `-iRAW` family filters** — the last open research-roadmap item
  (§5 P3). The `-i` spec now accepts `icmp` and `raw` protocol names like
  `tcp`/`udp` (case-insensitive; the `[46]` prefix narrows the family, so
  `-i6ICMP` is v6-only, and `ICMP` covers both the v4 `ICMP` and v6 `ICMPV6`
  codes). These families exist only in the ETW AFD capture — they have no IP
  Helper table — so either filter **implies the (Administrator-only) capture**
  the way `-U` does, instead of silently matching nothing. With this, roadmap
  §5 is complete and the roadmap has no open items.
- **`-T` queue/window stats in the machine formats.** The `-Tq`/`-Tw`
  extended TCP info (EStats) was previously table-only; it now also emits
  structured `-F` `T` fields using lsof's own prefixes — `TQR=` (read queue),
  `TQS=` (send queue), `TWR=` (advertised receive window), after the existing
  `TST=` — and JSON keys `tcp_window` / `tcp_queue_recv` / `tcp_queue_send`
  on socket objects. Pinned by portable golden tests across all three
  renderers and two new elevated live smoke cases (`-F` and `-J`).

### Changed
- **`-T` annotations no longer pollute machine-format names.** The
  `(Win=N) (QR=N) (QS=N)` decoration used to be appended to the row's NAME
  string at capture time, so `-T` combined with `-F`/`-J` leaked it into the
  `n` field / JSON `"name"`. The stats now travel as structured data; the
  table renders the identical suffix at display time (table output is
  byte-for-byte unchanged — the live smoke assertions still pass), and the
  machine formats keep a clean name plus the structured tokens above.
- **Nightly deep fuzz with an accumulating corpus**
  (`.github/workflows/winlsof-fuzz-nightly.yml`): a scheduled 30-minute
  `cargo-fuzz` run over the argument parser — 40× the PR gate's budget —
  restoring the previous night's corpus from the Actions cache and saving the
  grown one, so coverage compounds across nights. Crash reproducers upload as
  artifacts on a finding.
- **The privilege-hint decision is unit-tested on both elevation branches on
  every push.** Hosted CI runners are always elevated, so the two
  unelevated-only smoke cases (hint present; `-w` suppresses it) permanently
  SKIP in CI. The hint condition is now the extracted pure
  `wants_privilege_hint()` predicate, tested through the real argv parser on
  all platforms; the untestable-in-CI residue (the `TokenElevation` query
  itself) is a documented per-release manual checkpoint.
- **[`docs/road-to-1.0.md`](docs/road-to-1.0.md)**: what 1.0 means (a
  stability commitment on the option surface and `-F`/`-J` schemas), the
  six-item exit-criteria checklist (signed releases, a 14-night green fuzz
  soak, RC field validation in both privilege modes, gates green), and the
  elevation blind-spot decision record — why a low-privilege CI step on
  always-admin, UAC-disabled runners would test the runner rather than the
  product.

## [0.3.0] — 2026-07-25

**The depth-and-verification release.** 0.2.0 completed the option *surface*;
0.3.0 closes the depth gaps a full-port gap analysis found behind it — above
all, handle types the scan silently dropped — and hard-gates the whole feature
surface in CI so a dropped or untested feature now fails the build.

### Added
- **All Windows kernel object types in the handle listing.** The all-handle
  scan previously classified only `File` handles and silently skipped every
  other object type. It now types and names them all: registry keys (`KEY`,
  `\REGISTRY\...`), events (`EVT`), mutants (`MUT`), sections (`SECT`),
  process/thread/token handles (`PROC`/`THRD`/`TOKN`), and a long tail via
  short codes (`SEM`, `JOB`, `IOCP`, `ALPC`, `TMR`, ...). Named objects show
  their object-namespace path; a per-boot type-index cache keeps the unscoped
  scan at one type query per object type, not per handle. Pinned end-to-end by
  a test that creates real Event/Mutant/Section/process/token/char-device
  handles and requires each TYPE code back from an actual enumeration.
- **`(deleted)` NAME decoration** for open-but-unlinked regular files (the
  Windows delete-pending state) — the classic lsof signal for a file held open
  after removal; pairs with `+L 1`.
- **Socket oracle-substitution differential** (`winlsof/differential/`):
  winlsof's `-i` socket *set* is diffed against the OS's own table
  (`Get-NetTCPConnection`/`Get-NetUDPEndpoint`) over self-owned fixtures on
  every CI run — landed observe-first, now a hard gate, with a ledger for the
  one documented data-source divergence (transient BOUND sockets).
- **Feature-coverage gate in CI.** A curated inventory of the C's enumerated
  surface (45 option letters, 111 TYPE codes, extracted from lsof's own
  source) plus winlsof's Windows-native types is diffed against what the test
  suite actually exercises; anything neither covered nor explicitly waived
  (with a reason) fails the build. 163 features: 45 covered, 118 waived, 0
  silent.
- **The 55-case live smoke harness now runs in CI as a hard gate** (previously
  manual-only). Its first hosted run immediately found a real product bug (see
  Fixed) and a fixture bug — fixtures are now correct on pwsh 7/hosted
  runners (kernel-level file-position ground truth; elevation-dependent cases
  self-skip).
- **CI safety gates:** toolchain-free unsafe-audit (a `// SAFETY:` on every
  backend `unsafe` block — 139/139, hard fail), `cargo-deny` supply-chain
  checks, `[workspace.lints]` (incl. `undocumented_unsafe_blocks` and
  `missing_safety_doc` as errors), and a `cargo-fuzz` smoke run over the
  argument parser on every PR.

### Changed
- **`-F i` no longer leaks the socket protocol as an inode.** lsof leaves the
  `i` field empty for sockets (the protocol is reported via `P`); winlsof now
  matches.
- **The `-r` repeat-cycle marker is format-aware**, matching lsof: `=======`
  for the table, the `m` marker field for `-F` (NUL-then-NL under `-F0` so
  record splitting still works), and nothing for JSON, whose objects
  self-delimit. Previously a bare `=======` corrupted `-F`/`-J` streams under
  `-r`.
- **Path selectors are canonicalized before matching.** Bare paths and
  `+d`/`+D` directories are resolved to the same long-form spelling the
  backend reports, so 8.3 short names (`C:\Users\RUNNER~1\...`), relative
  paths, and symlinked directories now match instead of silently selecting
  nothing. Unresolvable paths are kept as typed, preserving the exit-1
  unmatched-item contract.

### Fixed
- Three FFI soundness bugs in the Windows backend found by the unsafe audit:
  an out-of-bounds read over an empty `MIB_*TABLE_OWNER_PID` table (reachable
  on every `lsof -i` when a TCP6/UDP table is empty), an off-by-one over the
  ETW property array, and an `NtQuery*` buffer-length-vs-allocation mismatch.
- `-u` (user filter) had no test at any layer; it now has parser and
  selection-engine tests (bare account and `DOMAIN\user`, case-insensitive,
  cross-domain rejection).

### Security
- **smoketest: removed the runtime download of Sysinternals `handle64.exe`.**
  The live harness fetched and executed `handle64.exe` from
  `download.sysinternals.com` as a handle-enumeration oracle — a supply-chain
  risk if the download host were compromised. Replaced with native oracles
  only (`Get-Process` + the harness's own fixture ground truth);
  `Get-NetTCPConnection` continues to cross-check sockets. Nothing is
  downloaded at test time.

## [0.2.0] — 2026-07-02

**Full lsof option-parity** ("Phase 5"): every in-scope lsof switch is now
implemented — [`docs/feature-parity-plan.md`](docs/feature-parity-plan.md)
holds the complete option inventory. Validated end-to-end on real Windows 11
hardware in both privilege modes with the expanded 55-case smoke suite
(elevated: 53 pass / 0 fail / 2 skip; unelevated: 51 / 0 / 4 — the union
covers all 55 cases).

### Added

- **Phase 5B — `-T [fqsw]` extended TCP info** (complete: IPv4 + IPv6):
  annotates **ESTABLISHED** TCP socket rows with the current receive window
  (`(Win=N)`) and app queue depths (`(QR=N)` / `(QS=N)`), read from
  per-connection extended TCP statistics (`GetPerTcpConnectionEStats` /
  `GetPerTcp6ConnectionEStats`, dispatched over a `RowKey { V4, V6 }` so the
  enable → read → disable flow is written once). EStats collection is
  enabled just-in-time per connection (needs Administrator) and disabled
  again — bounded and reversed; non-ESTABLISHED rows are skipped (EStats
  reports `ERROR_NOT_SUPPORTED` for them). `s` (state) is already shown;
  `f` (follow) is a no-op for a snapshot. Verified on Windows 11 over live
  v4 and v6 loopback pairs. Known corner: link-local (`fe80::`) rows carry
  scope id 0 internally and are left unannotated.
- **Phase 5B — `-U` UNIX-domain sockets**: AF_UNIX endpoints (Windows 10
  1803+) have no IP Helper table, so `-U` implies the (Administrator-only)
  ETW AFD capture and restricts socket output to AF_UNIX rows. A bare `-U`
  stays least-privilege — no handle-table enumeration; `-U -i` lists
  TCP/UDP (IP Helper) plus AF_UNIX (ETW).
- **Phase 5B — `-E` / `+E` pipe endpoint info**: pipe NAMEs gain
  ` (server=PID,cmd client=PID,cmd)` via the documented
  `GetNamedPipeServerProcessId` / `GetNamedPipeClientProcessId` APIs
  (anonymous pipes included), queried on the already-duplicated handle
  inside the hang-bounded per-handle worker, so the no-freeze invariant
  holds. `+E` additionally displays the peer processes' own pipe rows even
  when they match no selector (new `Process::endpoint_peer` flag, honored
  by the selection engine and composing with `-d`/`-s`/path filters).
  Works unelevated on your own processes. AF_UNIX peer PIDs have no public
  API; the ETW endpoint pointer on `--etw` rows remains the correlation
  key there.
- **Phase 5A — lsof option-parity port** (12 canonical switches the MVP
  didn't ship). All additive; the v0.1.0 CLI surface is unchanged.
  - **`-s [proto:state]`** — socket protocol/state filter
    (`TCP:LISTEN`, `TCP:^TIME_WAIT`, `TCP:LISTEN,ESTABLISHED`).
  - **`-K`** — list each in-scope process's threads as `task` rows
    (TID in NODE), via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`;
    needs no elevation.
  - **`-L`** — NLINK (hard-link count) column, from
    `BY_HANDLE_FILE_INFORMATION.nNumberOfLinks`. **`+L <n>`** keeps only
    files with link count `< n` (`+L 1` = unlinked-but-still-open).
    Also surfaced as the `-F k` field code and a `"links"` JSON key.
  - **`-l`** — numeric USER column (the raw SID string via
    `ConvertSidToStringSidW`) instead of the resolved `DOMAIN\user`.
  - **`-g <ppid>[,…]`** — Windows-extension semantics: select processes
    whose parent PID is in the list (Windows has no PGID).
  - **`-Q`** — quiet; suppress "no matching open files" on empty results.
  - **`-w` / `+w`** — suppress / enable non-fatal stderr warnings
    (the least-privilege hint).
  - **`-O`** — accepted as a documented no-op (Unix "avoid fork" hint).
  - **`+c <n>`** — cap the COMMAND column width.
  - **`-?`** — alias for `-h`.
  - **`--`** — end-of-options sentinel (so `lsof -- -name` is a path).
  - **`--unicode` / `--ascii`** — opt-in UTF-8 vs default ASCII output
    (`SetConsoleOutputCP(65001)`), so the banner/glyphs don't garble on
    PowerShell 5.1 / cmd.exe (Windows-1252 console).
  - `OpenFile` gained a `links: Option<u32>` field; `FdType::Task` and a
    `task`/`THRD` rendering path were added to `lsof-core`.
- **`--etw` opt-in flag** (Windows, iterations 1–3): runs a short
  `Microsoft-Windows-Winsock-AFD` ETW realtime capture (needs Administrator
  or *Performance Log Users* membership) and emits the **non-TCP/UDP**
  sockets it observes (raw, ICMP, ICMPv6, AF_UNIX) as additional `-i`
  rows — extending `-i` coverage beyond what IP Helper's tables enumerate.
  Stderr still carries the per-event-ID histogram and per-event TDH
  schemas (for diagnosability). See
  [`docs/research-roadmap.md`](docs/research-roadmap.md) §5.
- **`Protocol::Other(&'static str)`** added to `lsof-core::model` so the
  socket NODE column can render "ICMP", "ICMPV6", "RAW", "AF_UNIX", … for
  ETW-discovered rows. Existing `Protocol::Tcp`/`Protocol::Udp` matches
  unchanged.
- **Smoke suite: 37 → 55 cases** — one case per new switch, plus an
  established IPv6 loopback pair fixture (for `-T` v6 EStats), a connected
  named-pipe client fixture (so `-E` resolves both endpoint PIDs), and a
  `-U` case asserting the ETW capture fires. The harness also recognizes
  `target\` file-lock build failures (OneDrive sync handles) and suggests
  `-SkipBuild` when a current binary already exists.

### Fixed

- `-F` field output no longer emits a bare `n` field code for rows with an
  empty NAME (the `-K` thread `task` rows); regression-guarded by a golden
  test.
- Console output now defaults to pure ASCII so the banner doesn't garble
  on PowerShell 5.1 / cmd.exe (Windows-1252 console); `--unicode` opts
  into CP 65001 UTF-8.

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

[Unreleased]: https://github.com/kj299/lsof/compare/winlsof-v0.2.0...HEAD
[0.2.0]: https://github.com/kj299/lsof/compare/winlsof-v0.1.0...winlsof-v0.2.0
[0.1.0]: https://github.com/kj299/lsof/releases/tag/winlsof-v0.1.0
