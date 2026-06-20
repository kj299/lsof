# winlsof — live Windows smoke test

A self-contained harness that runs the **real `lsof.exe`** on a Windows 10/11
machine, exercises **every option and code path** built so far, captures all
output, cross-checks against native Windows oracles, and (optionally) produces an
**`llvm-cov` line-coverage report** so you can see exactly which lines of winlsof
were executed on Windows — and where the gaps (and bugs) are.

This is the P0 "prove it actually runs on hardware" step: CI compiles the backend
and runs scoped integration tests, but only a real machine exercises the
system-wide paths, elevation, WOW64, and the OS data sources end to end.

> First-run expectation: this harness was authored without a Windows host to
> validate against, so some **assertions may be too strict vs. real output**. A
> `FAIL` here is exactly the signal we want — capture it and report back (see
> [Reporting findings](#reporting-findings)) and the expectation/code gets fixed.

## What it does

`Invoke-WinlsofSmokeTest.ps1`:

1. **Builds** `lsof.exe` (`--release`, or an instrumented debug build with
   `-Coverage`).
2. **Stands up controlled fixtures** in the harness process and in child
   processes, so every observable state exists deterministically:
   - a held-open **regular file** with bytes written and the file pointer
     **seeked to offset 128** (exercises handle naming, size/node, and `-o`),
   - a **named pipe** server (PIPE classification),
   - a **memory-mapped data file** (the `mapped.rs` `mem` path),
   - **TCP v4** listener + a connected **ESTABLISHED** pair, **TCP v6** listener,
     **UDP v4/v6** sockets,
   - child **cmd.exe** with a known cwd (64-bit) and **SysWOW64\cmd.exe** (32-bit
     **WOW64**, exercises the 32-bit PEB cwd path).
3. **Runs ~50 cases** covering every flag/format/branch, writing each invocation's
   stdout/stderr/exit code to `cases\NNN-name.out.txt` / `.err.txt`.
4. **Cross-checks** against `Get-NetTCPConnection`, `Get-NetUDPEndpoint`,
   `Get-Process` (`.Path`/`.Modules`), `netstat -ano`, and Sysinternals
   `handle64.exe` if supplied.
5. **Emits results**: `results.csv`, `summary.txt`, a console PASS/FAIL/SKIP
   roll-up, and a full `transcript.log`.
6. **Optional coverage** (`-Coverage`): merges per-case `*.profraw` and produces
   `coverage-summary.txt` + an HTML report so you can confirm line coverage and
   find untouched code.

## Prerequisites

- Windows 10/11 x64, PowerShell 5.1+ (or PowerShell 7).
- Rust toolchain (`rustup`, `cargo`) with the MSVC target — **only needed to build
  from source.** Alternatively, download a prebuilt `lsof.exe` from the
  [Releases](https://github.com/kj299/lsof/releases) page, drop it at
  `winlsof\target\release\lsof.exe`, and run with `-SkipBuild` (no Rust needed).
- For `-Coverage`: `rustup component add llvm-tools-preview` (the script attempts
  this automatically).
- Optional: [Sysinternals `handle64.exe`](https://learn.microsoft.com/sysinternals/downloads/handle)
  on `PATH` or passed via `-HandleExe`.

## Running it

```powershell
cd winlsof\smoketest

# 1) Standard pass (current-user view). Some elevated-only cases will SKIP.
powershell -ExecutionPolicy Bypass -File .\Invoke-WinlsofSmokeTest.ps1

# 2) Full pass — run from an ELEVATED PowerShell so the system-wide / other-user
#    handle cases execute (this is where most real bugs hide).
#    (Right-click PowerShell → Run as administrator, then:)
.\Invoke-WinlsofSmokeTest.ps1

# 3) With measurable line coverage (recommended; run elevated for max coverage):
.\Invoke-WinlsofSmokeTest.ps1 -Coverage

# 4) Extra handle cross-checks:
.\Invoke-WinlsofSmokeTest.ps1 -HandleExe C:\tools\handle64.exe
```

Results land in `.\winlsof-smoke-results\<timestamp>\`.

**Recommended iteration loop (run both, twice):** do an unelevated pass and an
elevated pass, each with `-Coverage`. Compare `coverage-summary.txt` between them
(elevation unlocks more handle code), and open `coverage-html\index.html` to find
any red (unexecuted) lines — those are either missing test cases or dead code.

## Coverage map — which cases touch which code

| Area / cases | Source exercised |
|---|---|
| `version`, `help`, `bad-option`, all flag parsing | `lsof-cli/src/args.rs`, `main.rs` |
| `terse`, `process-table`, owner/USER column | `process.rs` (Toolhelp + token→SID), `render/table.rs` |
| `offset-self` (`-o`), file handle naming/size/node | `handles.rs` (`describe`/`final_path`/`disk_details`/`file_offset`) |
| `named-pipe`, `char device` | `handles.rs` PIPE/CHAR branches, `pipe_display` |
| `mapped-file` (`mem`) | `mapped.rs` (`VirtualQueryEx`/`GetMappedFileNameW`) |
| `tcp4/tcp6/udp4/udp6`, LISTEN/ESTABLISHED, `-i` filters | `sockets.rs`, `selection.rs` inet filter |
| `-n`/`-P` resolution, service names | `resolve.rs`, `lsof-core/src/service.rs`, `sockets.rs::format_socket` |
| `cwd-64bit`, `cwd-wow64` | `peb.rs` (`read_cwd64`/`read_cwd32`) |
| `modules-txt`, `modules-mem` | `modules.rs` |
| `named-file-lookup`, `+D` | `restart.rs`, `selection.rs` paths/dir_trees |
| `-d` (named/num/range/`^excl`), `-R`, `-a`, `-c`, `-u` | `selection.rs`, `render/table.rs` |
| `-F`/`-F0`/`-Fxxx`, `-J`, `-j` | `render/fields.rs`, `render/json.rs` |
| `-V` verbose, not-found, inaccessible count | `main.rs::report_unmatched`, `handles.rs` verbose |
| `priv-hint`, `inet-no-hint`, elevated system-process handles | `privilege.rs`, `backend.rs` least-privilege, `main.rs` hint |
| `repeat-mode` (`-r`) | `main.rs` repeat loop |

`-Coverage` turns "touch each line" from aspiration into a measured number.

## Reporting findings

For each `FAIL` (or surprising output), the fix loop needs:

1. The **`summary.txt`** and **`results.csv`** from the run folder.
2. The failing case's raw **`cases\NNN-name.out.txt` / `.err.txt`**.
3. The matching **oracle** output (the harness prints it for socket cases; for
   others run e.g. `Get-Process -Id <pid> | Format-List` / `handle64.exe -p <pid>`).
4. With `-Coverage`: the **`coverage-summary.txt`** (per-file line %), and a note
   of any source lines still red in `coverage-html`.

Paste those back and the assertion or the underlying code path gets fixed, then
re-run. Repeat until PASS across an elevated `-Coverage` run with no meaningful
red lines.

## Safety notes

- All fixtures are local (loopback sockets, temp files) and cleaned up in a
  `finally` block; child `cmd.exe` processes are hidden and killed at the end.
- Queries are scoped (`-p <pid>`, `-i :port`) wherever possible, so handle
  enumeration stays bounded and avoids the `NtQueryObject` hang class by design.
- Every case has a **hard per-invocation timeout** (`Invoke-Lsof -TimeoutSec`,
  default 60s): if `lsof.exe` ever wedges, the harness kills it and records the
  case as `FAIL` ("possible hang") instead of freezing — so a regression turns
  into a fast, actionable signal rather than a stuck run.
- The harness never elevates itself; run it elevated yourself for the system-wide
  cases.
