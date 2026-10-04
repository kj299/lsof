# lsof-rs — live Windows smoke test

A self-contained harness that runs the **real `lsof.exe`** on a Windows 10/11
machine, exercises **every option and code path** built so far, captures all
output, cross-checks against native Windows oracles, and (optionally) produces an
**`llvm-cov` line-coverage report** so you can see exactly which lines of lsof-rs
were executed on Windows — and where the gaps (and bugs) are.

CI runs this whole harness on every PR, elevated, on a hosted `windows-latest`
runner, as a hard gate. A run on your own machine adds what CI cannot: the
unelevated pass (hosted runners are always Administrator) and real hardware. A
`FAIL` there is exactly the signal we want — capture it and report back (see
[Reporting findings](#reporting-findings)) and the expectation or the code gets
fixed.

## What it does

`Invoke-LsofRsSmokeTest.ps1`:

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
3. **Runs its cases** — one per flag, format and branch it covers — writing each
   invocation's stdout and stderr to `cases\NNN-name.out.txt` / `.err.txt`.
4. **Cross-checks** against native Windows oracles — `Get-NetTCPConnection`
   (socket owners) and `Get-Process` (`.Path`, `.HandleCount`) — and the
   harness's own fixtures, whose paths/ports are authoritative ground truth.
   **Nothing is downloaded.**
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
  `lsof-rs\target\release\lsof.exe`, and run with `-SkipBuild` (no Rust needed).
- For `-Coverage`: the **MSVC** toolchain (`stable-x86_64-pc-windows-msvc`) plus
  `rustup component add llvm-tools-preview`. `-C instrument-coverage` needs the
  `profiler_builtins` runtime, which the `x86_64-pc-windows-gnu` toolchain doesn't
  ship — on a gnu toolchain the harness detects the failed instrumented build and
  **falls back to a normal run** (no coverage report). To enable coverage:
  `rustup toolchain install stable-x86_64-pc-windows-msvc` (needs VS Build Tools
  for `link.exe`), then re-run with `-Coverage`.
- **No external tools or downloads.** Every oracle is a native Windows command
  (`Get-NetTCPConnection`, `Get-Process`); the harness fetches nothing at runtime.

## Running it

```powershell
cd lsof-rs\smoketest

# 1) Standard pass (current-user view). This is the pass that exercises the
#    unelevated privilege-hint case (it SKIPs under elevation).
powershell -ExecutionPolicy Bypass -File .\Invoke-LsofRsSmokeTest.ps1

# 2) Full pass — run from an ELEVATED PowerShell so the system-wide / other-user
#    handle cases execute (this is where most real bugs hide).
#    (Right-click PowerShell → Run as administrator, then:)
.\Invoke-LsofRsSmokeTest.ps1

# 3) With measurable line coverage (recommended; run elevated for max coverage):
.\Invoke-LsofRsSmokeTest.ps1 -Coverage

# 4) Run the full suite against a PREBUILT binary (a downloaded release, a CI
#    artifact, etc.) instead of building from source - skips the build:
.\Invoke-LsofRsSmokeTest.ps1 -Binary $env:USERPROFILE\Downloads\lsof.exe
```

### Quick portable check — `Test-Lsof.ps1`

For a fast sanity check of any `lsof.exe` with **no repo, build, or Sysinternals
needed**, use the standalone tester. It stands up its own fixtures (a held file +
a loopback listener) and runs ~10 representative cases, each timeout-bounded:

```powershell
.\Test-Lsof.ps1 -Bin $env:USERPROFILE\Downloads\lsof.exe
```

Use `Invoke-LsofRsSmokeTest.ps1 -Binary <path>` for the exhaustive suite (pipes,
mapped files, WOW64 cwd, modules, Restart Manager, every format, native oracles);
`Test-Lsof.ps1` for a 10-second "does this binary work" smoke.

> SKIPs in a single pass are by design, not gaps: the `-T`, `-U`, `-iICMP`,
> `-iRAW` and system-process cases need Administrator (they run in pass 2), while the
> privilege-hint cases (`privilege-hint-unelevated`, `suppress-warnings-dash-w`)
> only apply to a **non-elevated** run (pass 1). Hosted CI runners are always
> elevated, so pass 1's two cases never execute there — their decision logic is
> unit-tested portably instead, and the live unelevated pass is a per-release
> manual checkpoint: see
> [`docs/road-to-1.0.md`](../docs/road-to-1.0.md) (the elevation blind spot).
> The `native-handle-cross-check` case needs no elevation and never SKIPs for a
> missing tool — it verifies lsof-rs against the harness's own fixtures (which it
> holds open) and `Get-Process`. Running pass 1 **and** pass 2 exercises everything.

Results land in `.\lsof-rs-smoke-results\<timestamp>\`.

**Recommended iteration loop (run both, twice):** do an unelevated pass and an
elevated pass, each with `-Coverage`. Compare `coverage-summary.txt` between them
(elevation unlocks more handle code), and open `coverage-html\index.html` to find
any red (unexecuted) lines — those are either missing test cases or dead code.

## Coverage map — which cases touch which code

Case names are the script's own (`Test-Case '<name>'`), so a name here can be
found in the results.

| Area / cases | Source exercised |
|---|---|
| `version`, `help-usage`, `help-alias-question`, `unknown-option-errors`, `end-of-options-dashdash`, `no-op-dash-O`, the `p4-dash-*` checks (`-N`, `-X`, `-Z`, `-e`, `-x`) | `lsof-cli/src/args.rs`, `main.rs` |
| `process-of-self`, `terse-lists-pids`, `user-column-present`, `ppid-column-dash-R`, `numeric-ids-dash-l` | `process.rs` (Toolhelp + token→SID), `render/table.rs` |
| `open-file-listed`, `file-offset-dash-o`, `human-size-dash-H`, `human-size-leaves-offset`, `link-count-dash-L`, `link-filter-plus-L`, `file-flags-plus-f-g` | `handles.rs` (`describe`/`final_path`/`disk_details`/`file_offset`), `render/table.rs` |
| `named-pipe-listed`, `pipe-endpoints-dash-E`, `pipe-endpoints-plus-E` | `handles.rs` PIPE branch, `pipe_display`, the endpoint lookup |
| `mapped-data-file-listed` (`mem`) | `mapped.rs` (`VirtualQueryEx`/`GetMappedFileNameW`) |
| `tcp4-listen-by-port`, `tcp4-established-state`, `tcp6-listen`, `udp4-by-port`, `inet-tcp-only`, `inet6-filter-excludes-v4`, `state-filter-listen`, `state-filter-exclude` | `sockets.rs`, `selection.rs` inet and state filters |
| `inet-icmp-family-dash-i`, `inet-raw-family-dash-i`, `unix-sockets-dash-U` | `etw.rs` (Administrator) |
| `port-service-name-https` (port names by default) | `resolve.rs`, `lsof-core/src/service.rs`, `sockets.rs::format_socket` |
| `tcp-info-selects-not-adds-dash-T`, `tcp-info-window-dash-T`, `tcp-info-window-v6-dash-T`, `tcp-info-fields-dash-T`, `tcp-info-json-dash-T` | `tcpinfo.rs` (EStats; Administrator) |
| `cwd-64bit`, `cwd-wow64-32bit` | `peb.rs` (`read_cwd64`/`read_cwd32`) |
| `modules-txt-image`, `modules-mem-dll` | `modules.rs` |
| `named-file-who-has-open`, `plus-D-directory-tree`, `filesystem-args-dash-f-plus-f` | `restart.rs`, `selection.rs` paths and dir trees |
| `tasks-dash-K`, `tasks-dash-K-i-suppresses`, `tasks-dash-K-terse`, `tasks-dash-K-with-a-held-file`, `tasks-not-listed-by-default` | `threads.rs`, `selection.rs` |
| `fd-filter-named-cwd`, `and-mode-dash-a`, `command-filter`, `ppid-select-dash-g`, `command-width-plus-c` | `selection.rs`, `render/table.rs` |
| `field-output-bare-F`, `field-output-Fpn`, `field-output-nul-F0`, `field-output-socket-state`, `json-aggregated-J`, `json-lines-j` | `render/fields.rs`, `render/json.rs` |
| `verbose-pid-not-found`, `quiet-dash-Q`, `suppress-warnings-dash-w` | `main.rs::unlocated`, `handles.rs` verbose |
| `privilege-hint-unelevated`, `inet-no-privilege-hint`, `elevated-system-process-handles` | `privilege.rs`, `backend.rs` least-privilege, `main.rs` hint |
| `native-handle-cross-check` | the harness's own fixtures and `Get-Process` |
| `repeat-mode-dash-r` | `main.rs` repeat loop |

`-Coverage` turns "touch each line" from aspiration into a measured number.

## Reporting findings

For each `FAIL` (or surprising output), the fix loop needs:

1. The **`summary.txt`** and **`results.csv`** from the run folder.
2. The failing case's raw **`cases\NNN-name.out.txt` / `.err.txt`**.
3. The matching **oracle** output (the harness prints it for socket cases; for
   others run e.g. `Get-Process -Id <pid> | Format-List`).
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
- **No downloads.** The harness runs only native Windows commands and never fetches
  an executable at runtime, so a compromised download host cannot inject code into
  the test machine. (This is why the former Sysinternals `handle64.exe` oracle was
  removed in favor of native `Get-Process` + fixture ground truth.)
