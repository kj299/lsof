# winlsof — a memory-safe, Windows-native `lsof`, in Rust

`winlsof` is a from-scratch **Rust** reimplementation of the classic `lsof`
("list open files") utility that runs **natively on Windows 11**. It replaces
the Unix `/proc`-based data sources with native Win32/NT APIs, eliminates the
memory-unsafety class of bugs inherent to the original C (buffer overflows,
use-after-free, handle leaks) by construction, and keeps `lsof`'s command-line
surface and output formats so existing scripts keep working.

This is the incremental rewrite described in the project plan; it lives
**alongside** the original C `lsof` tree (in `../`) without modifying it.

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
| `lsof-cli` | The `lsof` binary: lsof-compatible option parsing and rendering. Uses the Windows backend on Windows, a mock backend elsewhere (so the pipeline runs/tests anywhere). |

### Mapping Unix concepts to Windows

| lsof / Unix | Windows replacement (native API) |
|---|---|
| `/proc` PID scan, COMMAND, PPID | `CreateToolhelp32Snapshot` + `Process32NextW` |
| owner uid → USER | process token → `GetTokenInformation(TokenUser)` → `LookupAccountSidW` |
| `/proc/net/{tcp,udp}{,6}` (`-i`) | `GetExtendedTcpTable` / `GetExtendedUdpTable` (`*_OWNER_PID`, v4+v6) |
| `/proc/<pid>/fd/*` open files | `NtQuerySystemInformation` + `NtQueryObject` *(Phase 3)* |
| inode / `st_ino` | `GetFileInformationByHandle` file index *(Phase 3)* |

## Status

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

All planned phases (0–4) are now implemented and the binary runs on real
Windows 10/11 hardware; live validation is in progress via the
[`smoketest/`](smoketest/) harness, with ongoing parity refinements.

## Privilege model (least privilege)

Like Unix `lsof`, **no elevation is required to run** — you get a current-user
view. The binary's manifest pins `requestedExecutionLevel=asInvoker`, so it
never triggers a UAC prompt; an administrator must *deliberately* run elevated
for a system-wide view. Even when elevated, `winlsof` never holds privileges
globally: it enables a privilege (e.g. `SeDebugPrivilege`) only just-in-time
around the specific call that needs it, via the RAII `PrivilegeGuard`, and only
when the switches in use actually require system-wide data. Queries like `-i`
work entirely in the user context and never touch privileges.

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
(*More info → Run anyway*). Releases are produced by pushing a `winlsof-v*` tag,
which triggers [`.github/workflows/winlsof-release.yml`](../.github/workflows/winlsof-release.yml).
Prefer building from source? See below.

## Build & run

```sh
# On Windows (produces target\release\lsof.exe):
cd winlsof
cargo build --release
.\target\release\lsof.exe -nP -i        # network connections + owning process
.\target\release\lsof.exe -p 1234       # files/handles for PID 1234

# On any host (CLI runs against a mock backend for development):
cargo run -- -i
```

## Test

```sh
cd winlsof
cargo test --all                                   # portable core + CLI (any OS)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
# Type-check the Windows backend from a non-Windows host:
rustup target add x86_64-pc-windows-gnu
cargo check --target x86_64-pc-windows-gnu
```

CI (`.github/workflows/winlsof-ci.yml`) runs the lints + tests on Linux and
builds/tests the native backend on `windows-latest`.

For end-to-end validation on a real Windows host (concrete commands + expected
output, cross-checked against `Get-NetTCPConnection`, `handle.exe`, etc.), see
[`docs/windows-validation.md`](docs/windows-validation.md).

The phased plan for the remaining research-grade gaps (socket FD correlation,
AF_UNIX/raw, byte-range locks, mapped data files, file offset) is in
[`docs/research-roadmap.md`](docs/research-roadmap.md).

## License / attribution

Original Rust code. Command-line/output-compatible with `lsof` but sharing no
source with it; see `NOTICE`. The original `lsof` is © Purdue Research
Foundation (V. A. Abell) — see `../COPYING`.
