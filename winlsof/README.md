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
- ✅ **Phase 3 (initial)** — system-wide open *file handle* enumeration via the
  NT handle table (`NtQuerySystemInformation` + `DuplicateHandle` +
  `NtQueryObject`): regular files, directories, and named pipes, with
  drive-letter mapping (`QueryDosDeviceW`), size/file-index, access mode, and the
  `0x0012019F` hang-avoidance heuristic — all under just-in-time `SeDebugPrivilege`
  (`lsof-backend-windows/src/handles.rs`). Pure helpers are unit-tested on the
  Windows CI runner; live full-system validation on a Windows host is pending.
- ⏳ **Phase 4** — mapped modules (`mem`/`txt`), `cwd`/`rtd`, worker-thread name
  resolution for the remaining hang-prone handles, Restart Manager for
  `+D`/named-file lookups, repeat mode.

## Privilege model (least privilege)

Like Unix `lsof`, **no elevation is required to run** — you get a current-user
view. The binary's manifest pins `requestedExecutionLevel=asInvoker`, so it
never triggers a UAC prompt; an administrator must *deliberately* run elevated
for a system-wide view. Even when elevated, `winlsof` never holds privileges
globally: it enables a privilege (e.g. `SeDebugPrivilege`) only just-in-time
around the specific call that needs it, via the RAII `PrivilegeGuard`, and only
when the switches in use actually require system-wide data. Queries like `-i`
work entirely in the user context and never touch privileges.

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

## License / attribution

Original Rust code. Command-line/output-compatible with `lsof` but sharing no
source with it; see `NOTICE`. The original `lsof` is © Purdue Research
Foundation (V. A. Abell) — see `../COPYING`.
