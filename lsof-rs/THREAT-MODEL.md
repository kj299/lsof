# Threat model — lsof-rs

Scopes what "secure" means for this port, and tells the port loop which modules
touch untrusted input (fuzz those first) and which cross a privilege boundary
(audit those hardest). Written against the tree as of 2026-09-20; every claim
below was checked against the code rather than inferred from the C's design.

`lsof` reports which files processes have open. It is an **observer**: it never
writes to the system it inspects, never spawns a subprocess, and has no network
listener. Its risk is therefore asymmetric — almost all of it is in *reading
hostile data* and in *what it discloses*, not in what it changes.

## 1. Assets — what are we protecting?

**The integrity of the reporting process itself.** Every byte lsof-rs parses is
supplied by something it does not control: another user's process name, a
filename someone chose, a `/proc/net` table the kernel formats from packets that
arrived from the network. A crash is a denial of the tool; memory corruption in a
tool people run as root is worse. This is the primary asset and the reason the
fuzz gate exists.

**The confidentiality boundary the kernel already draws.** lsof-rs must not widen
it. What an unprivileged user can see through lsof-rs should be exactly what that
user could see by reading `/proc` themselves — no more. The port takes no
privilege on Linux at all (§3), so this holds by construction there rather than
by care.

**The accuracy of the report.** Not confidentiality, but a real asset: this tool
is used during incident response. A row that is silently wrong, or an entry
silently dropped, can send an investigation the wrong way. Two of the three
C-defects in §6 are exactly this failure — output that is quietly incomplete
rather than visibly broken. Accuracy is therefore in scope for the differential
gate, not just correctness-as-taste.

**The host it runs on.** Only indirectly: lsof-rs does not modify the host, so
this reduces to not being a vector — not executing attacker data, not passing it
to a shell (no subprocess is ever spawned), and not corrupting its own memory.

## 2. Trust boundaries — where does untrusted data cross in?

Every row is an input this process does not control. The "fuzz target" column is
the answer to "what proves we survive hostile bytes here", and an empty cell in
it is a gap, not a formatting choice.

| Entry point | Source | Trust | Ported module | Fuzz target |
|---|---|---|---|---|
| CLI args, the selection grammar | invoking user or a calling script | untrusted | `lsof-cli`, `lsof-core` | `parse_args` |
| `/proc/PID/stat`, `status`, `comm`, `cmdline` | **any local user's process** | **hostile** | `lsof-backend-linux::process` | `proc_status` |
| `/proc/PID/fd/N` symlink targets | filesystem, any local user | **hostile** | `lsof-backend-linux::files` | `render_escape` |
| `/proc/PID/fdinfo/N` | kernel, per-fd | untrusted | `lsof-backend-linux::files` | `proc_fdinfo` |
| `/proc/PID/maps` | kernel + mapped filenames | **hostile** | `lsof-backend-linux::maps` | `proc_maps` |
| `/proc/net/{tcp,udp,raw,unix,icmp,netlink,packet}` | kernel, shaped by **remote** traffic | **hostile** | `lsof-backend-linux::net` | `proc_net` |
| `/proc/self/mounts`, mountinfo | kernel + mount namespace | untrusted | `lsof-backend-linux::mounts` | `proc_mounts` |
| `/proc/locks` | kernel | untrusted | `lsof-backend-linux::locks` | `proc_locks` |
| `/etc/passwd`, `/etc/group` | operator, but arbitrary bytes | semi-trusted | `lsof-backend-linux::users` | `passwd` |
| Windows handle table, object names | **any local process** | **hostile** | `lsof-backend-windows::handles` | `windows_names` |
| Another process's PEB, via `ReadProcessMemory` | **the target process** | **hostile** | `lsof-backend-windows::peb` | none — see below |
| `LSOF_RS_TRACE`, `WINLSOF_TRACE` | operator | trusted-ish | tracing setup | not applicable |

Three things about this table are worth saying out loud, because they are the
difference between it being a security document and being a diagram.

**"Hostile" is not rhetorical.** Any local user can start a process whose `comm`
and `cmdline` are bytes of their choosing, and open a file whose *name* is bytes
of their choosing. On Linux a filename is a NUL-terminated byte string with no
encoding guarantee — it is not UTF-8, and assuming it is has been a real bug in
this family of tools. `/proc/net/tcp` is one step further out: its contents are
shaped by whoever sent packets to this host. These are not "semi-trusted config
files"; they are adversary-controlled inputs reached without authentication.

**The PEB row has no fuzz target, and that is a known gap.** `peb.rs` walks
another process's memory at documented `RTL_USER_PROCESS_PARAMETERS` offsets via
`ReadProcessMemory`, for both 64-bit and WOW64 targets. The *target* process can
write its own PEB, so the lengths and pointers read there are attacker-chosen.
The code bounds each read and treats failure as "no cwd", but the input is not
currently driven by a fuzzer the way the `/proc` parsers are. Recorded here
rather than left to be discovered.

**The environment surface is two variables.** The C `lsof` reads considerably
more, including the personal device-cache path; lsof-rs's whole environment
surface is the two trace switches above. The device cache is not ported (it is a
Unix kernel-memory-access feature this port does not need — see §5), so the class
of issues around a user-writable cache file consulted by a privileged binary does
not exist here.

## 3. Privilege transitions

**Linux: there are none.** This is the single largest security difference from
the C, and it is structural rather than careful.

The C `lsof` ships **setgid** (to the group owning the kernel memory files) and
sometimes setuid-root, opens what it needs, then relinquishes the power —
`src/main.c` carries `Setgid` and the "relinquish the setgid power" path, and
`00DCACHE` documents the model, including that `lsof` never drops setuid-root
because it keeps needing it. That design exists because the C reads kernel
memory. lsof-rs's Linux backend reads **only `/proc`**, so it needs no such
privilege: it is installed as an ordinary unprivileged binary, never calls
`setuid`/`setgid`/`seteuid`, and enumerates exactly what the invoking user is
already permitted to read. Verified by grep across the crates: no `setuid`,
no `setgid`, and no `Command::new` anywhere in non-test code.

The backend is additionally `#![forbid(unsafe_code)]`, as are `lsof-core` and
`lsof-cli`, so the Linux path cannot reach libc's privilege calls even by
accident. When lsof-rs shows fewer rows than the C, that is usually this
difference and not a defect.

**Windows: just-in-time, scoped, and never for the common case.**
`lsof-backend-windows::privilege` implements the kit's `PrivilegeGuard` RAII
pattern: a named privilege (`SeDebugPrivilege`) is enabled for *only* the
lifetime of the guard and removed on drop. It is enabled around the specific call
that needs it, only when the switches in use require system-wide data — never
globally, and never at all for queries like `-i` that work in the plain user
context. `is_elevated()` reads `TokenElevation` purely to tailor a user-facing
hint; by its own contract it never causes a privilege to be enabled.

The audit hotspots on Windows are therefore: the guard's drop path (a privilege
left enabled is the failure), `handles.rs` where the guard is taken, and `peb.rs`
where elevation buys the ability to read another process's memory. That crate
holds essentially all of the port's `unsafe` — roughly 153 blocks against 3 in
the Linux backend, 4 in the CLI and 2 in core — which is why the unsafe-audit and
sanitizer gates are pointed at it.

## 4. Attacker capabilities we defend against

- **Supplies arbitrary bytes at any boundary in §2** — a process name of raw
  high bytes, a filename that is not valid UTF-8, a `/proc/net` line with
  unexpected field counts. Defence: no panic and no UB on any input. Enforced by
  the fuzz gate over the ten targets listed above, plus `forbid(unsafe_code)` on
  the three portable crates.
- **Supplies bytes chosen to break the renderer rather than the parser.** Column
  widths are computed from attacker-controlled strings. Getting this wrong
  corrupts the *table*, not the process, which makes it quiet — and it is exactly
  the live C defect in §6. Defence: `render_escape` fuzz target, and the
  differential's byte-level comparison, which since this refresh distinguishes
  `\xff` from `\xfe` instead of collapsing both to U+FFFD.
- **Supplies pathological sizes** — implausible lengths in a PEB, huge fd counts,
  a very long path. Defence: checked arithmetic (`arithmetic_side_effects` is
  denied workspace-wide, so `i + 1` does not compile), bounded reads in `peb.rs`.
- **Races the enumeration.** `/proc/PID` is inherently racy: a process can exit
  between `readdir` and the read of its entries, and a PID can be recycled.
  Defence: treat every per-process read as fallible and skip, never abort the
  listing and never report a partial row as complete. This is a correctness
  requirement that is also a denial-of-service defence.
- **Is the process being inspected.** On Windows the target controls its own PEB
  contents; on Linux it controls its `comm`, `cmdline` and the names of files it
  opens. The inspecting process must not trust any of it beyond "bytes to render
  safely".

## 5. Explicit non-goals

Stated so reviewers do not assume coverage that is not there.

- **We do not defend against an operator who already holds our privileges.**
  Someone who can run lsof-rs as root can read `/proc` as root directly; lsof-rs
  is not a confinement mechanism.
- **lsof-rs is not a security boundary between the invoking user and the
  kernel.** It shows what the caller is already permitted to see. It deliberately
  adds no access of its own on Linux (§3), so there is no "lsof-rs told me
  something I was not allowed to know" threat to defend against there.
- **No side-channel resistance.** Timing, memory-usage and ordering differences
  between runs are not treated as leaks. The tool's whole purpose is disclosure
  to an authorised caller.
- **Kernel memory access is out of scope, permanently.** The C reads kernel
  memory on several platforms and carries the setgid model and the device cache
  to support it. This port reads `/proc` and documented Windows APIs instead.
  That is a deliberate capability reduction, not an unfinished feature.
- **We do not defend the accuracy of data the platform will not give us.**
  Where an API cannot supply a field, lsof-rs reports it as unknown rather than
  fabricating it. `docs/known-limitations.md` enumerates these; the Windows
  socket-to-handle join is the main one.
- **The Windows backend's `unsafe` FFI is in scope for review but not for
  formal proof.** It is audited (`audit_unsafe.py`, every block documented) and
  sanitized (ASan on Windows, miri on the portable crates), not verified.

## 6. C-defect inventory

The kit's rule is that the C is a specification which may itself be buggy, and
that a defect found in it is triaged rather than faithfully re-implemented. Three
are currently recorded in [`DIVERGENCES.md`](DIVERGENCES.md) as **`C-DEFECT`**,
each with the C code named so the triage can be checked:

- **`hostile-comm-utf8-table`** — the C mis-sizes a table column when a process
  `comm` contains bytes ≥ 0x80, taking the wrong branch. This is the §4
  "breaks the renderer, not the parser" capability, live, in the tool's most
  attacker-reachable string. Not reproduced by lsof-rs.
- **`lsof -c ^name` exits 1 on a successful listing** while `lsof -u ^name`
  exits 0, for two options the man page describes identically. lsof-rs copies
  the half that is defensible and not the asymmetry.
- **A bare path argument alongside `+d`/`+D` makes the C silently lose the
  expansion's entries.** Measured: 4 entry rows dropped on a fixture where a
  correct result is discarded because of an unrelated argument. Silently
  incomplete output, which §1 names as an asset in its own right. Not reproduced.

**Gap: there is no checked-in `scan_c_flaws.py` report for this tree.** Phase 0
prescribes one and the harness exists (`porting-kit/harnesses/c-flaw-scan/`), but
no output is committed, so the three defects above are the ones the differential
and hostile-input work happened to surface rather than the result of a systematic
scan. Running it and triaging the findings into this section is outstanding work,
named here rather than left implicit — a threat model that quietly omits its own
gaps is the documentation theater this file's gate exists to prevent.
