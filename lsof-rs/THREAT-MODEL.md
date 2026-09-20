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

Two sources feed this: divergences the differential surfaced, and the Phase-0
flaw scan. Both are now present; the scan was the gap this section used to name
against itself.

### 6a. Confirmed defects, already triaged

The kit's rule is that the C is a specification which may itself be buggy, and
that a defect found in it is triaged rather than faithfully re-implemented. Three
are recorded in [`DIVERGENCES.md`](DIVERGENCES.md) as **`C-DEFECT`**, each naming
the C code so the triage can be checked:

- **`hostile-comm-utf8-table`** — the C mis-sizes a table column when a process
  `comm` contains bytes ≥ 0x80. The scan below independently re-finds this at its
  root, `lib/misc.c:1369`. This is the §4 "breaks the renderer, not the parser"
  capability, live, in the tool's most attacker-reachable string. Not reproduced.
- **`lsof -c ^name` exits 1 on a successful listing** while `lsof -u ^name`
  exits 0, for two options the man page describes identically. lsof-rs copies
  the half that is defensible and not the asymmetry.
- **A bare path argument alongside `+d`/`+D` makes the C silently lose the
  expansion's entries.** Measured: 4 entry rows dropped where a correct result is
  discarded because of an unrelated argument. Silently incomplete output, which
  §1 names as an asset in its own right. Not reproduced.

### 6b. The Phase-0 flaw scan

Report: [`coverage/c-flaw-scan.json`](coverage/c-flaw-scan.json), from
`porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py src lib/*.c lib/dialects/linux`.

The harness says of itself that it is "deliberately noisy: every hit is a
*question* for the porter". So the raw count is not a finding; the triage is.

The first run produced **113** hits. Triaging them found a fifth of the output was
text that never executes, so the scanner was fixed before the numbers were written
down (§6d) — the report above is the post-fix run, **98** hits.

**26 of those are in code this platform does not compile.** Verified in the headers
rather than assumed:

- `lib/dvch.c` — the whole body is inside `#if defined(HASDCACHE)`, and
  `lib/dialects/linux/machine.h` carries `/* #define HASDCACHE 1 !!!DON'T
  ENABLE!!! */` with a caution paragraph. Dead on Linux. (This is also why the
  device cache is a §5 non-goal: the port does not implement a feature the
  reference build does not compile.)
- `lib/rnam.c`, `lib/rnch.c`, `lib/rnmh.c` — each guarded by
  `HASNCACHE && USE_LIB_RN{AM,CH,MH}`, all four commented out for Linux. Dead.
- `lib/dialects/linux/tests/ux.c` — a test program, not linked into `lsof`.

That leaves **72 in the binary the differential actually compares against**:

| Category | Live | Triage |
|---|---|---|
| `int-overflow-mul` | 42 | **0 confirmed.** 14 are `calloc(n, sizeof(T))` with compile-time constants, and C11 requires `calloc` to detect the product overflowing. The rest are `realloc(ptr, len)` — one size argument, no multiplication at the call, so not the pattern this category describes. Whether the arithmetic *upstream* can overflow is a real question the scanner did not ask and this pass did not answer; the `dsock.c` address-assembly sites (`plen + len + 2`, from `/proc/net` data) are where I would start. |
| `toctou` | 18 | **0 confirmed.** All 18 are now real `stat`/`lstat` calls on `/proc` paths — the 15 that were comments and string literals are gone with the scanner fix. A race there needs a PID recycled between the stat and the open; §4 already names it, and the consequence for a read-only reporter is a wrong or missing row, not a compromise. |
| `unbounded-copy` | 5 | **0 confirmed.** The two in `dproc.c` are bounded three lines above the call, where the scanner cannot see: `:1815` copies into a buffer `malloc`'d to `strlen(p)+1` on the preceding line; `:1919` appends a postfix into space `snp_eventpoll` reserved up front (`len -= (tfd_count == EPOLL_MAX_TFDS) ? 4 : 1`, plus the NUL). `dsock.c:1091` copies a string literal. `dmnt.c:307` and `rmnt.c:185` copy into fields sized from the source length. |
| `format-string` | 4 | **0 confirmed.** `ACCESSERRFMT` is a string-literal macro (`lib/common.h:273`). `SzOffFmt_dv` and `InodeFmt_d` are non-literal but program-constructed — built by `sv_fmt_str()` in `src/main.c` from compile-time `SZOFFTYPE` options, never from input. The `src/usage.c` hit is the scanner joining lines across an `#if`. |
| `signed-char-compare` | 3 | **1 confirmed, 1 latent, 1 false.** Detail below — this is the category that earns the scan. |

### 6c. The one category that paid for the whole scan

Three hits, three different answers, which is the argument against reporting a
count:

- **`lib/misc.c:1311`, `if (c < 0x20)` — false positive.** `safepup` declares
  `unsigned int c`. The comparison is unsigned; there is no sign bug.
- **`lib/misc.c:1369`, `if ((*sp < 0x20) || ((unsigned char)*sp == 0xff) || …)`
  — CONFIRMED, and it is the root of `hostile-comm-utf8-table`.** `safestrlen`
  takes `char *sp`, and `char` is signed on x86-64 Linux, so `*sp < 0x20` is
  **true for every byte 0x80–0xFF**. Those take the `len += 2` branch when
  `safepup` will actually render them as `\xNN`, four characters — so the width
  is under-counted by two per high byte, and the column is sized too small. The
  tell is in the same expression: the author cast for `(unsigned char)*sp ==
  0xff` and not for the `< 0x20` test beside it. Attacker-reachable through any
  `comm` or filename. Already ledgered; the scan re-found it from the source
  rather than from output, which is the stronger form of the same evidence.
- **`src/print.c:174`, `else if (val < 0x20)` — latent, and benign here.**
  `json_print_char` takes `char val`, so on x86-64 every byte 0x80–0xFF is
  "< 0x20" and takes the `printf("\\u%04x", (unsigned int)(unsigned char)val)`
  branch — which escapes it correctly. The accident produces the *safe* output.
  On a platform where `char` is unsigned (AArch64 Linux, where lsof also builds)
  the branch flips to `putchar(val)` and a raw high byte lands in the JSON
  document, which is not valid UTF-8. Not reproduced by lsof-rs and not
  reproducible by it: `render/escape.rs` and `render/json.rs` escape over UTF-8
  `char`s via `\u{:04x}`, so there is no signed-byte branch to get wrong.

### 6d. What the scan says about the scanner

The first run's noise was not spread evenly — it was concentrated in two
mechanical classes, which made it fixable rather than something to live with:

- **10 `toctou` hits were the word `stat` inside a string literal**
  (`"%s: WARNING: can't stat() "`), and **5 were inside a comment opened on a
  code line and closed on a later one** (`int *ss /* stat(2) status result…`).
  The scanner already blanked *trailing* comments — a previous pass had fixed
  that after it accounted for 20 of 47 hits — but an unterminated `/*` needs
  `*/` on the same line to match, so continuation lines were scanned as code,
  and string literals were never considered at all.

This is the same "a comment is not code" defect `control-coverage` had in this
kit until it was fixed to search `executable_text` instead of raw bytes.
`LESSONS #002` is why it matters rather than being cosmetic: a noisy Phase-0
scanner gets ignored, and skimming is how the one real hit in this run would
have been missed.

So the scanner was fixed in the same change: `_uncommented` now carries block
state across lines and blanks string and character literal *contents*, leaving
the quotes so the format-string rule — which runs separately over the raw source
and must see whether an argument starts with a quote — still works. Both
directions of that rule are pinned, along with the two new cases and the real
call that must still be caught.

**And the fix found a blind spot, not just noise.** The old heuristic skipped any
line starting with `*`, meaning to skip comment continuations. A pointer
dereference assignment starts that way too, so `*bp = (char *)realloc(*bp, sz)`
in `src/print.c:2414` and `*cbf = (char *)realloc(*cbf, len)` in
`dproc.c:195` — both real, both executable — had never been scanned. Removing the
heuristic brought them back. A filter tuned for quiet was also suppressing
signal, which is the argument for fixing noise at the parser rather than by
narrowing what gets looked at.

Net on this tree: **113 → 98** hits, 17 of them text that never executes, minus 2
recovered false negatives. Pinned by eight self-test checks so neither the noise
nor the blind spot can come back.

**Scope note.** This is a heuristic grep, and the harness says so — it does not
replace a real SAST pass (clang analyzer, CodeQL, cppcheck). Nothing here should
be read as "the C has one defect". It should be read as: the eight classes this
scanner knows about, over the Linux-built sources, produced one confirmed defect,
one platform-latent one, and a list of questions that are now written down.
