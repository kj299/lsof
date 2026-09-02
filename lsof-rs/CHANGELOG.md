# Changelog

All notable changes to **lsof-rs** (the Rust `lsof` reimplementation under
[`lsof-rs/`](.), with native Windows and Linux backends). The changelog tracks
the new Rust workspace; the legacy C `lsof` tree in the parent directory is
untouched. Entries below are left as written at the time, so older ones
describe the project while it was still Windows-only.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Linux backend phase L3 — the C-vs-Rust differential as a CI gate**
  (`differential/linux_diff.py`, `linux-matrix.toml`, `DIVERGENCES.md`). Mode 1
  of the porting kit's differential, the one Windows structurally cannot have:
  the C `lsof` built from **this tree** (4.99.6 — not apt's older package,
  which would let the harness manufacture divergences that are not the port's)
  and lsof-rs, run against the same self-owned fixture process at the same
  instant and diffed through the kit's `diff_run.py`. Two fixtures: a sleeper
  holding a regular file, a directory and a FIFO; a process holding a TCP
  listener, a UDP socket and an AF_UNIX listener. 13 cases, every one carrying
  `-a` (see Fixed/Known below for why); a hard gate on every Linux CI run from
  its first — it is not CI-only, so it was run end to end before the job was
  written: 9 MATCH, 4 DIVERGE(ledgered), 0 unexplained. Three-way exit so a
  broken harness cannot read as a port bug. The wrapper adds nothing to the
  comparison; normalization and the ledger are the kit's.
- **`DIVERGENCES.md`**, the kit's intentional-divergence ledger, which the
  retrospective found this port had reached 1.0 without. It carries the four
  ledgered cases with the phase or decision that closes each, the record of
  what the gate found, and the C-flaw scan's 127 findings marked — honestly —
  as untriaged.
- **Linux backend** (`lsof-backend-linux`), phases **L0** and **L1**.
  Dependency-free and `#![forbid(unsafe_code)]` — `/proc` is a filesystem, so
  no FFI is involved.
  - **L0** — processes and owners from `/proc/<pid>/status`, open files from
    `/proc/<pid>/fd` plus the `cwd`/`root`/`exe` links, and
    types/DEVICE/SIZE/NODE/NLINK from `stat`. Covers `-p`, `-c`, `-u`, `-t`,
    `-d`, `-a`, `-R`, bare paths and `+D`/`+d`.
  - **L1 — sockets.** `/proc/net/{tcp,tcp6,udp,udp6,raw,raw6,unix}` is read
    once per gather and indexed by inode; an fd whose link target is
    `socket:[N]` resolves by that key into a real TYPE (`IPv4`/`IPv6`/`unix`),
    protocol, addresses and TCP state. **`-i` and `-U` work**, as does `-T q`
    (the queue depths sit in the same line, so they cost nothing — but they
    stay gated on the flag, because the table renderer emits its `(QR=…)`
    suffix whenever the field is present). An inode that is not found — a
    socket in another network namespace, or a family not read — degrades to
    the L0 `SOCK` row rather than to a wrong answer.

  Verified by diffing against the real C `lsof` 4.95.0 on the same host, the
  differential Windows structurally cannot have: `-i`, `-iTCP:443`,
  `-i@127.0.0.1`, `-i4` and `-iUDP` all return identical row counts, and `-U`
  matches cell for cell.
- `FileType::Block` (`BLK`) in `lsof-core`. Unix-only; the Windows backend
  never emits it.
- **Platform-scoped coverage waivers.** `[[waive]]` entries take
  `platforms = [...]`, and `coverage_gate.py` takes `--platform NAME`; CI runs
  the gate once for `windows` and once for `linux`. A waiver that does not name
  the platform under test stops applying, so whatever it excused becomes
  required again. Waivers without `platforms` apply everywhere, so
  single-platform ports are unaffected.
- Matrix cases declaring what the Linux backend's tests cover, and a
  `type:LINK` assertion in `mode_maps_to_lsof_type_codes` — the code mapped
  `S_IFLNK` to `LINK` but no test had ever asserted it.

### Fixed
- **SIZE/OFF for character devices and FIFOs, and `-o` on Linux.** The C
  prints the offset (`0t0`) where a size means nothing; the Linux backend
  printed the size (`0`). It now withholds `st_size` for `CHR`/`BLK`/`FIFO`
  and reads the offset from `/proc/<pid>/fdinfo`'s `pos:` line — the same
  file it already opened for `flags:` — so the shared renderer falls through
  to `0t<pos>` with no platform branch in `lsof-core`, and `-o` and the `-F o`
  field become real on Linux. Found by the differential's first fixture.
- **`pipe` in NAME.** The C prints `pipe` for a pipe fd; the Linux backend
  printed the raw link target `pipe:[12047]`. The inode is already NODE. Same
  fixture, same run.
- **`-U` never filtered anything.** `Selection::unix_only` was declared and
  never read: on Windows the ETW path happened to yield only AF_UNIX rows when
  `-U` was set, so the missing predicate was invisible. Against a backend that
  returns every open file, `-U` listed the whole system. It is now a file-level
  predicate in `lsof-core`, where it belongs, and a process with no AF_UNIX
  socket is no longer a `-U` result row. This also corrects Windows.
- **The coverage gate was excusing features the port now intends to ship.**
  Most waiver reasons were platform-specific ("Unix-only", "no Windows
  equivalent") and expired silently when the Linux backend merged: nothing in
  the file changed, so the gate stayed green while waiving `-Z` (SELinux), `-X`
  (epoll bridge), the mount-table options, and every Unix socket family — on a
  port that now targets Linux. Two were not merely expired but wrong that day:
  `type:BLK` and `type:FIFO` were waived as having no Windows analogue while
  the Linux backend was already emitting both; they are now **covered**, not
  waived. The Linux-side features whose waiver expired are recorded as
  `DEBT (L2)` naming the phase that closes them, rather than re-waived — a
  waiver claims "we will never do this", which is untrue of `-Z`.

### Known, recorded rather than changed
- **Six more divergences from the C, found by the L3 differential the day it
  landed** and recorded in `DIVERGENCES.md` for decision — each changes shared
  output, so none was fixed in a backend phase. The largest: **lsof ORs its
  list options unless `-a`** (Lsof.8: "list options that are specifically
  stated are ORed"), and lsof-rs does so for the process selectors but applies
  file-level selectors (`-i`, `-d`, `-U`, paths) unconditionally — so
  `lsof -d ^mem -p PID` lists the whole host in the C and one process here.
  Also: the `-F` default field set (`g u G l D` and empty `a`/`l`, which
  lsof-rs omits; `d` where the C emits `D`), `-o`'s `OFFSET` header and blank
  cells, the `W` write-lock marker on FD, `a_inode` typing, and a directory fd
  the C shows as `u` where fdinfo says read-only — that last one an open
  question about the C, not yet a verdict. Every matrix case carries `-a` so
  the gate measures what it names; one case deliberately does not, so the
  OR divergence stays visible in every run.
- Three renderer divergences from the C, found by the L1 differential and
  written up in [`docs/known-limitations.md`](docs/known-limitations.md). Each
  alters output the Windows golden fixtures and 59-case smoke suite assert, so
  matching the C is a compatibility decision rather than a fix to slip into a
  backend phase: the `-T` suffix shape (`(QR=0) (QS=0)` vs the C's
  `(QR=0 QS=0)`), `-Tq` appending to the state rather than replacing it, and
  `COMMAND` not being truncated to the C's default width of 9. All three have
  applied to the **Windows** output since v0.2.0 and were invisible there for
  want of a reference implementation on the same host.

### Changed
- **miri is a hard gate.** Landed observe-first in the retrospective PR after
  the playbook's sanitizer gate was found never to have been wired for this
  port; promoted in its own PR on the kit's rule — consecutive log-verified
  green runs (two, 54 tests each, zero UB findings), with the promotion PR
  itself the third. Scope is the `forbid(unsafe_code)` crates: `lsof-core` and
  `lsof-cli`. The Windows backend needs Windows and the Linux backend reads
  live `/proc`, so those two rows stay open in `progress.json`. The nightly is
  **pinned** (`nightly-2026-08-31`, the build that produced the green runs): a
  hard gate must fail only for the code's reasons, so a newer miri is a
  deliberate bump rather than a surprise red on someone else's PR.
- **Docs no longer describe the project as Windows-only**, which stopped being
  true when the Linux backend landed. The README now leads with both backends
  and their status, and the privilege section covers Linux's uid-based split
  alongside Windows' `SeDebugPrivilege` model.
- **Renamed `winlsof` → `lsof-rs`.** The old name dated from when this was
  Windows-only and stopped being true when the Linux backend landed; the rename
  waited for L1, so it happened once rather than piecemeal. The workspace
  directory, the three workflow files, the coverage inventory and every prose
  mention moved. Three things deliberately did **not**:
  - **Published tags.** Releases v0.1.0 – v1.0.1 are tagged `winlsof-v*` and
    stay so; the CHANGELOG's comparison links still point at them, because
    rewriting them would name tags that never existed. The release workflow
    triggers on **both** prefixes, so the old series still builds.
  - **`WINLSOF_TRACE`.** Still honored as an alias for the new
    `LSOF_RS_TRACE`. It is documented in shipped releases, and a silent rename
    would turn tracing off exactly when someone reaches for it.
  - **Crate names and the binary.** Already platform-neutral (`lsof-core`,
    `lsof-cli`, `lsof-backend-{windows,linux}`), and the binary was always
    `lsof`.
- Corrected a stale README claim that cited **v0.2.0** as the latest field
  validation; it is v1.0.1 (51 unelevated / 57 elevated, 0 FAIL).

## [1.0.1] — 2026-08-30

**Found by the 1.0 field checkpoint.** The per-release two-pass validation on
real hardware failed for v1.0.0, and root-causing it surfaced a defect that had
been present since Phase 4.

Validated in turn: 1.0.1 passes both modes on Windows 11 — 51 PASS / 0 FAIL /
8 SKIP unelevated, 57 PASS / 0 FAIL / 2 SKIP elevated — with `lsof +D %TEMP%`
elevated going from **214 s to 8.7 s**.

### Fixed
- **Elevated runs no longer stall for minutes.** The per-process extras phase
  (`cwd`, `txt`/`mem` modules, mapped files) waited on each process **in turn**
  with a 2-second timeout apiece, so its worst case was `2 s × process count` —
  unbounded in aggregate. Unelevated this is invisible, because `OpenProcess`
  on a foreign process fails instantly; *elevated*, `SeDebugPrivilege` makes
  every read genuinely succeed and some of them slow. A measured `lsof +D
  %TEMP%` on a normal Windows 11 desktop took **214 seconds** — against a
  `%TEMP%` holding only 431 entries, so the cost was entirely this loop and not
  the directory.

  The phase now runs every process concurrently (as it always did per-process,
  just serially awaited) under a **single 5-second budget** for the whole phase
  — sized against the 2-second per-process bound it replaces, since concurrent
  workers no longer queue behind each other. Wedged workers are still abandoned
  exactly as before, and a pathological box degrades to "some extras missing"
  (reported under `WINLSOF_TRACE`) rather than stalling. Hosted CI never caught
  this because runners have a small, idle process set; only the real-hardware
  checkpoint could.

## [1.0.0] — 2026-08-30

**Stable.** 1.0 is a **stability commitment, not a feature milestone**: the CLI
option surface (every switch in `lsof -h`) and the machine formats (`-F` field
codes, `-J`/`-j` JSON shapes) are now stable, and a breaking change to either
requires a major bump. Releases are no longer marked prerelease.

Nothing in the tool changed from v0.4.0 beyond the `-T` link-local fix below —
this release is the *declaration* that the surface is settled. Every option in
the C's 47-switch inventory is dispositioned (37 implemented, 18 Unix-only and
explicitly rejected), the coverage gate reports `UNCOVERED: 0`, and the
research roadmap has no open items. The two capabilities lsof-rs will never
have on Windows — a socket's FD value and the byte-range lock column — are
documented closed gates requiring a kernel driver, not outstanding work.

### Added
- **[`docs/linux-backend-scope.md`](docs/linux-backend-scope.md)** — a scoping
  study (proposal, not a commitment) for a second backend behind the existing
  `Backend` seam: measured against the C's own Linux dialect in this repo
  (10,205 lines, half of it sockets), it estimates ~2,200 Rust lines plus one
  small core addition (a lock-state field). The strategic point: on Linux the C
  `lsof` *runs*, so a real C-vs-Rust differential replaces the
  oracle-substitution workaround Windows forces — and two closed Windows gates
  (socket-FD correlation, byte-range locks) become ordinary features.
  Recommended sequencing is after 1.0.

### Changed
- **Releases drop `--prerelease`**, and the release notes no longer describe
  the binary as one. The unsigned-by-design rationale is stated inline instead.
- **1.0 exit criterion 4 (fuzzing) is measured, not timed.** It previously
  required "14 consecutive green nightly runs" — a calendar bar that used
  elapsed days as a proxy for fuzzing effort. It now requires demonstrated
  saturation: cumulative effort, an accumulating corpus whose growth has
  flattened, plateaued coverage, and zero findings. Met on the evidence of 9
  deep-fuzz runs (~4.5 h, 200M+ executions, corpus 338 KB → 6.03 MB with +6%
  on the final night, coverage steady at `cov: 1125 / ft: 6790`, zero
  findings). The nightly job continues — as regression detection, which was
  always its real purpose, rather than as a release gate.
- **Code signing reframed as optional — not a 1.0 blocker.** lsof-rs ships
  unsigned `lsof.exe` + a published SHA-256 as a deliberate, privacy-conscious
  default: any publicly-trusted signing certificate requires identity
  validation that puts the maintainer's legal name and city/state/country
  permanently on every binary (a CA/Browser Forum requirement), and signing
  buys only reduced download friction — never integrity, which the SHA-256
  already provides. `docs/road-to-1.0.md` criterion 3 is now optional and 1.0
  no longer waits on it; the release workflow stays wired to sign automatically
  if the `AZSIGN_*` secrets are ever added.

### Fixed
- **`-T` now annotates link-local (`fe80::`) IPv6 connections.** IPv6 socket
  rows were built with `SocketAddr::new`, which forces the scope id to 0, so a
  link-local connection never matched its `GetPerTcp6ConnectionEStats` row key
  and its `-T` window/queue was silently dropped. Sockets now carry the scope
  id IP Helper already reports (`dw*ScopeId`). Global and loopback IPv6 use
  scope 0, so their behavior — and the numeric NAME, which never showed the
  scope — is unchanged.

## [0.4.0] — 2026-08-23

**The runway release.** Every open engineering item from the v0.3.0
retrospective and the post-release survey is closed: the machine formats carry
the last table-only data (`-T` stats), the `-i` grammar reaches the last
socket families (ETW-sourced ICMP/RAW — the research roadmap now has zero
open items), the elevation blind spot is dispositioned with the untestable
residue documented as a per-release checkpoint, the nightly deep-fuzz soak
that gates 1.0 is running with an accumulating corpus, and
[`docs/road-to-1.0.md`](docs/road-to-1.0.md) turns "prerelease" into a
six-item exit checklist. What remains for 1.0 is runway, not construction:
signed releases, the 14-night soak, and release-candidate field validation.

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
- **Nightly deep fuzz with an accumulating corpus**
  (`.github/workflows/lsof-rs-fuzz-nightly.yml`): a scheduled 30-minute
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

### Changed
- **`-T` annotations no longer pollute machine-format names.** The
  `(Win=N) (QR=N) (QS=N)` decoration used to be appended to the row's NAME
  string at capture time, so `-T` combined with `-F`/`-J` leaked it into the
  `n` field / JSON `"name"`. The stats now travel as structured data; the
  table renders the identical suffix at display time (table output is
  byte-for-byte unchanged — the live smoke assertions still pass), and the
  machine formats keep a clean name plus the structured tokens above.

### Fixed
- **Docs truth pass.** `feature-parity-plan.md` still marked all twelve
  Phase 5A switches 🟡-planned though they shipped in v0.2.0 (now recorded as
  the option inventory + mapping decisions); `windows-validation.md` still
  instructed using Sysinternals `handle64.exe` as the file-handle oracle,
  contradicting the v0.3.0 supply-chain decision that removed downloaded
  oracles from the test path (now native fixtures/`Get-Process` only, and
  version-agnostic); the research-roadmap intro and README pointers now
  reflect that every roadmap item is shipped or a documented closed gate.

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
- **Socket oracle-substitution differential** (`lsof-rs/differential/`):
  lsof-rs's `-i` socket *set* is diffed against the OS's own table
  (`Get-NetTCPConnection`/`Get-NetUDPEndpoint`) over self-owned fixtures on
  every CI run — landed observe-first, now a hard gate, with a ledger for the
  one documented data-source divergence (transient BOUND sockets).
- **Feature-coverage gate in CI.** A curated inventory of the C's enumerated
  surface (45 option letters, 111 TYPE codes, extracted from lsof's own
  source) plus lsof-rs's Windows-native types is diffed against what the test
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
  `i` field empty for sockets (the protocol is reported via `P`); lsof-rs now
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

- **Cargo workspace** (`lsof-rs/`) split along lsof's `core + dialect` boundary:
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
- **CI** (`.github/workflows/lsof-rs-ci.yml`): `cargo fmt --check`, `cargo
  clippy -D warnings`, and tests on Linux; build + tests + release-profile
  artifact build on `windows-latest`. The Windows job runs `cargo test
  --all`, which includes `cfg(windows)` runtime integration tests that
  execute the real `lsof.exe`.
- **Live smoke-test harness** (`lsof-rs/smoketest/`): 37-case PowerShell
  harness that stands up deterministic fixtures (held file at a known
  offset, named pipe, mapped data file, TCP v4/v6 listeners +
  ESTABLISHED pair, UDP v4/v6, child cmd.exe with a known cwd in 64-bit
  and 32-bit WOW64), exercises every option / format / branch with a hard
  per-invocation timeout, auto-fetches Sysinternals `handle64.exe` for a
  differential oracle cross-check, and writes `results.csv` /
  `summary.txt` / per-case logs. Run against any prebuilt binary via
  `-Binary <path>`. A standalone `Test-Lsof.ps1` provides a quick
  ~10-case sanity check with no repo/build dependency.
- **Release pipeline** (`.github/workflows/lsof-rs-release.yml`): tag a
  `lsof-rs-v*` (or trigger manually) and the workflow builds a native
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

[Unreleased]: https://github.com/kj299/lsof/compare/winlsof-v1.0.1...HEAD
[1.0.1]: https://github.com/kj299/lsof/compare/winlsof-v1.0.0...winlsof-v1.0.1
[1.0.0]: https://github.com/kj299/lsof/compare/winlsof-v0.4.0...winlsof-v1.0.0
[0.4.0]: https://github.com/kj299/lsof/compare/winlsof-v0.3.0...winlsof-v0.4.0
[0.3.0]: https://github.com/kj299/lsof/compare/winlsof-v0.2.0...winlsof-v0.3.0
[0.2.0]: https://github.com/kj299/lsof/compare/winlsof-v0.1.0...winlsof-v0.2.0
[0.1.0]: https://github.com/kj299/lsof/releases/tag/winlsof-v0.1.0
