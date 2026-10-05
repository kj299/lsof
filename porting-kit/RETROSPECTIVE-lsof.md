# Retrospective — the lsof-rs port (C `lsof` → Rust, Windows)

A forensic account of how this project actually unfolded, reconstructed from the
repository, the git history (59 non-merge commits, 2026-06-14 → 2026-07-02, no
reverts), and the shipped docs. It is the evidence base for the Porting Kit.

**Evidence key.** Plain statements are grounded in an artifact (commit, file,
test). `[INFERRED]` marks a reading of the artifacts I could not fully confirm
from them alone — every `[INFERRED]` is also a numbered question at the bottom.

---

## 0. Scope reality (read this first — it reframes everything)

The kickoff prompt described "a rewrite of `lsof` targeting Linux, Unix variants,
and Windows." **The shipped artifact is narrower, and the difference is the
single most important planning lesson here.**

| Dimension | Premise | What actually shipped |
|---|---|---|
| Platforms | Linux + BSD + Solaris + Windows | **Windows only.** Non-Windows builds link a `MockBackend` that returns sample data. |
| Relationship to C | "rewrite" | **Reimplementation, not a translation.** Zero lines of C are shared, linked, or transpiled. The C tree (~89.5 KLOC) is an *executable specification*, never a dependency. |
| Data sources | port `/proc`, kvm, sysctl | replaced wholesale with Win32/NT APIs (Toolhelp, IP Helper, NT handle table, PEB, ETW). None of the C dialect code was portable — the acquisition layer is 100% new. |
| Size | 89.5 KLOC C | ~6.5 KLOC Rust (core 1.8k / windows backend 3.6k / cli 1.0k) + 0.8k PowerShell smoke harness. |

The `Backend` trait was deliberately built as a **seam for future dialects**
(mirroring lsof's own `core + lib/dialects/<os>` split), and `lsof-backend-linux`
was named in the plan — but it was **never created**; the workspace has three
crates, not four. So this is a *single-dialect reimplementation behind a
multi-dialect-ready seam*, validated on one OS.

**Lesson for the kit:** separate "reimplement behavior behind a portable core"
(what happened, and worked) from "translate C to Rust" (what the word *port*
implies, and did not happen). When the data-acquisition layer is entirely
OS-specific, transpilation (c2rust) buys nothing; the C is worth more as an
oracle than as source. The kit must ask, up front, *which* of these two projects
the user is actually running — they need different playbooks.

---

## 1. Port order and dependency strategy

Order was **capability-phased, dependency-aware within each phase** — not
leaf-first over the C call graph, and not ad hoc. The phases are legible in the
commit stream:

- **Phase 0** — scaffold: workspace, `Backend` trait, RAII `OwnedHandle`, error
  type, least-privilege plumbing, CI. `-v`/`-h` work. (`13a3415`)
- **Phase 1** — processes (PID/COMMAND/PPID/USER). The root of the data model:
  everything else hangs off a process.
- **Phase 2** — sockets (`-i`, TCP/UDP via IP Helper). Chosen next because it
  delivers standalone value (`netstat`-with-process) and needs no elevation.
- **Phase 3** — file handles (the core lsof behavior; the hard one).
- **Phase 4** — parity polish: mapped modules, cwd/PEB, Restart Manager, `-r`.
- **Phase 5** — full option parity (5A: 12 switches; 5B: `-T`/`-U`/`-E`).

The ordering principle was **"shippable user-visible value, cheapest-and-safest
first, dependency roots before dependents."** Processes before the files they own
(hard dependency); sockets before handles (sockets are easy and unprivileged,
handles are the hang-prone deep end). Handle enumeration — the riskiest module —
was deliberately deferred to Phase 3, after two easier phases had established the
model, the CI loop, and the smoke harness.

**In hindsight, would I change it?** The order was sound. The one thing worth
front-loading: the *hang* that dominated Phase 3 (see §6) is inherent to Windows
handle-naming and was foreseeable. A one-day spike on `NtQueryObject` behavior
*before* Phase 3 (instead of discovering the hang mid-implementation across seven
commits) would have paid for itself. **Generalized: spike the known-scary module
before you schedule it, not during.**

---

## 2. Interop / coexistence strategy

**There was none, by design — and that was correct here.** No FFI to the C code,
no `bindgen`/`cbindgen`, no linking Rust into the C build or vice versa, no
transpilation. The two trees coexist in one repo, untouched (`lsof-rs/` beside
the original), and share nothing but behavior.

Why this worked: the entire value of lsof on Windows is in the *acquisition*
layer, which had to be rewritten anyway (no `/proc`). Keeping the C as a
read-only spec meant zero FFI-boundary bugs, zero build-system entanglement, and
the C tree kept building on its own platforms the whole time.

**The friction this avoided** (visible by its absence in the history — there is
not one commit about FFI struct layout, ABI mismatch, or a C/Rust link failure)
is exactly the friction a coexistence port pays continuously.

**Lesson for the kit:** a "strangler-fig" FFI coexistence is the *default advice*
for porting a library whose internals you must preserve — but it is the wrong
default for a tool whose OS integration layer is being replaced. The kit's
inventory phase must classify the codebase: **library-with-portable-internals**
(coexist via FFI, port leaf-first) vs **tool-with-OS-specific-acquisition**
(reimplement behind a trait, use C as oracle only). `[INFERRED-1]` that the
coexistence path was consciously rejected rather than never considered.

---

## 3. Platform abstraction

The seam is a single trait in the pure-logic crate:

```
lsof-core (no_std-spirit, #![forbid(unsafe_code)])
  ├─ Backend trait:  fn gather(&self, sel: &Selection) -> Result<Vec<Process>>
  ├─ model (Process, OpenFile, FileType, Protocol, …)
  ├─ selection (the -p/-i/-u/-s/... filter engine)
  ├─ render (table / -F fields / JSON)
  └─ mock::MockBackend  (sample data; keeps core testable off-Windows)

lsof-backend-windows  (all #[cfg(windows)]; empty shell elsewhere)
  └─ 14 modules, each one Win32/NT subsystem: process, sockets, handles,
     peb, modules, mapped, restart, tcpinfo, threads, etw, privilege, resolve, util

lsof-cli  →  lsof.exe   (arg parse → Selection → Backend → render)
```

Decisions that held up:

- **The trait lives in `core`, not in a shared FFI crate.** The dialect fills
  `Process`/`OpenFile` structs; the core owns selection and rendering. This is
  lsof's own `struct lproc`/`lfile` boundary, preserved intentionally.
- **`#[cfg(windows)]` at the crate boundary, `MockBackend` fallback.** The whole
  backend compiles to an empty shell off-Windows, so `lsof-core` (and its 26
  unit/golden tests) run on the Linux CI runner. This kept the pure logic under
  test on every push regardless of platform. High-value, low-cost.
- **`#![forbid(unsafe_code)]` on `core`.** Made the unsafe/safe split
  structural, not aspirational (see §4).

What leaked / caused rework:

- **Rendering assumptions vs. the terminal.** The core renderer emitted UTF-8
  (em-dashes, arrows). That leaked all the way to the Windows console encoding
  and caused a 6-commit fidelity saga (§6). The abstraction "core renders text"
  was fine; the missing piece was "the *sink* has an encoding" — an OS concern
  that had leaked *out of* the platform layer into core's string choices.
- **`Process`/`OpenFile` grew fields as switches landed** (`links`, `endpoint_peer`,
  `SocketInfo` sprouting `tcp_info`). Every new struct field touched every
  `Process { … }` literal across mock, tests, and two backend modules — a small
  but repeated tax (visible in `2d94cf8`/`3cb4f3c` touching 6-14 files for a
  one-field change). `[INFERRED-2]` that a `#[non_exhaustive]` + builder pattern
  was considered and rejected for the model structs.

---

## 4. Unsafe surface

Cleanly quarantined, by construction:

| Crate | `unsafe` occurrences | `// SAFETY:` comments |
|---|---|---|
| `lsof-core` | **0** (compiler-enforced via `forbid`) | — |
| `lsof-backend-windows` | 144 | 91 |

All unsafe is in the backend, concentrated where the OS surface is widest:
`etw.rs` (43), `handles.rs` (24), `process.rs` (14), `sockets.rs` (12), `peb.rs`
(8). The nature of it matters: **almost all of it is FFI-call unsafe** (calling
`windows-sys` raw bindings), not algorithmic pointer math. The genuinely
dangerous idioms were localized:

- **`repr(C)` structs cast from raw buffers** — the NT handle table
  (`SystemHandleInformationEx` + trailing array) in `handles.rs`, and TDH event
  schemas in `etw.rs`. These are the flexible-array-member / union C idioms, and
  they are exactly where the pointer-cast `unsafe` lives.
- **The "call-twice for buffer size" idiom** (`NtQuerySystemInformation`,
  `GetExtended*Table`) — a memory-bug magnet in C, handled with a growing
  `Vec<u64>` and length checks. Safe in Rust by construction.
- **RAII wrappers** (`OwnedHandle`, `PrivilegeGuard`) turn the two
  most-leak-prone C patterns (handle close, privilege drop) into `Drop` impls —
  killing the use-after-free / leak / privilege-held-too-long classes outright.

Gap: 144 unsafe blocks but only 91 SAFETY comments — **~53 unsafe blocks lack a
documented invariant** `[INFERRED-3]` (some of the 144 hits are the word in
comments/strings, so the true block count is lower; the ratio still says coverage
is incomplete). This is precisely the thing the kit's unsafe-audit harness should
have caught continuously. The count-mismatch is the single clearest "we would
have benefited from a harness" signal in the whole repo.

**Lesson:** `forbid(unsafe_code)` on the portable crate is the highest-leverage
single line in the project. It made "is the unsafe contained?" a compile-time
fact, not a review question.

---

## 5. Behavioral fidelity — how "does it behave like lsof" was verified

Two-tier, because the obvious oracle was unavailable:

1. **The C `lsof` binary cannot be the oracle** — it doesn't run on Windows.
   So fidelity to *lsof semantics* was verified structurally (option letters,
   column layout, `-F` field codes, JSON shape ported from `src/print.c` /
   `lsof_fields.h`) and locked with **13 golden tests** in `lsof-core/tests/`
   over the deterministic `MockBackend` — table / `-F` / JSON snapshots.
2. **Correctness of the *data* was verified against native Windows oracles**, not
   against C lsof: `Get-Process`, `Get-NetTCPConnection`, `netstat -ano`, and
   Sysinternals `handle64.exe` (auto-fetched by the harness, `0bb76f0`). The
   **55-case live smoke harness** (`Invoke-LsofRsSmokeTest.ps1`) stands up
   deterministic fixtures (a held file at a known offset, a named pipe with a
   connected client, a mapped data file, TCP v4/v6 listener+established pairs,
   UDP, child processes with known cwd in 64- and 32-bit) and asserts lsof-rs
   reports them, cross-checking `handle64.exe` where it can.

Where behavior silently diverged, and how it was caught:

- **`-F` emitted a bare `n` field for empty names** (thread rows). Caught by
  eyeballing output, not by a test; fixed in `aa3a7b9` *and then* pinned with a
  golden test (`fields_skips_empty_name`). The lag between "shipped" and "pinned"
  is the lesson.
- **EStats on non-ESTABLISHED sockets** returned `ERROR_NOT_SUPPORTED` and
  produced wrong/empty annotations; caught on hardware, fixed with an
  ESTABLISHED-only guard (`eed9abe`).
- **Empty-result runs printed a bare header** (`3a56937`) — a fidelity miss vs
  lsof's silence, caught by the smoke harness's exit-code/So output capture.

**Lesson:** when the reference binary won't run on the target platform, you lose
byte-for-byte differential testing and must substitute (a) structural golden
tests for the *format* and (b) native oracles for the *data*. The kit's
differential harness must therefore support two modes: **same-binary-both-platforms
diff** (the easy case) and **oracle-substitution** (the lsof case). Several
fidelity misses reached "shipped" before a test pinned them — the loop of
*fix → then immediately add the golden test that would have caught it* was
practiced but not enforced.

---

## 6. Failure inventory — the core value

No `git revert` was ever used. **Every failure is fix-forward**, so the signal is
in *commit sequences* where the message says "the real fix" or "actually." Three
sagas dominate.

### 6.1 The handle-enumeration hang (7 commits, ~2 weeks of recurring pain)

The marquee failure. Enumerating file handles means naming them, and
`NtQueryObject(ObjectNameInformation)` **blocks forever** on synchronous handles
(pipes, some devices) — a well-known Windows trap. The fix evolved through five
distinct approaches, each addressing the previous one's shortfall:

| # | Commit | Approach | Why it wasn't enough |
|---|---|---|---|
| 1 | `f92d3bc` | Add a timeout around the name query | The worker thread still blocked; timeout freed the *caller* but leaked stuck threads |
| 2 | `493bbb0` | Bound the **whole per-handle classify** on a worker thread | Better, but exit still hung on the abandoned worker |
| 3 | `5b6d8fd` | **Hard-terminate the process** after output so a stuck worker can't hang teardown | Treats the symptom at exit; enumeration still paid the stall |
| 4 | `91e453d` | Add `LSOF_RS_TRACE` phase tracing **to find where** it hung | Diagnostic, not a fix — but the pivot point |
| 5 | `25d9a1c` | **Classify handles by NT type-index** (learned from a NUL probe) so the hang-prone query is *never issued* for the wrong types | The real fix — avoids the dangerous call by construction |

Then a **second, separate hang** surfaced in socket reverse-DNS (`5f8c47b`) and
per-process PEB/module gather (`a92fe01`), each fixed by the same
bound-on-a-worker + scope-to-selected pattern. The pattern that finally won:
**"never make the blocking call on your only thread; better yet, structure the
work so you never make it at all."**

**Kit implications:** (a) a "known-hazardous syscalls" checklist per OS would have
front-run this; (b) the winning move — a pre-flight probe (open NUL, learn the
type index) to *avoid* the dangerous call — is a reusable pattern; (c) tracing
was added *reactively* at step 4; it should be scaffolded from day one so the
first hang is diagnosable in minutes, not after three partial fixes.

### 6.2 The PowerShell 5.1 / Windows-1252 fidelity saga (6 commits)

The *test harness's* host environment fought back. PS 5.1's console is
Windows-1252 and its parser is byte-oriented, so: the `.ps1` itself had to be
ASCII-only to parse (`24d0284`); a fixture used `[byte[]](1..4096)` which
overflows a byte (`4a5a7b8`); native stdout with an em-dash rendered as `â€"`
(`9eaf7f1`, `6bf3e26`); and the final resolution was to **default output to ASCII
and add `--unicode`/`--ascii`** (`b99736e`). Plus exit-code capture across the
native-command boundary (`3a56937`).

**Kit implication:** the test *harness* is software too, and its host has an
encoding/quoting model that will bite. Budget for "harness hardening" as a named
work item, not a rounding error. Default the tool's output to the lowest-common-
denominator encoding of the target platform's *default* shell.

### 6.3 The spike-gated research dead-ends (disciplined, not painful)

Four hard capabilities (socket-FD correlation, byte-range locks, AF_UNIX/raw,
real-FD-via-ETW) were each run as **spike → decision gate → {ship | document the
wall}** rather than open-ended attempts. Two shipped (offset, mapped-data `mem`);
two closed as *documented platform limits* (locks and socket-FD need a kernel
driver); one **pivoted** (ETW couldn't get the real FD — driver-only — but *could*
extend `-i` to raw/ICMP/AF_UNIX, which became the actual `--etw`/`-U` feature).

This is the **anti-time-sink**: `research-roadmap.md` shows effort/confidence
ratings and explicit gates that *prevented* sinking L-effort into driver
territory. The one that pivoted rather than died (ETW) is the template — a closed
sub-goal didn't kill the adjacent shippable one.

**Kit implication:** codify the spike-and-gate ritual as a first-class artifact.
Every "research-grade" item gets an effort/confidence rating and a written
decision gate *before* code, and a pivot check ("is there an adjacent reachable
goal?") *before* declaring it dead.

### 6.4 Smaller, still-instructive

- **Toolchain**: cross-compiled to `x86_64-pc-windows-gnu` (user had no MSVC
  linker); harness had to *detect* a missing MSVC linker and hint switching back
  to GNU (`194d246`). Toolchain assumptions are a portability tax.
- **OneDrive file-lock** on `target\` (`845bd66`): the dev environment (synced
  folder) locked build output; harness learned to detect it and suggest
  `-SkipBuild`. Environment, not code.

---

## 7. Top 5 time sinks (ranked by churn + commit clustering)

Churn = commits × lines touched on a file/area; corroborated by the saga
clustering above. `[INFERRED-4]` on the exact ranking of 3 vs 4 — both were
steady CLI-growth taxes and I'm ordering by commit count.

1. **The hang class** — `backend.rs` (19 commits) + `handles.rs` (14 commits,
   1186 lines). Five approaches to §6.1 plus the two follow-on hangs. **The
   single biggest sink**, and the most preventable with an up-front syscall-hazard
   spike.
2. **The live smoke harness** — `Invoke-LsofRsSmokeTest.ps1` (16 commits, 706
   lines). The §6.2 encoding saga plus continuous fixture growth. High value
   (it caught real bugs) but under-budgeted.
3. **CLI surface** — `main.rs` (18 commits) + `args.rs` (13 commits). Each new
   switch touched the parser, help text, and dispatch — death by a thousand
   small edits as parity grew from MVP to 40+ options.
4. **The selection/filter engine** — `selection.rs` (12 commits). Grew a new
   predicate per switch (`-s` state, `+L` links, `-U` unix, `+E` endpoint peer);
   several touched every `Process` literal (the §3 struct-growth tax).
5. **The ETW subsystem** — `etw.rs` (7 commits, 825 lines, 43 unsafe blocks). The
   spike→4-iteration implement arc — the most unsafe-dense, TDH-schema-parsing-
   heavy module in the tree.

---

## 8. What to carry into the kit (executive summary)

The reusable, evidence-backed lessons:

1. **Classify the port first**: reimplement-behind-a-seam vs translate-via-FFI.
   They need different playbooks; picking wrong is the costliest mistake.
2. **Establish the oracle before writing Rust** — and when the reference binary
   won't run on the target, substitute structural golden tests (format) +
   native tools (data).
3. **`forbid(unsafe_code)` on the portable core** — makes containment structural.
4. **Spike the known-scary module before scheduling it** (the hang would have
   cost 1 day up-front vs. 7 commits reactively).
5. **Scaffold tracing and the unsafe-audit gate on day one** — both were added
   reactively; both would have paid immediately (the 144-vs-91 unsafe/SAFETY gap;
   the trace added at hang-fix step 4 of 5).
6. **The test harness is software with a hostile host** — budget encoding/quoting
   hardening explicitly; default output to the platform default shell's encoding.
7. **Spike-and-gate every research-grade item** with effort/confidence + a written
   gate + a pivot check — the discipline that made the *hard* gaps the *cheap*
   ones.
8. **Fix-forward, then immediately pin the regression test** — practiced but not
   enforced; several fidelity misses shipped before their test existed.


### Questions behind the `[INFERRED]` marks

Promised at the top and never written until 2026-10-04, when a retrospective
found the list missing.

1. **`[INFERRED-1]`** Was FFI coexistence with the C considered and rejected,
   or never considered? *Open: only the author can say.*
2. **`[INFERRED-2]`** Was `#[non_exhaustive]` with a builder considered for the
   model structs, and rejected? *Open.*
3. **`[INFERRED-3]`** How many `unsafe` blocks lacked a `// SAFETY:` comment?
   *Answered by LESSONS #1: 131 real blocks, 51 undocumented; the 144 and 91
   above are grep hits. On 2026-10-04 the audit counts 139 blocks, all
   documented.*
4. **`[INFERRED-4]`** Is time sink 3 or 4 the larger? *Open, and it changes
   nothing above.*
---

## 9. Addendum — scope direction from the author (2026-07-05)

After the retrospective was drafted, the author redirected the *kit's* focus (not
this historical record) on PR #5:

> "Ignore the need to reconstitute code on another operating system. Focus the
> harnesses for this porting mission to best practices in rewriting from C to
> Rust. Recognize that the existing operating system running code may have other
> flaws. Do as much as possible to add controls to adhere to safety and
> security."

Consequences for the Porting Kit (this doc stays as-is; the playbook/harnesses
adopt the new emphasis):

- **Cross-OS reconstitution is de-emphasized.** §0's "reimplement-behind-a-seam
  vs translate-via-FFI" classification and §3's platform-abstraction lessons
  remain *true history*, but the kit does not center OS portability. The seam is
  kept only as an isolation boundary for unsafe/FFI, not as a multi-OS mechanism.
- **The C source is not ground truth.** "Existing code may have other flaws"
  elevates a new first-class step: **scan the C for vulnerability classes before
  porting** (so a CVE isn't faithfully re-implemented), and treat every
  oracle divergence as a triage question — *bug in Rust* vs *intentional fix of a
  C defect* — recorded in an **intentional-divergence ledger**, not silently
  matched.
- **Safety/security controls are maximized.** The kit's harnesses and CI center
  on: `forbid(unsafe_code)` on pure crates, a **hard-fail** unsafe-audit gate
  (every `unsafe` needs a `// SAFETY:`), Miri, ASan/UBSan/TSan over the FFI
  surface, `cargo-fuzz`, and supply-chain gates (`cargo-deny` / `cargo-audit`).
  This resolves the §4 "144-vs-91" gap by construction: the gate fails CI rather
  than accruing undocumented `unsafe`.

The rest of this document is unchanged: it is the evidence, and the evidence is
what the kit is built to not repeat.

---

## 10. Addendum — the hardening arc (2026-07-24): the kit applied back to lsof-rs

§1–§8 are the *forensic* record of the original port; §9 redirected the kit. This
addendum records what happened when the hardened kit was turned back on lsof-rs
itself across three merged PRs — the compounding loop closing on its origin
project. Detail lives in LESSONS #6–#10; the arc:

- **The safety gates went from prose to CI (PR #30).** The `unsafe-audit` hard
  gate, `cargo-deny`, `[workspace.lints]` (incl. `undocumented_unsafe_blocks`),
  and a `cargo-fuzz` arg-parser target were wired into CI. The audit paid the §4
  "144-vs-91" debt down to **0 undocumented** — and wiring the clippy half exposed
  a real bug the audit alone had blessed: the two gates disagreed on SAFETY-comment
  placement (LESSONS #7). Three genuine FFI soundness bugs (an OOB read in
  `sockets.rs`, an off-by-one in `etw.rs`, a wrong length in `handles.rs`) were
  found and fixed *while documenting the blocks* (`cf230fe`) — evidence that
  writing the SAFETY comment is itself a review pass, not paperwork.
- **The oracle-substitution differential was built and promoted (PR #29).** The
  mode §5 said the kit "must support" now exists: lsof-rs's socket SET diffed
  against `Get-NetTCPConnection` / `Get-NetUDPEndpoint` over self-owned fixtures,
  observe-first then hard-gated. It taught LESSONS #6 (the native oracle lies in
  new ways) and, by omission, #8 (a green diff over a socket-only matrix hid that
  every non-File object type was dropped).
- **The depth gaps were closed (PR #31).** A gap analysis against the C
  established the option surface was complete (47/47) but the *depth* was not:
  all-handle object classification (the biggest gap), the `(deleted)` marker, and
  `-F`/JSON scripting fidelity. All three shipped behind the now-green gates.
- **The test harness was de-weaponized.** The `handle64.exe` auto-download (§5,
  praised there as convenient) was removed as a supply-chain hole in the *test*
  path (LESSONS #10) — native commands only.

**The single failure the kit still would not have prevented** (the next target):
the depth gap (#8) was invisible until a *human-directed* analysis enumerated the
C's feature surface and asked "what does lsof emit that no fixture creates?" The
differential, the golden tests, and the option-parity count were all green while
whole object classes were dropped. The kit can now *hold* that enumeration (the
matrix-completeness note) but cannot yet *generate* it — a future harness that
diffs the C's emitted-TYPE / option enumeration against the matrix's coverage
would turn #8 from a discipline into a gate. Until then, "green on the matrix"
remains a statement about the matrix, not the port.

*Closed 2026-07-24 (same day):* that harness now exists —
`harnesses/coverage/coverage_gate.py` bootstraps the inventory from the C
itself (validated on the real tree: the 45-letter union optstring across all
`#if` branches of `src/main.c`, and all 111 TYPE literals `lib/print.c` can
emit → `feature-inventory-lsof.toml`), infers option coverage from each matrix
case's `args`, takes fixture-borne TYPE coverage via a per-case `covers` list,
and exits 1 on any non-waived feature no case exercises. LESSONS #11.

## 11. Addendum — the 1.0 arc and the second platform (2026-08-22 → 2026-09-01)

Scope: PRs #43–#63 — 24 non-merge commits in eleven days. Three releases
(v0.4.0, v1.0.0, v1.0.1), a Linux backend to phase L1, a per-platform coverage
gate, and the rename to `lsof-rs`. Reconstructed from git, the release
validation log in `docs/road-to-1.0.md`, and step 0 of the retrospective
prompt: every harness re-run against the real tree on 2026-09-02.

### 11.0 Step-0 results — what the harnesses found *about themselves*

Run first, as the prompt insists, and it paid immediately. The code gates were
all green (unsafe 139/139 documented; coverage 0 uncovered on both platforms;
differential self-test 30/30; `check-kit` OK). The findings were about **controls
the kit mandates that this port never instantiated**:

| Kit control | Where mandated | State in lsof-rs after 21 PRs |
|---|---|---|
| `progress.json` | CLAUDE.md "keep current"; Phase 4 step 6; retrospective step 1 | **never created** |
| `DIVERGENCES.md` | Phase 2 exit criteria; Phase 5 "ship as release notes"; control table | **never created** — `ledger.json` holds one entry |
| C-flaw triage | scan output: "Triage each… record in DIVERGENCES.md" | 127 findings (94 int-overflow-mul, 24 unbounded-copy, 8 format-string, 1 command-exec), **none triaged** |
| Sanitizers | control table row "No UB at the FFI boundary — CI"; template has `miri` + `asan` jobs | **zero mentions in the port's CI** |
| Fuzz per parse module | Phase 4 step 3 | one target (`parse_args`); the Linux backend's seven `/proc` text parsers unfuzzed |

None of these surfaced from reading the playbook, and none would have from a
green CI. They surfaced because the prompt says *run* the harnesses and one of
them ends its output with an instruction nobody had followed. The lesson is not
"be more diligent"; it is that the kit **asserts** these artifacts exist and
**checks** none of them (§11.4, LESSONS #019).

### 11.1 Failure inventory

Ranked by what it cost and what it taught. Every item was found by something
that executed against reality, and none by review.

**F1 — v1.0.0 failed its own field checkpoint** (`36ace1e`, `1a66cd6`).
Every automated gate was green on the 1.0.0 artifact. The manual pass on real
Windows 11, elevated, failed one case: `plus-D-directory-tree` exceeded 60 s —
measured at **214 s** against a `%TEMP%` of 431 entries. Root cause: the
per-process extras phase awaited each process *in turn* with a 2 s timeout, so
its worst case was `2 s × process count`. Unelevated it is invisible
(`OpenProcess` on a foreign process fails instantly); elevated, `SeDebugPrivilege`
makes every read succeed and some of them slow. **Not a 1.0 regression**: the
code was unchanged since Phase 4; v0.4.0 had passed the same case on timing.
Hosted runners have a small idle process set and cannot express the condition.
The fix ran the phase concurrently under one global budget; the first budget
value (20 s) was itself wrong — a wedged worker would have cost `lsof -p` 20 s
where the old code cost 2 s — and was caught pre-merge by asking "what does this
number replace?" and sizing it against that (5 s).

**F2 — exit criterion 4 measured calendar, not effort** (`edb763b`).
"14 consecutive green nightly deep-fuzz runs" used elapsed days as a proxy for
fuzzing work. Asked why 1.0 had to wait, there was no answer that survived
contact: the nightly had already done 200M+ execs with corpus growth flattened to
+6 % and coverage steady at `cov: 1125 / ft: 6790`. The criterion was rewritten
to what it had meant to measure — cumulative effort plus a coverage plateau plus
zero findings — and 1.0 cut the same day.

**F3 — the release published a checksum for a different binary** (`220ea86`).
Two dispatches of the release workflow raced; the notes carried one SHA-256 and
the asset another. Fixed with a `concurrency` group and by writing the notes from
the run that uploaded the asset. The user deleted the release and it was re-cut
once, cleanly. LESSONS #014 had covered release *permissions*; it had not
covered release *concurrency*.

**F4 — the coverage gate excused features the port now intended to ship**
(`9dce2f4`). 118 waivers. Roughly half rested on "Unix-only" or "no Windows
equivalent". All true when written; all false the day the Linux backend merged;
**nothing in the file changed**, so the gate stayed green. Two were wrong on the
day, not merely expired: `type:BLK` and `type:FIFO` were waived as having no
Windows analogue while the Linux backend was already emitting both. The fix gave
waivers a `platforms` list and the gate a `--platform` flag, run once per
platform; the Linux run then demanded four TYPE codes, one of which
(`type:LINK`) the code mapped but **no test had ever asserted** — declaring it
covered without the assertion would have been exactly the lie the gate exists
to catch, so the assertion went in first.

**F5 — `-U` had never filtered anything** (`7d64265`). `Selection::unix_only`
was declared and never read. On Windows the ETW path happened to yield only
AF_UNIX rows when `-U` was set, so the missing predicate was invisible for the
flag's whole life. Against a backend that returns every open file, `-U` listed
the system. Fixed in `lsof-core`; Windows' smoke suite still passed, proving the
predicate a no-op there and a fix on Linux.

**F6 — DEVICE/NODE are filled differently per socket family** (`7d64265`).
lsof puts inode+protocol in those cells for inet rows and kernel-pointer+inode
for AF_UNIX. L1's first cut had the inode in NODE for both — reasonable-looking,
wrong, and invisible to any unit test. Found by the first side-by-side run
against the C. Likewise `st_rdev` vs `st_dev` for device nodes in L0
(`a58d133`), and that a *listening* AF_UNIX socket sits in `St=01` and is
identified only by `SO_ACCEPTCON` in the flags column.

**F7 — three renderer divergences latent in the Windows output since v0.2.0**
(`docs/known-limitations.md`). The `-T` suffix shape (`(QR=0) (QS=0)` vs the C's
`(QR=0 QS=0)`); `-Tq` appending to the state where the C replaces it; `COMMAND`
never truncated to the C's default 9. All in `lsof-core`'s renderer, so they
had applied to every Windows release; nobody could see them because Windows has
no C to compare against. **The Linux differential found Windows bugs.** They are
recorded, not fixed — each alters output the golden fixtures and 59 smoke cases
assert, which makes matching the C a compatibility decision for the maintainer.
*Fixed 2026-09-05 (PR #73), all three: DIVERGENCES.md rows 1–3.*

**F8 — the rename broke four things across three passes** (`e73c73c`). A
case-sensitive `find -name` missed `Invoke-WinlsofSmokeTest.ps1`. A bare
`winlsof` used as a Python variable became `lsof-rs` (does not parse). CI called
a script filename that did not yet exist. `Add-Type -Namespace Lsof-rsNative` —
a .NET namespace cannot contain a hyphen. And the protection regex for published
tags guarded only the *left* side of each CHANGELOG compare URL, leaving six
dead links. Pass 1 did the rename; pass 2 found three by **syntax-checking every
tracked script**; pass 3 found the dead links by verifying every tag named in
the file against the remote. The silent-CI failure I had been guarding against
never happened; the loud and the quiet-but-wrong ones did.

**F9 — invented test expectations** (L0). The `dev_t` decode test was written
with hex expectations I had not computed; it failed twice. Fixed by computing
them. Small, but it is the same species as F6: a test pins what you *believe*.

### 11.2 Diff against the playbook — what it prevented and what it lacked

*Prevented, as written.* Observe-first promotion of CI-only gates (LESSONS #9/#13)
held: the Linux job landed hard-gated only because its tests were host-portable.
Spike-and-gate (Phase 4) held for `-iICMP/-iRAW`. The human-button release
fallback (LESSONS #14) was used again. The coverage gate (LESSONS #11/#12) did its
job the moment it was given a platform axis. `forbid(unsafe_code)` on `core`
extended cleanly to a whole second backend.

*Lacked — the failures the playbook, as written, would not have prevented:*

1. **Phase 2 has no "asymmetric oracle" case.** It covers "reference runs here"
   and "reference cannot run on the target" (substitute). It has nothing for the
   situation that actually produced the most findings: *the port targets two
   platforms and the reference runs on one of them*. That platform's diff is an
   oracle for every line of shared code — F5, F6, F7 all came from it — and the
   playbook did not tell me to build it first or treat its findings as
   cross-platform. The scope doc did ("start L3's harness immediately after L0")
   and I did not; the diff was done by hand.
2. **Phase 5 has no real-hardware field checkpoint.** It gates cutover on the
   differential, fuzz corpus and supply chain — all things a hosted runner can
   run. F1 is a defect no hosted runner can express. `road-to-1.0.md` criterion 5
   (the *exact* release artifact, real hardware, every privilege mode, with a
   per-case ceiling) is what caught it; the kit had no such gate.
3. **The architecture template knows one `sys` crate.** "Implementations live in
   `sys` behind `#[cfg(...)]`." lsof-rs has two backend crates, and the second is
   `#![forbid(unsafe_code)]` — a backend needing no FFI, which the template's
   defining invariant ("`sys` = the unsafe crate") has no slot for. Adding a
   platform touched `lsof-core` by one enum variant and nothing else, which is
   the seam working *better* than the template describes.
4. **Waiver reasons had no platform scope** (F4). Fixed in the kit this window.
5. **Three mandated ledgers with no existence check** (§11.0). The playbook
   names `progress.json`, `DIVERGENCES.md` and a fuzz target per parse module
   as exit criteria. Nothing fails when they are absent; a 21-PR port shipped
   1.0 without any of them.
6. **No procedure for renaming a project** (F8), and no prompt for adding a
   backend — `PROMPTS/` has kickoff, module, retrospective.
7. **Release concurrency** (F3) — #014 covered credentials, not races.

*The scope doc versus what happened.* It estimated L0+L1 at 1,450 lines; actual
is 1,201 (the Linux crate, including tests). It said to decide the name *before*
L0; it was decided after L1, which cost one more release under the old prefix
and one more PR of prose. It said to settle the matrix shape in L3; that became
its own PR between L0 and L1 — the right call, because L1's own TYPE codes were
pre-waived and building against that gate would have produced no signal. And it
said to start the L3 harness right after L0; that is still not started, and the
diffs in F5–F7 were run by hand in a shell. **L3 is the highest-leverage open
item in the port** and the kit should have made it a gate, not a suggestion.

*Closed 2026-09-02 (PR #66):* the L3 harness is the `differential (linux, vs the
C)` CI job, `lsof-rs/differential/linux_diff.py`.

### 11.3 Top time sinks (churn + clustering)

| Rank | Where | Signal |
|---|---|---|
| 1 | `CHANGELOG.md` (16 commits), `README.md` (9), `road-to-1.0.md` (9) | Docs churn tracked every decision; the price of keeping them truthful was paid continuously and was worth it — a stale v0.2.0 validation claim was found and fixed. |
| 2 | Release day 2026-08-30 — 12 commits, 14:37 → 21:07 | v0.4.0 validation, 1.0.0 cut, its field failure, root cause, 1.0.1, re-validation, CI dedupe, then L0 — six hours from "1.0 is done" to "1.0 was wrong" to "1.0.1 is validated". |
| 3 | `coverage-matrix.toml` (7) | Every feature PR touched it — the gate is load-bearing. |
| 4 | `lsof-backend-windows/src/backend.rs` (5) | The extras-budget fix and its self-caught correction. |
| 5 | The rename (92 files, 73 detected renames) | One PR, three passes, four breakages. |

### 11.4 What to carry into the kit (this addendum's patches)

1. **Phase 2 — the asymmetric oracle.** If the reference runs on *any* target
   platform, that platform's C-vs-Rust diff is the oracle for all shared code;
   build it before the second backend's phase 1 and treat its findings as
   cross-platform.
2. **Phase 5 — the field checkpoint.** Per release: the exact artifact, real
   hardware, every privilege mode, per-case time ceiling, results logged with the
   verdict. Hosted CI cannot substitute.
3. **Architecture template — one backend crate per platform**, each `cfg`-gated
   at its root, any of which may be `forbid(unsafe_code)`; the unsafe audit runs
   per crate.
4. **`harnesses/ledgers/check_ledgers.py`** — a port-side presence check for the
   three mandated ledgers, wired into `check-kit`'s self-test and offered for the
   port's CI, so "the playbook says so" becomes "the build says so".
5. **Coverage gate `--platform`** and `platforms` on waivers (already landed;
   documented in the control table with its expiry failure mode).
6. **A rename procedure** (three passes; protect published tags; alias env vars;
   inventory case-insensitively; verify by executing).
7. **`PROMPTS/20-new-backend.md`** — the second-platform prompt.
8. **Release concurrency** added to Phase 5's mechanics.

### 11.5 The single failure the kit still would not prevent

**F7.** After every patch above, a port whose reference implementation cannot
run on its *only* target platform still has no way to find fidelity bugs in what
it renders. The kit's answer for that case is oracle-substitution: a native data
oracle plus golden tests for format. But a golden test pins what its author
*believed* the C emits, and for the `-T` suffix, `-Tq` semantics and the
`COMMAND` width that belief was wrong for six releases. The thing that found
them was not a control — it was acquiring a second platform where the C runs,
which is a project, not a gate. The kit can say this plainly (Phase 2 now
does): **on a platform with no reference, format fidelity is a claim, not a
measurement, until a same-host diff exists somewhere in the port.** It cannot
manufacture that diff. The next single-platform port's target is to find a
cheaper substitute — a recorded C transcript corpus captured on any host where
the C runs, replayed as golden input on the target — before it ships 1.0.

## 12. Addendum — the Linux parity arc (2026-09-02 → 2026-10-04)

Scope: PRs #64–#121, 145 non-merge commits in 33 days. The Linux differential
(L3, PR #66) went from nothing to 425 cases against the C built from this tree,
and DIVERGENCES.md's numbered table from nothing to 107 rows. LESSONS went from
#022 to #081: 59 entries, 45 written here and 14 imported from the primary line.
Inside the arc sit three smaller ones: the repository cleanup (PRs #81–#96, with
its own retrospective, `RETROSPECTIVE-cleanup.md`); the kit's refresh from the
primary line (PR #93) and eleven kit PRs after it; and the parity work that runs
through PRs #106–#121, where each change closed measured differences one at a
time. Reconstructed from git, the arc's LESSONS entries, DIVERGENCES.md and a
step-0 run on 2026-10-04 against master `2543252`.

### 12.0 Step-0 results

Every gate the port runs was green on the real tree. Two harnesses the kit
offers could not be pointed at it, and one control had no evidence to run:

| Harness | On the real tree, 2026-10-04 |
|---|---|
| fmt, clippy (Linux, and Windows through `x86_64-pc-windows-gnu`), rustdoc, unit tests | clean |
| `audit_unsafe.py`, `check_forbid_unsafe.py` | 139 `unsafe` blocks, all documented; 3 crates forbid `unsafe_code` |
| `coverage_gate.py`, both platforms | 186 features, 0 uncovered (Linux 80 covered and 106 waived; Windows 80 and 126) |
| `check_ledgers.py`, `check_threat_model.py` | 5 of 5 present; pass |
| `linux_diff.py` | 425 cases, 0 unexplained, 8 s |
| `resource_gate.py`, 400 synthetic processes | `-i` at 0.94x the C's wall time and 0.96x its peak RSS; the whole host at 0.88x and 0.89x |
| miri: core and CLI; the Linux backend | green, in 122 s and 387 s |
| ten fuzz targets, 46 s each | 12.0 M executions, no crash |
| cargo-deny | advisories, bans, licenses and sources ok |
| `scan_c_flaws.py`, over the triage's scope | the committed triage's 98 hits, exactly |
| `make check-kit` | OK in 6 min: 46 gates mutated, 0 survivors; 608 decisions, 0 new, 0 stale. One warning called a self-test that overran its time under load "nondeterministic"; alone it ran in 1.9 s |
| `diff_fuzz.py` | **cannot be pointed at lsof**: it fuzzes stdin, and lsof parses argv |
| `perf_gate.py` | **cannot run this matrix**: 395 of its 425 cases need a fixture process; the port wrote `resource_gate.py` instead |
| the port's mutants | **nothing to run**: at least 233 mutants recorded in DIVERGENCES.md, by eight scripts, none committed |

The three bold rows were the finding, with the warning: it told a reader that
kills elsewhere in the sweep could not be trusted, when the cause was load. Its
message now says which of the two happened. The integrity sweep (§12.3) then
asked each green gate what it does with input that is missing, misspelt or
empty, and nine passed where they should have failed (LESSONS #082).

### 12.1 Failure inventory

Ranked by what each cost. Most were found by measuring against the C; F7 was
found by reading the code.

**F1 — the option parser was debugged by hand for eight days** (PRs #112–#118;
LESSONS #084). getopt's two spellings of a value, a `+` word read as a cluster,
an empty list item: each was found by measuring one case against the C, writing
a row and fixing it. The retrospective built an argv fuzzer and ran it against
the binary from the merge before #112: 1,500 vectors in about a minute found 52
distinct divergences, and 34 of them are what those eight days fixed. The kit's
differential fuzzer could not have been pointed at lsof: it fuzzes stdin.

**F2 — rules that were reasoned about, not measured, were wrong** (LESSONS
#074–#078). "Any row of a task locates `-K`" (under `-a -i` the C builds fewer
rows); a NAME fallback for sockets that never matched a socket and did match the
wrong file in another mount namespace; `filter(|s| !s.is_empty())` deciding what
an empty list item means; `canonicalize()` standing in for the C's `Readlink()`;
two cases that matched for the wrong reason. Each rule passed every differential
case written from it, because the cases were written from the same belief, and
each was found by a second reader measuring against the C. Of the 44 DIVERGENCES
rows that say how they were found, 22 came from that review, 9 from measuring
the C for a change, and 10 from this retrospective (LESSONS #085).

**F3 — the gate could not compare what differed** (LESSONS #067, #068, #070,
#071). The normalizer collapsed runs of blanks, so the C's right-aligned columns
matched the port's left-aligned ones in 205 cases. The port printed one `unk`
line where the C prints a row for each unreadable link, through 170 cases,
because every fixture was the harness's own process, which it could read. A
kernel table holding one byte that is not UTF-8 was read as empty. Coverage by
option letter credited `-F` for `-Fpn` while `-F pn` looked for a file named
`pn`. In each case the gate compared what it could compare, and the difference
was somewhere else.

**F4 — costs that scale were invisible at ambient scale** (LESSONS #061, #062,
#079). `lsof -i` read every process's maps file, 578 of them at 577 processes
where the C read none, and the output was identical. The meter that called
memory "identical and flat" was measuring Python. Porting the C's `Readlink()`
and `+D` walk brought the C's costs to input a user can choose: 2 s per mount
for a FUSE source holding 20 links. The resource gate now starts 400 processes
of its own, so the `-i` cost would fail it if it came back.

**F5 — `lsof | head` panicked** (LESSONS #063) with exit 101, for the life of
the port: the C dies of SIGPIPE and Rust ignores it. No gate piped the output
anywhere.

**F6 — gates reported what they had not measured, again** (LESSONS #029,
#031–#033, #058–#060, #066, #072, #073, #082). This was the arc's most-written
lesson. Most failed open: the kit's integrity gate ran in no workflow; the
sanitizers ledger took a comment for a job; a citation list was checked on its
first number; a skip counter hid four live links; a mutant that was not reverted
read as a kill. Some failed the other way: a mutation that did not apply read as
a survivor, and a stale verdict read off one run in a busy pool failed
`check-kit` on a tree that had passed. Each fix closed one instance, and nothing
enumerated the class until the retrospective asked nine more gates the same
question.

**F7 — what the port touches, as against what it prints** (DIVERGENCES
110–112). This was found by the retrospective's code review and confirmed with
`strace`, not by any gate:
- lsof-rs `statx()`es every mount directory in-process, with no timeout and
  without `AT_NO_AUTOMOUNT`, on every run but `-f`, `-i` included. The C `stat`s
  them only when a run needs them, each in a child under a 15 s `alarm()`, and
  none under `-i`.
- A `+D` walk `lstat`s an entry and then `stat`s it again following links, so a
  rename between the two gives the entry another file's identity.
- An `-i` error message prints its argument raw, ESC included.

On a healthy host all three print what the C prints (see §12.6).

**F8 — "done" was a gate state** (LESSONS #085). `progress.json` had said all
four units were done since 2026-09-20, and 37 rows were found in October.

**F9 — documents restated the code, and drifted** (LESSONS #080). About 200
claims had stopped being true, most of them counts written into prose. This
retrospective found another round (§12.3).

### 12.2 Diff against the playbook — what it prevented and what it lacked

*Prevented, as written.* The differential-and-ledger loop held for the whole
arc. Every divergence was triaged, and the C's own defects were recorded, not
ported (`safestrlen()`'s sizing, LESSONS #023; rows 102, 103 and 107). Mutating
the cases a change had just written found tests that passed for the wrong reason
(LESSONS #026, #078). Observe-first promotion took miri (PR #65) and the Windows
ASan job (PR #78) to hard gates without a red master. The threat model became a
gate (PR #97), and the flaw scan was triaged (PRs #75, #98). The coverage gate,
given a platform axis in §11, gained the next-word spelling the day it was shown
blind to it (LESSONS #071).

*Lacked — failures the playbook, as written, would not have prevented:*

1. **No step measured the C before the Rust was written, and "review" was not
   defined** (F2). Phase 4 began at "port the module". Patched: Phase 4 now
   measures the C first, and step 6 says what a review is and what it produces
   (LESSONS #085).
2. **Mutation evidence was prose** (§12.0). Patched: `mutate_port.py`, and
   lsof-rs's first mutants file (LESSONS #083).
3. **The differential fuzzer could not reach the port's input** (F1). Patched:
   an argv mode (LESSONS #084).
4. **Cost was not a control** (F4). The port built its own resource gate, and
   the playbook had no row for one. Patched: a cross-cutting row for cost.
5. **Phase 2 prescribed `golden.py` capture**, and this copy's `golden.py`
   stores a hang as a golden and ignores exit codes (§12.4). It was not used on
   real input here, so it cost nothing; the playbook now warns.
6. **"Done" in the progress table read as "matches"** (F8). Patched in prose
   (LESSONS #085); the table is unchanged.
7. **Nothing compares what the port touches** (F7). Not patched; see §12.6.

### 12.3 The integrity sweep — every tracked file against the project's purpose

The repository states its purpose in three parts: lsof-rs is a memory-safe
reimplementation of lsof; the C tree beside it is the oracle it is compared
with, unchanged; and `porting-kit/` is the method, vendored from the primary
line. All 425 tracked files were read against that, in nine passes (five by
area, three for step 4c, and step 0), which reported 124 findings, about a dozen
of them one defect seen twice.

- **The oracle is unchanged.** Over the arc nothing the Linux build of the C
  compiles changed: there were two comment-only edits to
  `lib/dialects/linux/machine.h` and one `EXTRA_DIST` line. Of the 128 files PR
  #81 deleted, none is compiled for Linux.
- **The port is less safe than the C in three places** (F7, rows 110–112). Each
  is recorded as an OPEN security row. The threat model's §2 gained the inputs
  it lacked: link targets, namespace links, mount directories, AF_UNIX paths,
  Windows object and module names, accounts, the IP Helper tables and reverse
  DNS. Fixing row 110 is the next work item.
- **The kit's gates.** Nine fail-opens were fixed (LESSONS #082). The skeleton
  is built and tested by something automatic for the first time. The BSD CI
  claim is withdrawn: no provider runs `.cirrus.yml` or `.builds/` for this
  fork, so the platform ledger waives FreeBSD, NetBSD and OpenBSD, and
  `RETROSPECTIVE-cleanup.md` carries the correction.
- **The release workflow** could publish a build of one commit under another
  commit's tag, and pasted the tag into its script in a job that can write to
  the repository. It now builds the tag's own commit, refuses to replace a
  published release without an explicit input, and reads the tag from the
  environment.
- **Documents.** The kit's README now says where each harness runs here and
  where it does not, and the playbook is back under its ~400 lines. The C tree's
  docs no longer point at what PR #81 deleted. lsof-rs's README, threat model,
  coverage waivers and plans were corrected where they had drifted; two waivers
  covered TYPE codes the port had shipped.

Every finding has one of four dispositions: fixed in the retrospective's PR,
recorded as a DIVERGENCES row, left as a decision for the maintainer (§12.7),
or put on the kit's backlog.

### 12.4 Step 4c — the vendored kit against the primary line

This copy has 27 harness and skill scripts. 21 are shared with the primary
(`kj299/c2rust-port` at `eb058f6`), and all 21 differ, mostly in renumbered
citations. Six exist only here (`coverage_gate.py`, `check_ledgers.py`,
`check_imports.py`, `resolve_collision.py`, `check_platforms.py` and
`mutate_port.py`). Four exist only there; the README's not-vendored table says
why.

| Disposition | What |
|---|---|
| Imported now | `check_controls.py`'s comment-filter fixtures and the mutation row that pins the filter; the `cites()` row for `check_lessons_pinned.py`; the CI template's `rust-src` for the sanitizer job and its fail-closed fuzz loop |
| To import (backlog) | `golden.py`: an exit-code sidecar, refusing a hang as a golden, `keep_whitespace`, pruning stale goldens. `progress.py`'s ingest matching. The scanner's multi-line sinks, `memcpy`, precomputed `malloc` sizes and `exec` family. The example matrix's multibyte case |
| To send to the primary | the fail-open fixes in harnesses both copies share; `mutate_port.py` and the argv mode; the placement rule for `// SAFETY:` in `audit_unsafe.py`; `check_lessons_pinned.py`'s fixture numbers; `golden.py`'s refusal of an empty matrix; the scanner's literal blanking bounded to one line; the quoted fuzz-ledger form; the CI template running every control, with the C sources in its trigger and miri's isolation flag |
| Deliberate divergence | never take the primary's `diff_run.py` whole: it ignores `cwd` and `with_stderr`, which 41 and 6 of lsof-rs's cases set |

### 12.5 What this retrospective carried into the kit

The three largest improvements:

1. **Mutants as data** (LESSONS #083): `harnesses/port-mutation/mutate_port.py`,
   and `lsof-rs/mutants/mapped-rows.toml`, a kill table that runs again. Run
   against master, all 30 of its mutants were killed, and the split between
   gates had moved since the PR recorded it.
2. **An argv mode for the differential fuzzer** (LESSONS #084), taking its
   alphabet from the coverage inventory. Its first run on master took 16 s and
   found four divergences no one had recorded (rows 114–117).
3. **The fail-open sweep** (LESSONS #082): nine gates fixed, each with a
   fixture, and the rule to sweep the class when one is found.

The prose changes: Phase 4's measure-first step and a defined review (LESSONS
#085); `MATRIX-CHECKLIST.md` and `CI-AND-RELEASE.md`, split out of the playbook;
a README that says which harness runs where; the step-4c warning about
`diff_run.py`. The lift script, a one-time tool whose `FORCE=1` overwrites the
primary's `main`, was deleted.

### 12.6 The single failure the kit still would not prevent

**F7: what the port touches.** The kit's controls look at what the port prints
(the differential, golden, coverage), whether it crashes (fuzzing), whether its
`unsafe` is sound (miri, ASan, the audit) and what it costs (the resource
gate). None of them looks at what the port does to the system it reads. Row 110
is the sharpest case. With a hung NFS server, lsof-rs hangs where the C gives
up after 15 s, and listing an automount point mounts it; on a healthy host the
two print the same bytes. A reader with the code open found it, and `strace`
confirmed it. The same tool had found the 578 maps files of LESSONS #062.

The candidate control is a **syscall differential**. Run each matrix case under
`strace -f` for both binaries and compare, by class, what each one touches:
which paths it `stat`s, opens or follows, and in which process. Deliberate
differences get waivers, as the ledger has. It would have caught the maps files
of LESSONS #062, row 110 and row 111 the day each was written. Building it is
the next port's target.

### 12.7 Decisions this retrospective leaves to the maintainer

1. **The next version.** Master's binary says 1.0.1 while the CHANGELOG's
   Unreleased section holds breaking changes; by semver that is 2.0.0.
2. **Row 110 first.** Stat mounts in a child under a timeout, with
   `AT_NO_AUTOMOUNT`, and none under `-i`.
3. **`overflow-checks`.** Turning them on in the release profile needs
   `checked_add` first in `peb.rs`, which adds offsets read from the target
   process; otherwise a hostile process could make lsof-rs panic.
4. **Rows 91 (`-J`'s schema) and 94 (`-b`, `-S`)**, both DECISION PENDING; row
   101 (a path argument that names a device); and `DEL` against `mem` for a
   container's deleted library (DIVERGENCES, "For you to decide").
5. **`default.nix` and `mkdocs.yml`**, whose consumers are gone.
6. **Connect Cirrus CI and sourcehut, or keep the three BSD dialects waived.**
7. **Kit work that needs a design:** signed `+X`/`-X` ids in the coverage gate;
   coverage per platform rather than shared; a check that the normalizer's masks
   hide nothing a case means to compare; a guard against optional fixtures
   skipping silently; third-party actions pinned by SHA.
