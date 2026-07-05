# Retrospective — the winlsof port (C `lsof` → Rust, Windows)

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
transpilation. The two trees coexist in one repo, untouched (`winlsof/` beside
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
   **55-case live smoke harness** (`Invoke-WinlsofSmokeTest.ps1`) stands up
   deterministic fixtures (a held file at a known offset, a named pipe with a
   connected client, a mapped data file, TCP v4/v6 listener+established pairs,
   UDP, child processes with known cwd in 64- and 32-bit) and asserts winlsof
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
| 4 | `91e453d` | Add `WINLSOF_TRACE` phase tracing **to find where** it hung | Diagnostic, not a fix — but the pivot point |
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
2. **The live smoke harness** — `Invoke-WinlsofSmokeTest.ps1` (16 commits, 706
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
