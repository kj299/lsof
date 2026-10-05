# PLAYBOOK — porting a C codebase to Rust, safely

A repeatable, codebase-agnostic procedure for rewriting C in Rust with **safety
and security as the primary goal** — distilled from the lsof-rs port (see
[`RETROSPECTIVE-lsof.md`](RETROSPECTIVE-lsof.md)) and designed to compound after
every use (see [`CLAUDE.md`](CLAUDE.md) and [`LESSONS.md`](LESSONS.md)).

**Prime directive.** The Rust rewrite exists to be *safer and more secure* than
the C, not merely equivalent. Two consequences run through every phase:

1. **The C is a specification, not an authority.** It may contain
   vulnerabilities, UB, and latent bugs. Faithfully re-implementing a CVE is a
   failure, not fidelity. Every divergence from C behavior is triaged, and the
   intentional ones (where C was wrong) are recorded — never silently matched.
2. **Every module clears the safety gates before it merges.** Compiling and
   matching the oracle is the floor, not the bar. The bar is: unsafe audited,
   fuzzed, sanitizer-clean, supply-chain-clean.

Nothing here assumes a target OS or that the port is cross-platform. If your port
*is* cross-platform, keep a platform seam — but that is an isolation detail, not
this playbook's focus.

Read [`SECURITY-CHECKLIST.md`](SECURITY-CHECKLIST.md) alongside this; it is the
per-module control ledger the phases refer to.

---

## Phase 0 — Inventory & threat model

**Goal:** know the terrain and the risk before writing Rust.

**Do:**
- Enumerate the C: modules, LOC, external deps, the syscall/ioctl/FFI surface,
  global mutable state, macros, the build system. `harnesses/progress/progress.py
  init --modules a,b,c` seeds the module table from this (one unit per crate:
  `check_ledgers.py` matches each against a sanitizer step's `-p <unit>`).
- **Scan the C for vulnerability classes** — `harnesses/c-flaw-scan/scan_c_flaws.py`
  flags the classic sinks (`strcpy`/`strcat`/`sprintf`/`gets`/`scanf("%s")`,
  `alloca`, integer-overflow-before-`malloc`, `system`/`popen`/`exec*`,
  non-literal formats, `access`/`stat` before open, signed-`char` compares). Every hit becomes a note on the owning module: *do not
  port this bug — fix it, and log the fix as an intentional divergence.*
  A scanner is only useful if it is *trusted*: tune it for signal-to-noise
  against the real target before relying on it — a check that cries wolf gets
  muted, and the real flaws drown (LESSONS #2: the format-string check once
  produced 828 false positives on lsof, burying ~215 real candidates).
- **Classify the FFI/syscall surface by failure mode** (LESSONS #1). For each
  external call the port will make, record three properties: can it **block
  indefinitely** (→ needs a timeout / worker thread / a design that avoids it),
  does it need **privilege**, does its behavior **vary by OS/version**? This is
  what makes Phase 1's "spike the scary module" rule actually fire. The lsof-rs
  hang cost seven commits precisely because `NtQueryObject`'s blocking behavior
  was never classified up front — the spike-first rule can't trigger on a hazard
  no one wrote down.
- Write a one-page **threat model**: trust boundaries (untrusted input, privilege
  transitions, IPC, parsing of external data), and what "secure" means for this
  tool. `SECURITY-CHECKLIST.md` has the template.

**Entry criteria:** access to the C source and its build.
**Exit criteria:** module inventory table exists; C-flaw scan run and triaged;
threat model written.
**Artifacts:** `progress` table, `c-flaw-scan` report, `THREAT-MODEL.md`.
**lsof failure modes this prevents:** going straight to code and discovering the
scary module (the `NtQueryObject` hang) mid-implementation. Inventory surfaces
the hazards first.

---

## Phase 1 — Dependency graph & port order

**Goal:** an order that lets each module be tested against the oracle the moment
it lands.

**Do:**
- Build the module dependency graph (includes + call graph; `cflow`/`clangd` or a
  grep pass). Choose order by these criteria, in priority:
  1. **Roots before dependents** — port what others need first (in lsof: the
     process model before the files that hang off it).
  2. **Cheapest-and-safest-first among independents** — bank easy wins, harden
     the loop and harnesses on low-risk modules before the deep end.
  3. **Spike the known-scary module before you schedule it** (see Phase 4's
     "spike" note) — do not let a hazard ambush you inside its port.
- Prefer *capability-phased* slices (a user-visible feature end-to-end) over
  strict leaf-first when the codebase is a tool — it keeps every phase shippable
  and testable.

**Entry criteria:** Phase 0 inventory.
**Exit criteria:** ordered module list with a one-line rationale each; hazards
flagged for a pre-port spike.
**Artifacts:** ordered list in the `progress` table.
**lsof failure modes this prevents:** ad-hoc order that defers integration risk.
lsof-rs's phase order was sound; its one miss was not spiking the hang first.

---

## Phase 2 — Establish the oracle (before any Rust)

**Goal:** a reference you can diff against — while remembering it may be wrong.

**Do:**
- Lock the C binary at a known commit. Capture golden outputs across a
  **documented input matrix** (`harnesses/differential/input-matrix.example.toml`)
  with `harnesses/golden/golden.py capture`. *This copy's `golden.py`
  compares stdout only and stores a hung oracle's `<<TIMEOUT>>` as a golden
  (LESSONS #072); until the primary line's version, which keeps exit codes
  and refuses a hang, is imported, judge exit codes and hangs with
  `diff_run.py` against a live oracle.*
- **Detect oracle nondeterminism up front** — `golden.py` runs each input N times
  and flags fields that vary (PIDs, timestamps, addresses, ordering). Those feed
  the normalization rules (`harnesses/differential/normalize.py`), so a real
  regression isn't masked by noise and noise isn't mistaken for a regression.
  Normalize only what varies. The runner's default also collapses whitespace,
  which is noise for some tools and **output** for a tabular one: a column
  aligned the other way collapses to the same line. Once the port's output
  matches, compare it byte for byte (`keep_whitespace`, LESSONS #070).
- If the reference binary **cannot run on your dev/target environment** (lsof-rs:
  C lsof doesn't run on Windows), substitute:
  - **structural golden tests** for output *format* (columns, field codes, JSON
    shape), and
  - **independent oracles** for the *data* (native tools that report the same
    facts a different way).
- **Harden the harness for its host** (LESSONS #1). The test harness is software,
  and it runs in a shell with its own encoding/quoting model that *will* bite —
  lsof-rs spent six commits on PowerShell-5.1 / Windows-1252 breakage in the
  harness itself. Two defenses: write kit-level harnesses in a portable language
  (these are Python + POSIX sh on purpose, not the target's shell), and pin the
  tool's default output to the lowest-common-denominator encoding of the target's
  default shell (lsof-rs: ASCII default, UTF-8 opt-in). And the **CI runner is
  yet another host** (LESSONS #13): hosted runners differ from any dev box in
  ways fixtures silently assume — 8.3 short paths in `%TEMP%`, always-elevated
  consoles, a newer shell *runtime* (lsof-rs's `-o` fixture seeked via .NET
  `FileStream`, which stopped moving the kernel file pointer in .NET 6+; green
  on PS 5.1 locally, red on pwsh CI). Establish fixture ground truth **at the
  layer the tool reads it** (set the kernel state, don't trust a runtime
  wrapper's view of it), and treat environment-dependent cases as first-class
  SKIPs, never FAILs.
- **The asymmetric oracle** (LESSONS #17). If the port targets several platforms
  and the reference runs on *any* of them, that platform's C-vs-Rust diff is the
  oracle for **every line of shared code**, not just for that backend. Build it
  before the second backend's first phase and treat each finding as
  cross-platform until proven backend-local: lsof-rs's Linux diff found three
  renderer bugs that had shipped in every Windows release, plus a selection
  predicate (`-U`) that had never been enforced. On a platform with no
  reference, format fidelity is a claim, not a measurement — a golden test
  pins what its author *believed* the C emits — so say so in the release notes
  until a same-host diff exists somewhere in the port.
- **The oracle lives in the tree and looks like legacy** (LESSONS #27). For the
  whole port the reference implementation sits in the repo beside the Rust, and
  every instinct — and every request to "clean up the rewrite" — reads it as the
  old thing being replaced. lsof-rs's C tree *is* the Linux differential, so a
  tidiness pass that deleted it would have destroyed the project's strongest
  correctness signal while every Rust gate stayed green. Write the rule where a
  cleanup pass will actually meet it (the repo README, not only this playbook),
  and state the boundary as a question about participation — *does this file
  build, test or document the oracle or the port?* — never as "C vs Rust".
  Part of the reference tree usually IS dead (lsof-rs: 66 files of dialects for
  OSes no build in the repo targets, plus a vendor's release machinery). Establish
  that by **deleting it and running the build, not by searching for references**:
  `cd tests && make` names no filename a grep can find, and a 0-byte file can
  still be named three times in a build template. Prove every removal with the
  reference tree's own gates — configure, build, test, dist — run against an
  untouched control of the same commit, **and run them along the path that
  reaches what you removed** (LESSONS #30). Building is not enough if you build
  the way CI builds: lsof-rs verified a deletion with `./Configure -n linux`,
  where `-n` is documented in that same script as "avoid AFS, customization,
  and inventory checks" — the exact three helpers being deleted — so the one
  build that proved it safe was the one build that could not see the break.
  **A verification run carrying a flag documented as "skip X" proves nothing
  about removing X.**
- Stand up an **intentional-divergence ledger** (`DIVERGENCES.md`, template in
  the skeleton): every place the Rust will *deliberately* differ from C —
  starting with the Phase-0 flaw scan's findings. **Its existence is checked**
  (`harnesses/ledgers/check_ledgers.py`, LESSONS #19): lsof-rs shipped 1.0 with
  127 untriaged flaw-scan findings and no ledger, and every gate was green.

**Entry criteria:** ordered module list.
**Exit criteria:** golden corpus captured + versioned; nondeterminism map;
normalization rules; divergence ledger seeded from the flaw scan.
**Artifacts:** `golden/corpus/`, `normalize.py` rules, `DIVERGENCES.md`.
**lsof failure modes this prevents:** the empty-result "bare header" and the
bare-`n` `-F` field shipped because there was no format oracle pinning them.

---

## Phase 3 — Architecture skeleton (unsafe quarantine)

**Goal:** a workspace shape that makes safety structural, not a review burden.

**Do:** copy `skeleton/` (see [`ARCHITECTURE-TEMPLATE.md`](ARCHITECTURE-TEMPLATE.md)).
The invariant it encodes:
- **`core` crate: `#![forbid(unsafe_code)]`.** Pure logic, data model, the
  algorithm. Testable everywhere, no FFI. This is where most of the port lives.
- **`sys` crate: the only place `unsafe` is allowed.** Every raw FFI call is
  wrapped in a small, audited safe function; every OS resource is an RAII type
  (close/free/drop-privilege on `Drop`). This kills use-after-free, leak, and
  privilege-held-too-long by construction.
- **`cli` crate:** thin; parse → build request → call core → render.
- **Scaffold observability on day one:** a `TRACE` env-gated phase logger. Do not
  wait for the first hang to add it.

**Environment preflight** (LESSONS #1): before the loop, confirm the toolchain
target actually links here (lsof-rs lost time to an MSVC-vs-GNU linker mismatch)
and that the build directory is not a synced/locked folder (OneDrive locked
`target\` → `os error 5`). Cheap checks that prevent days of "is it my code or my
machine?". If the port will be released from an automated session, preflight the
**release credentials** now too (LESSONS #14): can this identity push a tag?
dispatch a workflow? create a release? lsof-rs discovered at release time that
its sandbox could push branches but not tags and could not dispatch workflows —
a ten-second check months earlier.

**Entry criteria:** oracle in place.
**Exit criteria:** workspace builds; `core` is `forbid(unsafe_code)`; unsafe-audit
gate wired into CI (`harnesses/unsafe-audit`); trace logger present; environment
preflight clean; **the ledgers exist and CI checks that they do** —
`harnesses/ledgers/check_ledgers.py` passes (progress file, divergence ledger,
≥1 fuzz target, a sanitizer job, and a sanitizer step that runs `cargo … -p
<unit>` for every unit `progress.json` tracks). Create them empty on day one: lsof-rs reached
1.0 with none of the first three and no sanitizer job, because nothing failed
without them (LESSONS #19).
**Artifacts:** the workspace; CI config from `harnesses/ci/porting-ci.template.yml`.
**lsof failure modes this prevents:** scattered `unsafe` (lsof-rs kept 0 in core
and 131 real blocks in the sys layer, 51 of them undocumented — LESSONS #1
counted them; the 144/91 first quoted were grep hits; the gate makes the gap a
build failure). Tracing added reactively at hang-fix step 4 of 5.

---

## Phase 4 — The module port loop (per module)

**Goal:** each module ends safer than its C original, proven, before merge.

For a hazardous module (flagged in Phase 1), **spike first**: a timeboxed
experiment on the one scary syscall/idiom to learn its behavior (does it block?
need privilege? vary by version?) *before* committing to a design. Record the
result. This is the single highest-ROI habit in the retrospective.

**For a *research-grade* capability — one that might be impossible, not merely
hard** (lsof-rs: socket-FD correlation, byte-range locks, AF_UNIX/raw) — run the
**spike-and-gate ritual** instead of an open-ended attempt (LESSONS #1). It was
lsof-rs's biggest win: the hard gaps became the cheap ones. Steps: (a) rate
**effort** (S/M/L) and **confidence** a safe/public solution exists (Low/Med/
High); (b) write a **decision gate** *before* coding — the concrete signal that
says "stop, document as a platform limit"; (c) on hitting the gate, do a **pivot
check** — is there an adjacent, reachable goal? (lsof-rs's ETW spike couldn't get
the "real FD" but pivoted to extending `-i` to raw/ICMP/AF_UNIX, which shipped).
A closed sub-goal must not kill the shippable one beside it.

**Before the loop, measure the C** (LESSONS #085). For each rule the module
must get right, run the C on the inputs that tell the readings apart, as each
user it serves (root and not, inside a namespace and out), and write down what
it does before writing the Rust. In lsof-rs every rule found wrong after
merging was one reasoned about rather than measured.

Then the loop — each step is a CI-enforced gate:

1. **Port** into `core` (or a safe wrapper in `sys`). Translate C idioms to Rust:
   the "call-twice-for-size" buffer dance → a growing `Vec` with length checks;
   pointer arithmetic over structs → slices + `repr(C)` with bounds; unions/FAMs →
   audited casts with a `// SAFETY:` proof; integer math → checked/`saturating`.
2. **Differential-test** against the oracle (`harnesses/differential/diff_run.py`).
   A divergence is a *triage*, not an auto-fail: {Rust bug → fix} vs {C bug →
   log in `DIVERGENCES.md`, keep the safe behavior}. The verdict is **stdout AND
   exit code** (LESSONS #4): lsof exits 1 on no-match and scripts branch on it;
   `--ignore-exit` opts out for tools without stable codes. The per-case timeout
   is the **liveness backstop** (LESSONS #1): a hang is not UB, so sanitizers
   won't see it, and the fix is to design the blocking call out, not wrap it.
   A green run says nothing about inputs the matrix lacks (LESSONS #6, #8), so
   the matrix is designed: every feature of the C (`coverage_gate.py`, a
   value-taking option counted twice, LESSONS #071), what the tool cannot read
   (LESSONS #068), and the inputs that tell two readings of a rule apart — a
   fallback's own input (LESSONS #075), empty list items (LESSONS #076), every
   spelling of a path (LESSONS #077), a silent case silent for the right reason
   (LESSONS #078), a fixture's effect on every other case (LESSONS #081). The
   checklist, with the lsof-rs failure behind each, is
   [`MATRIX-CHECKLIST.md`](MATRIX-CHECKLIST.md). Past the matrix, fuzz both
   binaries with the same inputs — on argv for a command-line tool (LESSONS
   #084). When the reference can't run on the target, switch to
   **oracle-substitution** with a three-way exit contract (match / divergence /
   infra-error), so a broken harness can't read as a port bug.
   Finally, **mutate the rules you just wrote** (LESSONS #26): one plausible
   wrong version of each, committed as a mutants file and run with
   `harnesses/port-mutation/mutate_port.py` (LESSONS #083). A mutant no case
   kills is a case that checks nothing.
3. **Fuzz** the module's parse/input surface (`harnesses/fuzz/gen_fuzz_target.sh`
   scaffolds a `cargo-fuzz` target). Any crash/panic on untrusted input is a
   release blocker. **This applies per backend crate, and "input" includes text
   the OS hands you** (LESSONS #21): `/proc` lines, registry values, `sysctl`
   output. lsof-rs fuzzed the first backend's argument parser and none of the
   second backend's seven `/proc` parsers — a `forbid(unsafe_code)` crate can
   still panic on a hostile `Name:` field. And a target that names a parser must
   reach it: plant a fault in the parser and watch the target find it (LESSONS
   #056).
4. **Sanitize** (`harnesses/sanitizers/run_sanitizers.sh`): Miri over the pure
   logic and, for the `sys` layer, ASan (and TSan if threaded); rustc has no UB
   sanitizer, so the harness's `ubsan` mode runs Miri. lsof-rs's
   worker-thread hang fix is exactly the class TSan/Miri reasoning catches.
5. **Unsafe-audit** (`harnesses/unsafe-audit/audit_unsafe.py`): every `unsafe`
   block has a `// SAFETY:` justifying its invariants — **hard fail** otherwise.
6. **Review, then merge.** The review is a second reader — a person, or an
   agent with no stake in the change — asked to find what it got wrong and to
   measure each suspicion against the C (LESSONS #085). Each finding becomes a
   ledger row before the merge, fixed or not: in lsof-rs's last arc this review
   found half the rows that recorded how they were found. Then update the
   `progress` table (the module advances `ported` → `differential` → `fuzzed` →
   `sanitized` → `unsafe_audited`, the names `progress.py set` takes). A module
   at `unsafe_audited` has cleared its gates, not matched the C: its open
   ledger rows are the work that remains.

**Entry criteria:** skeleton + oracle.
**Exit criteria (per module):** all six gates green; `progress` row fully ticked.
**Artifacts:** the module, its fuzz target, its golden cases, divergence entries.
**lsof failure modes this prevents:** the 7-commit hang (spike-first + sanitizer
reasoning), fidelity misses shipping before a test pinned them (gate 2 + golden),
undocumented unsafe (gate 5).

---

## Phase 5 — Cutover & retirement of the C

**Goal:** ship the Rust; retire the C without losing its guarantees.

**Do:**
- Gate cutover on: 100% of the port's target modules through all six gates; the
  differential corpus green (modulo logged divergences); fuzz corpus seeded and
  clean; supply-chain gate clean (`harnesses/supply-chain/run_supply_chain.sh` —
  `cargo audit` + `cargo deny`); the threat model filled in
  (`harnesses/threat-model/check_threat_model.py THREAT-MODEL.md`); **and the
  field checkpoint** (LESSONS #15): the
  *exact* release artifact — downloaded, not a local build — run on real target
  hardware in every privilege mode, with a per-case time ceiling, results logged
  next to the verdict. **Hosted CI cannot substitute for this.** lsof-rs's 1.0.0
  passed every automated gate and then took 214 s on one case elevated, from a
  defect present since Phase 4 that a runner's small idle process set can never
  express. Write any time-based criterion in the unit it stands for (LESSONS
  #16): "14 green nights" measured the calendar, not the fuzzing; gate on
  cumulative effort, coverage plateau and zero findings instead.
- Keep the C runnable as the oracle through one release overlap; only then retire.
- Ship the `DIVERGENCES.md` as user-facing release notes ("behaviors we
  deliberately changed, and why") — the security fixes are a *feature*.
- **Release mechanics** — [`CI-AND-RELEASE.md`](CI-AND-RELEASE.md): a release
  trigger with a human-button fallback, permissions preflighted (LESSONS #14);
  the published release verified from its public page; the API quota treated
  as a budget; and one `concurrency` group per tag, the checksum written by
  the run that uploads the asset (LESSONS #22).

**Entry criteria:** all target modules merged & gated.
**Exit criteria:** Rust is the shipped artifact; supply-chain clean; divergences
published; C archived (not deleted until an overlap release proves parity).
**Artifacts:** release, `DIVERGENCES.md`, final `progress` table.
**lsof failure modes this prevents:** big-bang deletion before parity; lsof-rs
kept both trees side by side — preserve that discipline.

---

## Cross-cutting safety controls (apply continuously)

| Control | Harness / mechanism | Gate |
|---|---|---|
| No `unsafe` in pure logic | `#![forbid(unsafe_code)]` on every target root of `core`, checked by `unsafe-audit/check_forbid_unsafe.py` (LESSONS #065) | **hard-fail CI** |
| Every `unsafe` justified | `unsafe-audit/audit_unsafe.py` | **hard-fail CI** |
| No UB at the FFI boundary | `sanitizers/run_sanitizers.sh` (Miri, ASan, TSan) | CI |
| No panics on untrusted input | `fuzz/` (`cargo-fuzz`) | CI smoke + nightly deep |
| No vulnerable/untrusted deps | `supply-chain/run_supply_chain.sh` (`cargo audit`,`cargo deny`) | CI |
| No silent behavior drift | `differential/diff_run.py` + `DIVERGENCES.md` | CI |
| Cases that check something | `port-mutation/mutate_port.py`, the mutants committed with the change; `--apply-only` on every PR (LESSONS #083) | per change + CI |
| Cost close to the C's | `perf/perf_gate.py` (wall-time ratio over the matrix), or a gate of the port's own under a load it creates: lsof-rs's matrix needs fixtures this runner cannot start, and a cost that scales is invisible at ambient scale (LESSONS #061, #062) | CI |
| Matrix covers the C's surface | `coverage/coverage_gate.py` (inventory vs matrix), **run once per platform** with `--platform` — a waiver whose reason names a platform (`platforms = [...]`) expires the day that platform is added, silently unless scoped (LESSONS #18) | CI |
| The mandated ledgers exist | `ledgers/check_ledgers.py` — progress file, divergence ledger, ≥1 fuzz target, a sanitizer job, and a sanitizer run per tracked unit (LESSONS #19, #21) | CI |
| The threat model is filled in | `threat-model/check_threat_model.py THREAT-MODEL.md` | **hard-fail CI** |
| Lints as errors | `clippy -D warnings` (+ overflow/cast lints) | CI |
| Don't re-port a C vuln | `c-flaw-scan/scan_c_flaws.py` at Phase 0 | review |

See `harnesses/ci/porting-ci.template.yml` for the wiring (control-coverage checks
it in `check-kit`) and
`make -C porting-kit check-kit` to smoke-test every harness.

**When a gate can only run in CI**, land it *observe-first* and promote it on
consecutive log-verified green runs, in its own PR (LESSONS #9, #13). The four
traps — a distinct exit code for infra errors, a superseded run is not a passed
run, an observing job's status is meaningless, and a trial arm belongs in its
own job because a job's timeout crosses `continue-on-error` (LESSONS #055) —
are in [`CI-AND-RELEASE.md`](CI-AND-RELEASE.md).
---

### Renaming the port

Three passes, never one (LESSONS #20): inventory case-insensitively, convert
by identifier context, protect published names; then verify by executing and
adversarially. The procedure is in [`CI-AND-RELEASE.md`](CI-AND-RELEASE.md).

## The compounding loop

Every port **ends with a retrospective** (`PROMPTS/90-retrospective.md`) that
diffs lived experience against this playbook and patches it. New lessons append
to `LESSONS.md` with the section they amended. The kit is never "done" — it is
the running sum of every port it has survived.
