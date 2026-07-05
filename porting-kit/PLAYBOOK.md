# PLAYBOOK — porting a C codebase to Rust, safely

A repeatable, codebase-agnostic procedure for rewriting C in Rust with **safety
and security as the primary goal** — distilled from the winlsof port (see
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
  --init` seeds the module table from this.
- **Scan the C for vulnerability classes** — `harnesses/c-flaw-scan/scan_c_flaws.py`
  flags the classic sinks (unchecked `memcpy`/`strcpy`/`sprintf`, `alloca`,
  integer-overflow-before-`malloc`, `system`/`popen`, format-string,
  `gets`, TOCTOU pairs). Every hit becomes a note on the owning module: *do not
  port this bug — fix it, and log the fix as an intentional divergence.*
  A scanner is only useful if it is *trusted*: tune it for signal-to-noise
  against the real target before relying on it — a check that cries wolf gets
  muted, and the real flaws drown (LESSONS #2: the format-string check once
  produced 828 false positives on lsof, burying ~215 real candidates).
- **Classify the FFI/syscall surface by failure mode** (LESSONS #1). For each
  external call the port will make, record three properties: can it **block
  indefinitely** (→ needs a timeout / worker thread / a design that avoids it),
  does it need **privilege**, does its behavior **vary by OS/version**? This is
  what makes Phase 1's "spike the scary module" rule actually fire. The winlsof
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
winlsof's phase order was sound; its one miss was not spiking the hang first.

---

## Phase 2 — Establish the oracle (before any Rust)

**Goal:** a reference you can diff against — while remembering it may be wrong.

**Do:**
- Lock the C binary at a known commit. Capture golden outputs across a
  **documented input matrix** (`harnesses/differential/input-matrix.example.toml`)
  with `harnesses/golden/golden.py capture`.
- **Detect oracle nondeterminism up front** — `golden.py` runs each input N times
  and flags fields that vary (PIDs, timestamps, addresses, ordering). Those feed
  the normalization rules (`harnesses/differential/normalize.py`), so a real
  regression isn't masked by noise and noise isn't mistaken for a regression.
- If the reference binary **cannot run on your dev/target environment** (winlsof:
  C lsof doesn't run on Windows), substitute:
  - **structural golden tests** for output *format* (columns, field codes, JSON
    shape), and
  - **independent oracles** for the *data* (native tools that report the same
    facts a different way).
- **Harden the harness for its host** (LESSONS #1). The test harness is software,
  and it runs in a shell with its own encoding/quoting model that *will* bite —
  winlsof spent six commits on PowerShell-5.1 / Windows-1252 breakage in the
  harness itself. Two defenses: write kit-level harnesses in a portable language
  (these are Python + POSIX sh on purpose, not the target's shell), and pin the
  tool's default output to the lowest-common-denominator encoding of the target's
  default shell (winlsof: ASCII default, UTF-8 opt-in).
- Stand up an **intentional-divergence ledger** (`DIVERGENCES.md`, template in
  the skeleton): every place the Rust will *deliberately* differ from C —
  starting with the Phase-0 flaw scan's findings.

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
target actually links here (winlsof lost time to an MSVC-vs-GNU linker mismatch)
and that the build directory is not a synced/locked folder (OneDrive locked
`target\` → `os error 5`). Cheap checks that prevent days of "is it my code or my
machine?".

**Entry criteria:** oracle in place.
**Exit criteria:** workspace builds; `core` is `forbid(unsafe_code)`; unsafe-audit
gate wired into CI (`harnesses/unsafe-audit`); trace logger present; environment
preflight clean.
**Artifacts:** the workspace; CI config from `harnesses/ci/porting-ci.template.yml`.
**lsof failure modes this prevents:** scattered `unsafe` (winlsof kept 0 in core /
144 in the sys layer — but only 91 documented; the gate makes the gap a build
failure). Tracing added reactively at hang-fix step 4 of 5.

---

## Phase 4 — The module port loop (per module)

**Goal:** each module ends safer than its C original, proven, before merge.

For a hazardous module (flagged in Phase 1), **spike first**: a timeboxed
experiment on the one scary syscall/idiom to learn its behavior (does it block?
need privilege? vary by version?) *before* committing to a design. Record the
result. This is the single highest-ROI habit in the retrospective.

**For a *research-grade* capability — one that might be impossible, not merely
hard** (winlsof: socket-FD correlation, byte-range locks, AF_UNIX/raw) — run the
**spike-and-gate ritual** instead of an open-ended attempt (LESSONS #1). It was
winlsof's biggest win: the hard gaps became the cheap ones. Steps: (a) rate
**effort** (S/M/L) and **confidence** a safe/public solution exists (Low/Med/
High); (b) write a **decision gate** *before* coding — the concrete signal that
says "stop, document as a platform limit"; (c) on hitting the gate, do a **pivot
check** — is there an adjacent, reachable goal? (winlsof's ETW spike couldn't get
the "real FD" but pivoted to extending `-i` to raw/ICMP/AF_UNIX, which shipped).
A closed sub-goal must not kill the shippable one beside it.

Then the loop — each step is a CI-enforced gate:

1. **Port** into `core` (or a safe wrapper in `sys`). Translate C idioms to Rust:
   the "call-twice-for-size" buffer dance → a growing `Vec` with length checks;
   pointer arithmetic over structs → slices + `repr(C)` with bounds; unions/FAMs →
   audited casts with a `// SAFETY:` proof; integer math → checked/`saturating`.
2. **Differential-test** against the oracle (`harnesses/differential/diff_run.py`).
   A divergence is a *triage*, not an auto-fail: {Rust bug → fix} vs {C bug →
   log in `DIVERGENCES.md`, keep the safe behavior}. The verdict is **stdout AND
   exit code** (LESSONS #4): a rewrite that prints the right thing but returns
   the wrong status is not a match — lsof exits 1 on no-match and scripts branch
   on it; `--ignore-exit` opts out for tools without stable codes. This gate is
   also the **liveness backstop** (LESSONS #1): a hang is not UB, so sanitizers
   won't see it — the harness's per-case timeout marks a wedged run as
   `<<TIMEOUT>>` and fails it. Treat a timeout as a design smell (an unbounded
   blocking call on the hot path) — the winlsof fix was to *avoid* the blocking
   call, not wrap it.
3. **Fuzz** the module's parse/input surface (`harnesses/fuzz/gen_fuzz_target.sh`
   scaffolds a `cargo-fuzz` target). Any crash/panic on untrusted input is a
   release blocker.
4. **Sanitize** (`harnesses/sanitizers/run_sanitizers.sh`): Miri over the pure
   logic and, for the `sys` layer, ASan/UBSan (and TSan if threaded). winlsof's
   worker-thread hang fix is exactly the class TSan/Miri reasoning catches.
5. **Unsafe-audit** (`harnesses/unsafe-audit/audit_unsafe.py`): every `unsafe`
   block has a `// SAFETY:` justifying its invariants — **hard fail** otherwise.
6. **Review & merge.** Update the `progress` table (the module advances
   ported → differential-passing → fuzzed → sanitized → unsafe-audited).

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
  `cargo audit` + `cargo deny`).
- Keep the C runnable as the oracle through one release overlap; only then retire.
- Ship the `DIVERGENCES.md` as user-facing release notes ("behaviors we
  deliberately changed, and why") — the security fixes are a *feature*.

**Entry criteria:** all target modules merged & gated.
**Exit criteria:** Rust is the shipped artifact; supply-chain clean; divergences
published; C archived (not deleted until an overlap release proves parity).
**Artifacts:** release, `DIVERGENCES.md`, final `progress` table.
**lsof failure modes this prevents:** big-bang deletion before parity; winlsof
kept both trees side by side — preserve that discipline.

---

## Cross-cutting safety controls (apply continuously)

| Control | Harness / mechanism | Gate |
|---|---|---|
| No `unsafe` in pure logic | `#![forbid(unsafe_code)]` on `core` | compile |
| Every `unsafe` justified | `unsafe-audit/audit_unsafe.py` | **hard-fail CI** |
| No UB at the FFI boundary | `sanitizers/run_sanitizers.sh` (Miri, ASan/UBSan/TSan) | CI |
| No panics on untrusted input | `fuzz/` (`cargo-fuzz`) | CI smoke + nightly deep |
| No vulnerable/untrusted deps | `supply-chain/run_supply_chain.sh` (`cargo audit`,`cargo deny`) | CI |
| No silent behavior drift | `differential/diff_run.py` + `DIVERGENCES.md` | CI |
| Lints as errors | `clippy -D warnings` (+ overflow/cast lints) | CI |
| Don't re-port a C vuln | `c-flaw-scan/scan_c_flaws.py` at Phase 0 | review |

See `harnesses/ci/porting-ci.template.yml` for the wiring and
`make -C porting-kit check-kit` to smoke-test every harness.

---

## The compounding loop

Every port **ends with a retrospective** (`PROMPTS/90-retrospective.md`) that
diffs lived experience against this playbook and patches it. New lessons append
to `LESSONS.md` with the section they amended. The kit is never "done" — it is
the running sum of every port it has survived.
