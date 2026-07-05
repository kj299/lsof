# C-to-Rust Migration Playbook — Best-of-Both Synthesis

*Merges two independently-developed sources that converged on the same backbone:*

1. **The TRACTOR-hardened playbook** (your document) — a four-step migration plan
   sharpened with the DARPA TRACTOR Round 1 evaluation (MIT Lincoln Laboratory,
   Feb 2026), a six-performer study with hard numbers. This supplies the
   *what and why, with evidence*.
2. **An executable "porting kit"** distilled from a real completed C→Rust port
   (winlsof — `lsof` reimplemented in Rust) plus its four self-patching
   retrospectives. This supplies the *how*: runnable harnesses that mechanically
   enforce the plan, a proactive flaw-hunt, and a loop that improves the playbook
   after every port.

**Why the merge is trustworthy:** the two were built from opposite evidence bases
— TRACTOR from watching six funded teams, the kit from one project's scar tissue
— and they agree on the spine (semantic-equivalence-over-build, test-harness-first,
leaf-first order, `forbid(unsafe_code)` + FFI-wrapper split, unsafe-op metrics,
surface-the-UB). Independent convergence at n=6 and n=1 on the same structure is
about as strong as methodology evidence gets. The kit's contribution is to make
that structure *executable and self-correcting*; TRACTOR's is to *prove it and
fill the gaps* (C→C preconditioning, the library test model, held-back vectors,
the performance envelope, LLM-loop discipline).

Throughout, **`Adds:`** callouts mark what the executable kit contributes on top
of the TRACTOR-confirmed content, so you can see exactly what is new.

---

## The one reconciliation to make up front: equivalence vs. hardening

TRACTOR scores "correctness" as **behavioral equivalence to the C** under test
vectors, and an *unprompted* divergence lowered a performer's score. A
safety-hardening rewrite, by contrast, sometimes *wants* to diverge — when the C
has UB or a CWE-class bug, faithfully re-implementing it is a failure, not
fidelity. These are not in conflict; they meet exactly at TRACTOR's own UB policy.
Resolve it once, explicitly:

> **Behavioral equivalence to C is the default and the scoring standard.** The
> only sanctioned divergences are (a) inputs that were *already* corrupting memory
> in the C, and (b) documented security fixes. Every such divergence is recorded,
> in writing, in a **divergence ledger** and surfaced to users. An *unexplained*
> divergence is a regression and fails the gate; a *ledgered* one is a feature.

This is precisely TRACTOR's UB-policy option (2) ("convert to a detectable failure;
diverges only on already-corrupting inputs") promoted to a first-class,
machine-checked artifact (`Adds:` below). Equivalence-first keeps you honest;
the ledger keeps the hardening controlled.

---

## Step 0 — Precondition the C (C→C), *before* any Rust

The most portable idea in the TRACTOR report: reshape the C so it translates into
safe Rust cleanly, verify with the existing C test suite, *then* translate.

- **Localize global state as a C refactor.** Gather every mutable global (and its
  type closure) into one context struct, instantiate it once in `main`, and thread
  a pointer through the call graph. A global that reaches Rust as `static mut` is
  unsafe at every access; the same global threaded as a struct field becomes an
  ordinary `&mut` borrow. Fallback for globals you cannot thread (Yale PROCTOR):
  rewrite `static mut` into `Cell`/`RefCell`/thread-locals.
- **Reduce aliasing pressure.** Lift subfield arguments (`foo(x, x->y)` →
  `foo(x, tmp)`), split multi-variable declarations, simplify pointer arithmetic
  into array indexing — these are the patterns the borrow checker rejects later.
- **Decide the macro/`#ifdef` story now.** Preprocessing-based translation
  silently collapses the build to *one* configuration and discards the other
  `#ifdef` paths. Either translate each configuration and merge under Rust
  `#[cfg]` (UW's Hayroll approach), or consciously pick one and document what is
  dropped. Never let it happen by accident.

**`Adds:` Proactively hunt the C's vulnerabilities here, not just react to them.**
Before translating, scan the C for the classic sink classes (unbounded copies,
non-literal format strings, integer-overflow-before-malloc, `alloca`,
`system`/`popen`, TOCTOU) and triage each: *does the port close it?* Confirmed
flaws become planned divergence-ledger entries. TRACTOR's UB handling is
reactive-at-the-callsite; a Phase-0 scan makes it a deliberate inventory so a CWE
isn't faithfully re-ported. (Practical note from the kit: tune any such scanner
for signal-to-noise against the *real* target first — a naive format-string check
produced 828 false positives on a 90-KLOC C tree, burying ~215 real candidates,
until it was fixed to locate the actual format-position argument. A scanner that
cries wolf gets muted.)

**`Adds:` Write a one-page threat model here too:** trust boundaries (which entry
points take untrusted input → fuzz-first list), privilege transitions (→ audit
hotspots), and explicit non-goals. It scopes what "secure" means before code.

---

## Step 0.5 — Build the test-vector harness *before* translating anything

TRACTOR's central finding: **most failures were at the semantic-comparison stage,
not at build time.** Every performer produced Rust that compiled; what separated
98.7% correctness (Yale) from 48% (UW) was behavioral equivalence under test
vectors. "It builds" tells you almost nothing. So the harness comes first.

- Capture I/O vectors per module/entry point: CLI args, stdin, expected
  stdout/stderr (with regex tolerance for float formatting), return codes, and —
  for libraries — input state and expected output state (arguments, return values,
  environment, file contents).
- **Hold back a hidden vector set.** Performers failed hidden tests 21.8% vs 16.9%
  for public ones; if an LLM is anywhere in the loop it *will* overfit to the
  vectors it can see. Reserve a withheld set for final acceptance only.
- **Validate every vector against the original C first.** Run each vector against
  the C baseline in CI *before* it is allowed to judge a translation. A wrong
  vector that "passes" teaches you nothing.
- Generate vectors for the known-ugly inputs — boundary indices,
  `INT_MAX`/`CHAR_MAX`, empty buffers — and specifically for the UB shapes TRACTOR
  probed: stack buffer overflow via unchecked upper bound, signed-char overflow,
  array underflow from an off-by-one index calculation.
- Crib MIT LL's public JSON schema and the **`cando`** harness (loads a `.so`, C or
  Rust interchangeably, through a per-test harness and checks conformance) — it is
  exactly the side-by-side you want, and it is public in the TRACTOR test corpus.

**`Adds:` the runnable comparison layer.** The kit ships a differential harness you
can point at both binaries (or at `cando` for libraries) that mechanizes the
judging TRACTOR describes:
- **Symmetric output normalization** — mask the *nondeterministic* noise (PIDs,
  timestamps, pointer/handle values, ephemeral ports) identically on both sides,
  so real regressions surface and noise doesn't fake one. (Whatever you erase from
  the C you must erase from the Rust, or you manufacture a divergence.)
- **Exit-code equality is part of the verdict, not just stdout.** A rewrite that
  prints the right thing but returns the wrong status is *not* a match — programs
  branch on exit codes. (The kit shipped a differential that ignored this at first;
  it was a real hole.)
- **A per-case timeout is the liveness backstop.** A hang is not UB, so Miri and
  the sanitizers won't catch it; a wedged run must be marked and failed. Treat a
  timeout as a design smell (an unbounded blocking call on the hot path) and
  *design it out*, don't wrap it.
- **The divergence ledger is machine-read.** A case listed in the ledger as a
  known-intentional fix is suppressed; every other divergence fails CI.
- **Executable vs. library split** (from TRACTOR Step 2, mechanized here): CLI
  differential for executables; a `cando`-style function-level harness for
  C-ABI libraries. Pick the harness per artifact.

---

## Step 1 — Generate bindings and unify the build (reproducibly)

`bindgen` + a unified Makefile/CMake so `cargo build` output feeds the same link
step as the C objects (corrosion, or a custom target invoking cargo, both work).
Two evaluation-driven additions:

- **Make builds reproducible and self-contained.** Several performer failures
  traced to container-local or unreleased dependencies (Galois shipped a
  translation depending on an unreleased `c2rust-bitfields` that wouldn't build
  outside their container). Pin every crate version, vendor anything unusual, and
  verify the Rust artifacts build on a **clean machine that isn't your dev
  environment.**
- **Set binary-size expectations with stakeholders now.** Rust statically links
  its stdlib where C dynamically links glibc, so TRACTOR translations ran ~27–30×
  the C binary size (240×+ for raw C2Rust). Mostly fixed overhead, not a defect —
  but flag it early for constrained targets.

**`Adds:` a supply-chain gate that *enforces* the pinning.** Pinning is necessary
but only a gate makes it hold: run `cargo audit` (no open RUSTSEC advisories) +
`cargo deny` (licenses allow-listed, sources restricted to crates.io, no
banned/duplicate crates) in CI. A rewrite for safety that imports unsafety through
its dependency tree has failed. Also do the kit's **environment preflight** here:
confirm the toolchain target actually links (an MSVC-vs-GNU mismatch cost real
time) and that the build dir isn't a synced/locked folder (a cloud-sync lock on
`target/` produced spurious `os error 5` failures).

---

## Step 2 — Swap `main`, with the executable/library distinction explicit

- **Executables** give you freedom: once `main` is Rust you may refactor
  signatures, restructure modules, and idiomatize aggressively — the only contract
  is I/O behavior. Take advantage of it.
- **Libraries** (anything exposing a C ABI) must preserve symbols and signatures
  so the Rust `.so` is a drop-in replacement — the property that makes gradual
  migration work — which necessarily requires `unsafe` at the boundary.

**FFI splitting** (Galois and Intel arrived at it independently): every exported
entry point becomes (a) a thin `#[no_mangle] extern "C"` wrapper that *is allowed
to be unsafe* — it converts raw pointer + length into slices, C strings into
`&str`/`CStr`, and nothing else — and (b) an internal, fully safe Rust function
holding all the logic. The wrapper is a few mechanical lines you audit by eye; the
logic never touches a raw pointer. This is the structure that pays off in Step 4,
because the most common unsafe residue (`CStr::from_ptr`, `slice::from_raw_parts`,
pointer `offset`/`add`) is exactly what the wrapper confines.

**`Adds:` RAII for every OS resource** — the single biggest safety win in the real
port. Wrap each handle/fd/lock/privilege in a type that releases on `Drop`
(`OwnedFd`, `OwnedHandle`, a `PrivilegeGuard` that drops the privilege on scope
exit). This kills the use-after-free / double-free / leak / privilege-held-too-long
classes *by construction* — the C `close()`/`free()`/drop-privilege bug family
simply stops being expressible. Keep privileges just-in-time and scoped to the one
call that needs them, never held globally.

---

## Step 3 — Translate module-by-module, in dependency order, behind a hard gate

- **Leaf-first, topological order** (Intel IDEAS). Build a dependency graph of the
  C definitions and translate bottom-up, so each new translation compiles against
  already-translated, already-*tested* Rust rather than stubs. Whole-project
  big-bang scored worst on correctness (UW, 48%): context pressure grows and error
  provenance vanishes — a break could be any of 10,000 lines. Granular translation
  localizes every failure to one definition. Pay the orchestration bookkeeping.
- **Forbid unsafe in the core, mechanically.** Intel's best safety result (1.55
  unsafe ops/test vs 13.6 at the other extreme) came from making `unsafe` a *build
  error* in the translation target — `#![forbid(unsafe_code)]` on the internal
  crate (or `-D unsafe-code` in CI), FFI wrapper module exempt. This is a gate that
  forces safe signatures (slices, not pointer/length; `Option`, not nullable
  pointer) *at generation time*, not a lint you triage later. Critically, TRACTOR
  found correctness and safety are **not** in tension: Intel and Galois hit ~90%
  correctness *at the lowest* unsafe counts.
- **Guard the known drift classes** at every site, human- or LLM-translated:
  integer signedness/width (C `char` may be signed; Rust defaults differ), overflow
  (C unsigned wraps; Rust panics in debug, wraps in release — choose `wrapping_*` /
  `checked_*` / panic per site), bitwise/shift/rotation reproduced exactly, loop
  bounds and indexing, `errno` interactions. This matters most in bit-twiddling,
  security-critical, performance-sensitive code (the P01 SPHINCS+ shape), where a
  silently different overflow is a broken primitive. Add test vectors at every
  integer boundary in such code.
- **If an LLM is in the loop** (the convergent practice across all four LLM-using
  performers): scope context tightly (one definition plus its already-translated
  dependencies, never the whole project); state non-negotiable constraints in the
  prompt ("exactly equivalent, no simplifications, preserve this signature"); feed
  compiler/test output into *bounded* repair loops with an iteration cap; demand
  machine-parseable output. Use Wisconsin's cheap two-phase trick: first a
  *report-only* discrepancy analysis between C and Rust (no code changes allowed),
  then a separate targeted fix pass — it stops the model freeform-rewriting code
  that was fine. Keep the model pluggable; treat prompts as versioned, tested
  artifacts, not chat messages.
- **Validate with the vector suite after every unit lands**, not just at the end.
  Compile/check-driven pipelines are auditable but let semantic drift accumulate
  invisibly until a late comparison stage catches it.
- **Diversity beats any single method.** No TRACTOR test was failed by every
  performer, and most failures were unique to one translator. For your hardest
  modules, produce *two* candidate translations by different methods
  (C2Rust+refinement and constrained-LLM, say) and let the vector suite pick the
  winner. It is genuinely cost-effective.

**`Adds:` runnable enforcement of the "hard gate."** `forbid(unsafe_code)` covers
the core; wire the rest as CI gates the kit ships:
- **Unsafe-audit (toolchain-free, hard-fail):** every `unsafe {}` block needs a
  `// SAFETY:` justifying its invariants; CI fails otherwise. On a shipped backend
  this found **51 of 131 real unsafe blocks undocumented** — exactly the residue
  that accretes without a gate. Pair it with clippy's `missing_safety_doc`
  (every `pub unsafe fn` needs `# Safety`) and `undocumented_unsafe_blocks` as the
  compiler-side cross-check — and make sure they are actually *enabled* (both are
  allow-by-default; a "delegated to clippy" control that clippy never runs is not a
  control).
- **Miri + ASan/UBSan/TSan** over the unsafe/FFI layer — the UB the compiler can't
  see. TSan specifically for threaded code (shared-resource races are the class the
  liveness/hang bugs hide behind).
- **Fuzz every parse/input entry point** (cargo-fuzz): any panic/crash on arbitrary
  bytes is a release blocker. This is the memory-safety property the rewrite claims
  — verify it on exactly the input surfaces, don't assume it.
- **Track unsafe-op count per module** (raw-ptr deref, unsafe call, `static mut`,
  union field — TRACTOR's four categories) as a status table, so encapsulation
  progress is a metric, not vibes.
- **Scaffold observability (a trace/log switch) on day one.** In the real port it
  was added reactively, at fix #4 of a 5-commit hang; up front it makes the first
  hang diagnosable in minutes.

---

## Step 4 — Encapsulate remaining unsafe, with an explicit written UB policy

Wrapping raw memory behind safe types is right; TRACTOR's UB analysis adds the part
most plans skip — **decide, in writing, what the team/translator does on
encountering UB in the C.** In ascending order of risk:

1. **Preserve the UB in an `unsafe` block with a loud comment.** Least safety
   gained, but behavior matches C exactly and the hazard is visible/greppable.
2. **Convert it to a detectable runtime failure** — let bounds checks panic, or add
   an explicit check that returns an error. Diverges from C only on inputs already
   corrupting memory; failures are noisy instead of silent.
3. **Silently patch the semantics** (e.g., skip the offending input). The most
   dangerous option — a latent, undocumented behavior change comparative testing
   may never trigger.

**Prefer (2), tolerate (1), prohibit (3). Whatever the choice, the translation must
*surface* the UB** — comment, diagnostic, or panic. A translator that doesn't
visibly react to a known overflow simply didn't see it.

Mechanics (Yale PROCTOR, which validated at 98.7%): retype raw pointers to
references/slices optimistically and demote only the ones that violate borrow
rules, iterating to a fixed point; replace libc I/O idioms with stdlib equivalents;
eliminate `static mut` via `Cell`/`RefCell`/thread-locals; run clippy fixes to a
fixed point.

**`Adds:` the divergence ledger is that "written policy," mechanized.** Option (2)
and every security fix lands as a `- [x] <case>: <why + CWE>` entry that the Step
0.5 differential reads and suppresses — so the *decision* is enforced (unledgered
divergence = failing CI) and *shipped* to users as release notes ("behaviors we
deliberately changed, and why"). The security fixes over the C are a feature; say
so.

---

## Cross-cutting controls (net-new from the executable kit)

These aren't in the TRACTOR playbook and are worth adding wholesale:

- **A security-controls checklist** applied per-module and per-release: unsafe
  contained + documented, no UB (Miri/sanitizers), no panic on input (fuzz), clean
  supply chain, least-privilege, no secrets in artifacts, signed/checksummed
  release, current threat model.
- **The compounding loop.** A static playbook rots. End every port with a
  retrospective that *patches this document*, backed by an append-only `LESSONS`
  log (date, codebase, lesson, section amended). The kit has already improved
  itself four times this way. **Meta-lesson from those passes: run the tools
  against the real target — the gaps live in the harnesses, not the prose.** Three
  of four self-audits found defects in the *tooling* (a noisy scanner, an unwired
  gate, an under-checking differential), none from re-reading the plan. A dry-run
  that doesn't execute the harnesses against the actual code is theater.

---

## Performance envelope (calibration + a gate)

Across all six TRACTOR performers on Battery 01: runtime overhead vs C clustered at
a **3–5% median** (max ~1.3×), memory overhead near-zero at the median, throughput
~0.2–2 hours/KLOC. **`Adds:` make it a gate** — if a translated module is >1.3×
slower than the C, fail and investigate a *specific* cause (an accidental copy, a
missed release build, bounds checks in a hot inner loop worth restructuring). It is
not "the cost of Rust."

## Milestone validation targets

Mirror the program's escalation to prove the *pipeline*, not just a module: start
with **Battery-01-class** code (stack/static pointers, no `malloc`, simple structs,
errno-style errors), then a **P00-class** target (numerical/array-heavy library,
~500 LOC — Perlin-noise analog), then a **P01-class** target (bit-manipulation-
heavy, security-critical, performance-constrained — SPHINCS+ analog). If the
pipeline holds through the third class it will generalize; the report's clearest
warning is that **success on the easy class overstates readiness for the hard
ones.**

---

## Who contributed what (provenance)

- **From TRACTOR (evidence + the gaps the kit lacked):** the semantic-equivalence-
  over-build framing and its numbers; Step 0 C→C preconditioning; the library /
  `cando` function-level test model; held-back + C-validated vectors; the
  executable/library split; the LLM-in-the-loop discipline and the diversity
  principle; the performance envelope and milestone escalation; the three-option UB
  policy and PROCTOR mechanics.
- **From the executable kit (the runnable how + hardening):** runnable, self-testing
  harnesses (differential with normalization/exit-code/timeout/ledger, golden
  corpus, fuzz scaffold, unsafe-audit hard-gate, sanitizer runner, supply-chain
  gate, progress tracker, CI template); the proactive C-vulnerability hunt; RAII
  resource wrappers; the divergence ledger as a machine-checked artifact; the
  security-controls checklist and threat model; day-one observability; and the
  compounding retrospective loop with its "run the tools against the real target"
  meta-lesson.

*Sources for the evidence base: MIT Lincoln Laboratory, "First Test & Evaluation
Report for TRACTOR C to Rust Translators" (Feb 2026); DARPA TRACTOR program page;
DARPA-TRACTOR-Program/PUBLIC-Test-Corpus (Battery 01, P00_perlin_noise,
P01_sphincs_plus, `cando`, evaluation scripts). The executable layer is generalized
from a completed C→Rust reimplementation and its four self-patching retrospectives.*
