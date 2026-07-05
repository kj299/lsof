# Operating Guide — running a port with this kit efficiently, securely, well

Recommendations for actually *using* the Porting Kit on a real rewrite: how to
spend tokens and compute wisely, how to harden beyond the baseline, how and when
to reach for each skill, and an honest backlog of what to improve before this is a
v1.0 you'd stake a migration on. Read after `PLAYBOOK.md`.

---

## 0. Readiness assessment (candid)

**Solid today** — proven on a real completed port and self-tested:
the phased playbook; the executable harnesses (`make check-kit` green); the
`forbid(unsafe_code)` core / audited `sys` split; the differential + divergence
ledger; the unsafe-audit hard gate; the compounding LESSONS loop; the skills suite
with a mechanical integrity check.

**Provisional** — designed and documented, not yet battle-tested end-to-end:
the **library** path (the differential is executable-shaped; C-ABI libraries need
the `cando`-style function-level harness, §5 P0); C→C **preconditioning** is prose,
not tooling; the **performance** gate is a number in the playbook, not a harness;
**held-back vectors** and **C-baseline vector validation** are described, not wired.

**Bottom line:** ready to *drive an executable port today* and to *structure* a
library port; not yet a turnkey library-migration pipeline. §5 is the path to that,
prioritized. Lifting to its own repo is reasonable **now** if you ship it with this
honest maturity note and the P0 backlog visible — not as "done," but as "v0.x,
proven spine, known edges."

---

## 1. Token-use optimization (agent-driven ports)

The kit is designed so an agent reads *verdicts, not corpora*. Lean into that:

- **The harnesses are your token firewall.** Never read a C tree or a diff into
  context to "check" it — run the tool and read its summary. Use the machine
  outputs: `audit_unsafe.py --json --quiet`, `scan_c_flaws.py --json`,
  `diff_run.py --json`. `diff_run` only emits a diff for a DIVERGE case, so a
  green run costs a line, not a file.
- **Delegate reads to subagents; keep the conclusion.** Mapping a module,
  inventorying globals, reading a subsystem → spawn a subagent that returns a
  structured summary (the map), not the files. The orchestrator holds
  `progress.json` + the maps, never the source.
- **Scope context per definition** (also a *correctness* rule — TRACTOR: big-bang
  translation scored worst). Feed the module loop one definition + its
  already-translated deps, never the whole project. Smaller context = fewer tokens
  *and* fewer hallucinated cross-references.
- **`progress.json` is the session anchor.** A resumed session reads the tracker
  (tiny) to orient in seconds instead of re-deriving state from the codebase.
- **Cap the repair loop.** Bounded LLM fix iterations (TRACTOR's practice) — an
  uncapped compile→fix→compile loop burns tokens on diminishing returns; 3–5
  iterations then escalate to a human/spike.
- **Batch independent tool calls** in one turn; don't re-read a file you just
  edited (state is tracked); prefer `--quiet`/`--json` for agent eyes and the
  human tables only when reporting to the user.
- **Two-candidate translation is selective**, not default — spend the extra tokens
  only on the hardest modules where the vector suite picks a winner.

## 2. Efficiency considerations (compute, CI, wall-clock)

- **Path-scope every workflow** (LESSONS #5) so a change runs only the pipeline it
  can affect. The single biggest CI-waste fix.
- **Tier the slow gates:** fuzz = 60s smoke per target in CI, deep run nightly;
  Miri/ASan/UBSan on the `sys`/changed crates per-PR, full sweep nightly. Don't pay
  the whole safety matrix on every push.
- **Leaf-first order is an efficiency lever, not just correctness** — it localizes
  every failure to one definition, so you debug one thing, not a 10k-line blast
  radius. Fewer wasted cycles.
- **Differential per-unit, not just at the end** — catching drift at the module
  that caused it is far cheaper than bisecting it later.
- **`core` builds/tests on the cheap default runner** (no target setup) → fastest
  feedback loop; keep the logic there.
- **Pin + vendor deps** so a clean-machine build never becomes a re-debug session.
- **Spike hazardous modules first** — the winlsof hang cost 7 reactive commits vs
  ~1 day up front. The most expensive inefficiency in the whole retrospective.

## 3. Security hardening (beyond `SECURITY-CHECKLIST.md`)

The checklist is the floor. To make this a *security* rewrite you'd defend:

- **Vet dependency code, not just advisories.** Add `cargo vet` (or `cargo crev`)
  on top of `cargo audit`/`cargo deny` — provenance/review of the actual crates,
  not only known-CVE and license gates.
- **Pin GitHub Actions by commit SHA, not tag** (`uses: actions/checkout@<sha>`),
  set minimal `permissions:` (the template uses `contents: read` — keep it), and
  `persist-credentials: false`. A tag is mutable supply chain.
- **Ship an SBOM + auditable binary:** `cargo auditable build` embeds the
  dependency graph in the binary; `cargo cyclonedx` emits an SBOM. Consumers can
  then scan what you shipped.
- **Sign releases** (cosign / minisign) in addition to the SHA-256 checksum.
- **Fuzz with the sanitizer on** (cargo-fuzz runs ASan by default) and **fuzz the
  threat-model's untrusted boundaries first**. Use `arbitrary` for typed fuzzing of
  structured parsers, and **cap allocations derived from untrusted length fields**
  (integer-overflow-before-alloc is a top C class you must not re-port).
- **Differential fuzzing** (§5 P1): feed the *same* fuzz input to the C oracle and
  the Rust and compare — finds semantic divergences the fixed matrix never covers.
  The highest-value single addition for a security-critical port.
- **Stricter unsafe lints:** beyond `undocumented_unsafe_blocks` / `missing_safety_doc`
  (wired), consider `clippy::multiple_unsafe_ops_per_block` (isolate each unsafe op),
  `clippy::transmute_ptr_to_ptr`, `clippy::as_conversions` in the `sys` crate.
- **Miri strictness at the FFI seam:** run Miri with strict provenance and the
  alignment checks on the `sys` crate.
- **Secret hygiene as a gate:** run `gitleaks` in CI; assert no tokens/keys land in
  the binary, logs, or committed artifacts.

## 4. Leveraging the skills — strategy (per-skill reference: `skills/README.md`)

The skills are the operational surface; use them, don't re-derive their steps.

**When, across a rewrite** (map the skill to the phase):

| Phase | Skill | Cadence |
|---|---|---|
| Project start | `porting-kit-kickoff` | once |
| Phase 0 vuln hunt | `porting-kit-cflaw-scan` | once (re-run per subsystem) |
| Phase 2 oracle | `porting-kit-oracle` | once, before any Rust |
| Phase 4 per module | `porting-kit-module` | **repeated — the hot path** |
| Pre-merge / "is it safe?" | `porting-kit-audit` | per module + per release |
| Port/phase done | `porting-kit-retrospective` | once per phase — **never skip** |

**How, efficiently:**
- `cflaw-scan` and `oracle` are independent → run in parallel.
- `module` is the loop you spend the port in; drive it per leaf in topological
  order, delegating the C-reading to a subagent and keeping the translation +
  gate results.
- `audit` is cheap (runs tools, reads verdicts) — gate every merge with it.
- `retrospective` is what makes the kit compound; it patches the playbook, the
  harnesses, **and the skills** (integrity), then appends LESSONS.

**The one-line recipe:** `kickoff → (cflaw-scan ∥ oracle) → for each leaf: module →
audit → retrospective`.

## 5. Improvements backlog (the path to v1.0, prioritized)

**P0 — needed before a *library* port or a security-critical claim:**
1. **`cando`-style function-level differential harness** for C-ABI libraries — the
   current differential is executable-shaped (argv/stdin→stdout+exit). Biggest gap.
2. **Performance gate harness** — measure module runtime vs the C median, fail >1.3×.
3. **Held-back vectors + C-baseline validation** in `golden.py` (`--holdout`, and
   "a vector must pass on C before it may judge Rust").

**P1 — materially stronger:**
4. **Differential fuzzing** harness (C vs Rust on shared fuzz inputs).
5. **CI template hardening**: SHA-pin actions; split smoke/nightly for fuzz+sanitizers;
   add `cargo vet`, SBOM, `gitleaks` jobs.
6. **`scan_c_flaws.py` depth**: add double-free / use-after-free / uninitialized-read
   heuristics and `strncpy` non-termination / `snprintf` truncation; note its
   line-based checks can miss multi-line calls (the format-string check is already
   whole-file — extend the rest).
7. **A `porting-kit-precondition` skill** for Step 0 (C→C: global-state threading,
   aliasing reduction, `#ifdef` story) — currently prose only.

**P2 — polish / breadth:**
8. `normalize.py` rules as a per-project data file (currently code constants).
9. `progress.py ingest` to parse harness JSON directly and auto-advance gates.
10. Document the Windows/cross-platform caveats (sanitizers/Miri assume a Linux
    nightly toolchain).
11. A `porting-kit-diff-fuzz` skill once #4 lands.

**How the kit closes these:** each is a candidate for a normal port's
`porting-kit-retrospective` pass (the compounding loop is the delivery mechanism —
a real port will surface which of these actually bite first, and LESSONS will
record it). Nothing here is a redesign; all are additive to the proven spine.

---

*This guide is itself subject to the compounding rule: when a port teaches a better
way to spend tokens, compute, or risk, update it and log the lesson in `LESSONS.md`.*
