---
name: porting-kit-audit
description: Run the full safety-gate suite against a Rust port and report a gate-status table. Use before a merge or release, or whenever the user asks "is this port safe / secure / ready", to verify unsafe is contained + documented, no UB, no panic on input, clean supply chain, and no silent behavior drift.
---

# Porting Kit — safety-gate audit

Runs every control in `porting-kit/SECURITY-CHECKLIST.md` and reports pass/fail.
Nothing here is optional for a "safe" verdict; a module that compiles and matches the
oracle is at gate 2 of 6, not done.

## Procedure — run each gate, collect results
1. **Unsafe contained + documented** (toolchain-free hard gate):
   `python3 porting-kit/harnesses/unsafe-audit/audit_unsafe.py crates/`  → must be 0
   undocumented. (On a real backend this found 51/131 undocumented — exactly what a
   gate catches.) Plus `cargo clippy --all-targets -- -D warnings -D
   clippy::missing_safety_doc -D clippy::undocumented_unsafe_blocks`.
2. **No UB:** `bash porting-kit/harnesses/sanitizers/run_sanitizers.sh all .`
   (Miri + ASan/UBSan; TSan for threaded code — the class that hides the hang bugs.)
3. **No panic on input:** `cargo fuzz list` then a 60s smoke per target. Any crash blocks.
4. **Clean supply chain:** `bash porting-kit/harnesses/supply-chain/run_supply_chain.sh .`
   (`cargo audit` + `cargo deny`: no advisories, licenses allow-listed, crates.io-only.)
5. **No silent drift:** the differential shows MATCH or a ledgered divergence
   (`diff_run.py ... --ledger DIVERGENCES.md`).
6. **Least privilege / no secrets / signed build / current threat model** — walk the
   per-release section of `SECURITY-CHECKLIST.md`.
7. **Performance sanity** (synthesis): fail if a module is >1.3x the C median runtime —
   that's a specific bug (a copy, a missed release build, bounds checks in a hot loop),
   not "the cost of Rust".
8. **CI hygiene** (LESSONS #5): confirm each language/subtree's CI is path-scoped so
   unrelated changes don't trigger heavyweight jobs or leave PRs misleadingly
   "unstable"; see `porting-kit/harnesses/ci/porting-ci.template.yml`.

## Report
Emit a gate-status table via `python3 porting-kit/harnesses/progress/progress.py show`
and call out any red gate with the exact command to reproduce it. Do not report "safe"
unless every applicable gate is green (or a divergence is ledgered with justification).

## Integrity
Gate commands must match the harnesses and SECURITY-CHECKLIST. Fix the reference on
drift; re-run `make -C porting-kit check-kit`.
