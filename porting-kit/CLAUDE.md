# CLAUDE.md — standing instructions for any kit-based repo

You are working in a repository that uses the **Porting Kit** (this directory) to
rewrite a C codebase in Rust. These rules are always in force.

## The one rule that makes the kit worth having

**Every port ends with a retrospective that patches the kit.** A port that ships
without running `PROMPTS/90-retrospective.md` and appending to `LESSONS.md` has
wasted its most valuable output. The kit is a compounding asset or it is dead
weight — there is no middle.

## Prime directive

The Rust must be **safer and more secure** than the C, not merely equivalent.
- The C is a *specification that may be buggy*. Do not faithfully re-implement a
  vulnerability. Every oracle divergence is triaged (Rust bug vs intentional
  fix-of-C-defect) and the intentional ones are logged in `DIVERGENCES.md`.
- **Maximize safety controls.** All of them are cheap relative to a CVE.

## Process (see PLAYBOOK.md for detail)

Phase 0 inventory + C-flaw scan + threat model → Phase 1 dependency-ordered port
plan → Phase 2 oracle → Phase 3 skeleton → Phase 4 per-module loop → Phase 5
cutover. Do not skip Phase 0's flaw scan or the oracle: they are what make the
port *safe* and *verifiable*.

## The gates (non-negotiable, wired into CI)

Every module clears all six before merge:
`ported → differential → fuzzed → sanitized → unsafe-audited`. A module that
compiles and matches the oracle is at step 2 of 6, not done.

| Control | Command |
|---|---|
| unsafe contained | `#![forbid(unsafe_code)]` on `core` |
| unsafe documented | `harnesses/unsafe-audit/audit_unsafe.py crates/` — **hard fail** |
| no UB | `harnesses/sanitizers/run_sanitizers.sh` (miri/asan/ubsan/tsan) |
| no panic on input | `harnesses/fuzz/` (cargo-fuzz) |
| clean deps | `harnesses/supply-chain/run_supply_chain.sh` |
| no silent drift | `harnesses/differential/diff_run.py` + `DIVERGENCES.md` |
| don't re-port a vuln | `harnesses/c-flaw-scan/scan_c_flaws.py` at Phase 0 |

Smoke-test the harnesses anytime with `make -C porting-kit check-kit` (python3 +
bash only; no toolchain needed).

## Habits the retrospective bought in blood

- **Spike the scary module before scheduling it** (the winlsof hang: 7 commits
  reactively vs ~1 day up front).
- **Fix-forward, then immediately pin the regression test** — in the *same*
  change, not "later."
- **Scaffold tracing + the unsafe-audit gate on day one** — both were added
  reactively in winlsof and both would have paid immediately.
- **The test harness is software with a hostile host** — budget for its
  encoding/quoting/portability hardening explicitly.

## Skills

`skills/` operationalizes this kit as invokable Claude Code skills —
`porting-kit-{kickoff,cflaw-scan,oracle,module,audit,retrospective}`. They are
**thin wrappers**: they point at the authoritative docs here and run the real
harness commands, never a divergent copy. **Keep them in integrity with the kit** —
if you rename a harness or change a flag, update every skill that references it;
`skills/check_skills.py` (in `make check-kit`) hard-fails on a dangling reference.
The retrospective (which patches the kit after every port) must patch the skills too.

## Working notes

- Keep `progress.json` current (`harnesses/progress/progress.py`) so any new
  session orients in seconds.
- Keep `PLAYBOOK.md` under ~400 lines; push detail into linked docs.
- When you infer project history from artifacts, mark it `[INFERRED]`.
