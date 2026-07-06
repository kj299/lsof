# Porting Kit — rewrite C in Rust, safely, and get faster each time

A reusable set of playbooks, working harnesses, an architecture skeleton, and
session prompts for **safety-first C→Rust rewrites**. Distilled from a real port
(see [`RETROSPECTIVE-lsof.md`](RETROSPECTIVE-lsof.md)) and built to **compound**:
every port ends with a retrospective that patches the kit ([`LESSONS.md`](LESSONS.md)).

## Prime directive

The Rust must be **safer and more secure** than the C, not merely equivalent.
The C is a specification that *may itself be buggy* — don't re-implement a
vulnerability. Maximize safety controls.

## Start here

| You want to… | Read / run |
|---|---|
| Understand the whole process | [`PLAYBOOK.md`](PLAYBOOK.md) (≤400 lines) |
| Run a port well (tokens, efficiency, security, backlog) | [`OPERATING-GUIDE.md`](OPERATING-GUIDE.md) |
| Lift this kit into its own repo over SSH (two git commands) | [`scripts/lift-to-c2rust-port.sh`](scripts/lift-to-c2rust-port.sh) |
| Kick off a new port | paste [`PROMPTS/00-new-port-kickoff.md`](PROMPTS/00-new-port-kickoff.md) |
| Port one module | paste [`PROMPTS/10-module-port.md`](PROMPTS/10-module-port.md) |
| Close a port & improve the kit | paste [`PROMPTS/90-retrospective.md`](PROMPTS/90-retrospective.md) |
| Lay out the workspace | copy [`skeleton/`](skeleton/); see [`ARCHITECTURE-TEMPLATE.md`](ARCHITECTURE-TEMPLATE.md) |
| The control ledger | [`SECURITY-CHECKLIST.md`](SECURITY-CHECKLIST.md) |
| Standing rules for any kit repo | [`CLAUDE.md`](CLAUDE.md) |

## Skills (invokable wrappers over the kit)

`skills/` holds Claude Code skills that operationalize the kit — each a thin wrapper
that reads the authoritative docs and runs the real harness commands (never a
divergent restatement). `skills/check_skills.py` (run by `make check-kit`) fails if
any skill references a kit path that no longer exists, so they can't drift.

| Skill | Use it to |
|---|---|
| `porting-kit-kickoff` | start a new port: Phase 0 inventory + flaw scan + threat model, propose the order |
| `porting-kit-cflaw-scan` | hunt C vulnerabilities before porting and triage them into the ledger |
| `porting-kit-oracle` | establish the differential oracle + test-vector harness before translating |
| `porting-kit-module` | port one module through the six safety gates |
| `porting-kit-audit` | run the full safety-gate suite and report a gate-status table |
| `porting-kit-retrospective` | close a port and patch the kit (the compounding loop) |

**Install:** copy or symlink `porting-kit/skills/*` into the target repo's
`.claude/skills/` so Claude Code discovers them (they assume the kit lives at
repo-root `porting-kit/`; adjust the paths inside if you vendor it elsewhere).

## Harnesses (all runnable; `make check-kit` smoke-tests them all)

| Harness | Purpose | Gate |
|---|---|---|
| `harnesses/unsafe-audit/audit_unsafe.py` | every `unsafe {}` needs a `// SAFETY:` | **hard-fail CI** |
| `harnesses/differential/diff_run.py` (+`normalize.py`) | diff Rust vs C oracle; triage divergences via a ledger; timeout = liveness backstop | CI |
| `harnesses/golden/golden.py` | capture/version/replay the oracle; flag oracle nondeterminism | CI |
| `harnesses/fuzz/gen_fuzz_target.sh` | scaffold a cargo-fuzz target per module | CI smoke + nightly |
| `harnesses/sanitizers/run_sanitizers.sh` | Miri / ASan / UBSan / TSan over the unsafe layer | CI |
| `harnesses/supply-chain/run_supply_chain.sh` | `cargo audit` + `cargo deny` | CI |
| `harnesses/c-flaw-scan/scan_c_flaws.py` | find C vuln classes *before* porting | Phase 0 |
| `harnesses/progress/progress.py` | per-module status table incl. safety gates | tracking |
| `harnesses/ci/porting-ci.template.yml` | wires all gates into GitHub Actions | — |

```
make check-kit      # smoke-test every harness (python3 + bash only, no toolchain)
```

## Related

- [`C-to-Rust-Playbook-Best-of-Both.md`](C-to-Rust-Playbook-Best-of-Both.md) — a
  standalone synthesis that merges this kit's executable layer with the
  TRACTOR-hardened (DARPA/MIT-LL, Feb 2026) four-step translation playbook.
  Written as portable feedback; useful when the port is a *translation*
  (transpile / LLM / FFI-coexistence) rather than a reimplementation.

## The compounding loop

Kick off → per-module loop (port → differential → fuzz → sanitize → unsafe-audit)
→ **retrospective that patches this kit**. The kit is the running sum of every
port it has survived; `LESSONS.md` is its memory.
