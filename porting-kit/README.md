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
| Kick off a new port | paste [`PROMPTS/00-new-port-kickoff.md`](PROMPTS/00-new-port-kickoff.md) |
| Port one module | paste [`PROMPTS/10-module-port.md`](PROMPTS/10-module-port.md) |
| Close a port & improve the kit | paste [`PROMPTS/90-retrospective.md`](PROMPTS/90-retrospective.md) |
| Lay out the workspace | copy [`skeleton/`](skeleton/); see [`ARCHITECTURE-TEMPLATE.md`](ARCHITECTURE-TEMPLATE.md) |
| The control ledger | [`SECURITY-CHECKLIST.md`](SECURITY-CHECKLIST.md) |
| Standing rules for any kit repo | [`CLAUDE.md`](CLAUDE.md) |

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

## The compounding loop

Kick off → per-module loop (port → differential → fuzz → sanitize → unsafe-audit)
→ **retrospective that patches this kit**. The kit is the running sum of every
port it has survived; `LESSONS.md` is its memory.
