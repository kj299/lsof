# Skills — reference card

Invokable Claude Code skills that operationalize the Porting Kit. Each is a **thin
wrapper** over the authoritative kit docs and real harness commands (integrity
enforced by `check_skills.py`, run in `make check-kit`). For the *strategy* of when
and how to spend effort across a port, see `../OPERATING-GUIDE.md` §4; this is the
per-skill card.

## Install
Copy or symlink each `porting-kit-*` directory into the target repo's
`.claude/skills/` so Claude Code discovers it. They assume the kit lives at
repo-root `porting-kit/`; if you vendor it elsewhere, adjust the paths inside each
`SKILL.md` and re-run `make -C porting-kit check-kit`.

## The suite

| Skill | Phase | Cadence | Cost | Parallelizable |
|---|---|---|---|---|
| `porting-kit-kickoff` | 0–1 | once | low (plan only) | — |
| `porting-kit-cflaw-scan` | 0 | once / per subsystem | low (tool + triage) | ∥ with oracle |
| `porting-kit-oracle` | 2 | once, pre-Rust | medium (build corpus) | ∥ with cflaw-scan |
| `porting-kit-module` | 4 | **per module (hot path)** | high (translate + iterate) | per-module ∥ (leaf order) |
| `porting-kit-audit` | 4–5 | per module + release | low (runs gates, reads verdicts) | — |
| `porting-kit-retrospective` | end | once per phase — **never skip** | medium | — |

## Per-skill

- **`porting-kit-kickoff`** — begin a port. Reads CLAUDE.md/PLAYBOOK/RETROSPECTIVE,
  runs Phase 0 (inventory + flaw scan + threat model), classifies the port shape,
  proposes a dependency-ordered plan. Analysis only; stops for approval.
- **`porting-kit-cflaw-scan`** — hunt C vulnerabilities before porting; triage each
  into `DIVERGENCES.md`. Tune for signal-to-noise first (LESSONS #2).
- **`porting-kit-oracle`** — establish the differential oracle + test-vector harness
  *before* writing Rust. Golden corpus, normalization, hidden vectors,
  C-baseline-validated vectors, ledger seed.
- **`porting-kit-module`** — the six-gate loop for one module: spike-if-hazardous →
  port → differential → fuzz → sanitize → unsafe-audit → pin+merge. Advances
  `progress.json`.
- **`porting-kit-audit`** — run the full safety-gate suite; report a gate-status
  table; refuse a "safe" verdict unless every applicable gate is green or a
  divergence is ledgered. Gate every merge/release with it.
- **`porting-kit-retrospective`** — close the port and **patch the kit** (playbook,
  harnesses, and *these skills*), then append `LESSONS.md`. The compounding loop.

## Recipe

```
kickoff
  → (cflaw-scan  ∥  oracle)
  → for each leaf in topological order:  module  →  audit
  → retrospective   (patch the kit + LESSONS; keep skills in integrity)
```

## Integrity rule
These skills are part of "all elements of the kit." If a harness is renamed or a
flag changes, update every skill that references it — `check_skills.py` hard-fails
on a dangling `porting-kit/<path>` reference, and the retrospective must patch the
skills alongside the docs.
