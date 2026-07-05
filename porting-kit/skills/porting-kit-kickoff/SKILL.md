---
name: porting-kit-kickoff
description: Start a new C-to-Rust port using the Porting Kit. Use when the user wants to begin rewriting/porting/migrating a C (or C++) codebase to Rust, or asks to "kick off", "scope", or "plan" such a port. Runs Phase 0 (inventory + C-vulnerability scan + threat model) and proposes a dependency-ordered plan before any Rust is written.
---

# Porting Kit — new-port kickoff

Operationalizes `porting-kit/PROMPTS/00-new-port-kickoff.md` and PLAYBOOK Phases 0–1.
**This skill does analysis and planning only — it writes no Rust and stops for approval.**

## Read first (authoritative; do not restate divergently)
1. `porting-kit/CLAUDE.md` — standing rules (every port ends with a kit-patching retrospective).
2. `porting-kit/PLAYBOOK.md` — the phased process.
3. `porting-kit/RETROSPECTIVE-lsof.md` §6 (failure inventory) and §9 (safety direction).

## Prime directive
The Rust must be **safer** than the C, not merely equivalent. The C is a spec that
*may itself be buggy* — never faithfully re-implement a vulnerability. Maximize controls.

## Procedure (Phase 0, then propose Phase 1)
1. **Inventory** the C: modules, LOC, external deps, the syscall/FFI/ioctl surface,
   global mutable state, macros, build system. Seed the tracker:
   `python3 porting-kit/harnesses/progress/progress.py init --modules <list>`
2. **Hunt C vulnerabilities** (invoke the `porting-kit-cflaw-scan` skill, or run
   `python3 porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py <c-dirs>`). Tune for
   signal-to-noise first (LESSONS #2). Each confirmed hit is a planned
   `DIVERGENCES.md` entry — a bug the port will fix, not re-port.
3. **Classify the FFI/syscall surface by failure mode** (LESSONS #1): for each
   external call, record can-it-block-indefinitely / needs-privilege /
   varies-by-OS-or-version. This arms the "spike the scary module first" rule.
4. **Draft the threat model** from `porting-kit/skeleton/THREAT-MODEL.md`.
5. **Decide the port shape:** reimplement-behind-a-seam (OS-integration replaced,
   like lsof) vs translate-with-FFI-coexistence (library internals preserved). If
   translation, also read `porting-kit/C-to-Rust-Playbook-Best-of-Both.md` (Step 0
   C→C preconditioning; executable/library split).
6. **Propose a dependency-ordered port plan** (leaf-first / roots-before-dependents),
   flagging any hazardous module for a pre-port spike.

**Stop and present** the Phase 0 report + proposed order. Do not port modules until
the order is agreed. Then copy `porting-kit/skeleton/` and invoke `porting-kit-oracle`.

## Integrity
Commands and file paths above must match the kit exactly. If a harness path/flag has
changed, fix the kit reference (and re-run `make -C porting-kit check-kit`) rather than
diverging here — the playbook is the single source of truth.
