# Prompt — kick off a new C→Rust port with the Porting Kit

Paste this into a fresh Claude Code session at the root of (or alongside) the C
codebase you want to rewrite. Replace the bracketed values.

---

You are starting a **safety-first C→Rust port** of `[TARGET REPO URL / PATH]`
using the Porting Kit in `porting-kit/`.

**Before anything else, read, in this order:**
1. `porting-kit/CLAUDE.md` — the standing rules (especially: every port ends with
   a retrospective that patches the kit).
2. `porting-kit/PLAYBOOK.md` — the phased process you will follow.
3. `porting-kit/RETROSPECTIVE-lsof.md` §6 (failure inventory) and §9 (safety
   direction) — the mistakes you are here to not repeat.

**Prime directive:** the Rust must be *safer and more secure* than the C, not
merely equivalent. The C is a specification that **may itself be buggy** — do not
faithfully re-implement a vulnerability. Maximize safety controls.

**Do Phase 0 now** and report before writing any Rust:
1. Inventory the C: modules, LOC, external deps, the syscall/FFI/ioctl surface,
   global mutable state, macros, build system. Seed the tracker:
   `python3 porting-kit/harnesses/progress/progress.py init --modules <list>`.
2. Run the C-flaw scan and triage it:
   `python3 porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py <c-src-dirs>`.
   Every confirmed hit is a planned DIVERGENCES.md entry (a bug you will fix).
3. Draft `THREAT-MODEL.md` from `porting-kit/skeleton/THREAT-MODEL.md`: trust
   boundaries, privilege transitions, what "secure" means here.
4. Decide the port shape: is this **reimplement-behind-a-seam** (OS-integration
   layer being replaced — like lsof) or **translate-with-FFI-coexistence**
   (library internals preserved)? State which and why; it sets the strategy.

Then propose the **dependency-graph-driven port order** (Phase 1), flagging any
known-hazardous module for a pre-port spike (the winlsof hang cost 7 commits
because it wasn't spiked first).

**Stop and present** the Phase 0 report + proposed order before Phase 2. Do not
begin porting modules until the order is agreed.

When you do build, copy `porting-kit/skeleton/` for the workspace shape, wire
`porting-kit/harnesses/ci/porting-ci.template.yml` into CI, and run
`make -C porting-kit check-kit` to confirm the harnesses work in this repo.
