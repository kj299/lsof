---
name: porting-kit-retrospective
description: Close a C-to-Rust port (or a major phase) and patch the Porting Kit with what was learned. Use when a port/phase is complete, or when the user asks to "wrap up", "retro", "capture lessons", or "improve the kit". This is the compounding loop — every port leaves the kit sharper than it found it.
---

# Porting Kit — closing retrospective (patch the kit)

Wraps `porting-kit/PROMPTS/90-retrospective.md`. This is the rule from
`porting-kit/CLAUDE.md`: **every port ends with a retrospective that patches the kit.**
A port that ships without this wastes its most valuable output.

## Procedure
0. **Run every harness against the real target first — not last.** The kit's own
   post-ship passes (LESSONS #2–#4) each found a defect *in a harness* (a noisy
   scanner, an unwired gate, an under-checking differential); none surfaced from
   reading the prose. A dry-run that doesn't execute the tools against the actual code
   is theater. Run `scan_c_flaws.py`, `audit_unsafe.py`, the differential, etc. and
   eyeball the signal-to-noise.
1. **Reconstruct from artifacts** the way `RETROSPECTIVE-lsof.md` was built: lean on git
   history — especially commit *sequences* where a message says "the real fix"
   (higher signal than reverts), churn per file (time-sink proxy), the final
   `progress.json`, and the `DIVERGENCES.md` entries.
2. **Diff lived experience against `PLAYBOOK.md`.** Per phase: did entry/exit criteria
   match reality? Was a gate missing that would have caught a bug earlier? Did any
   harness misfire, over-report, or get skipped (a skipped control is a broken
   control)? **Did a failure occur the playbook would NOT have prevented?** — the most
   important finding.
3. **Patch the kit — make the edits, don't just describe them:** amend `PLAYBOOK.md`;
   fix/extend a harness and re-run `make -C porting-kit check-kit`; update
   `ARCHITECTURE-TEMPLATE.md`, the `PROMPTS/`, or these skills if the shape/loop changed.
   **Keep the skills in integrity with the kit** — if you renamed a harness or changed a
   flag, update every skill that references it (the skills-integrity check enforces this).
4. **Append to `porting-kit/LESSONS.md`** — one entry per lesson in the required format
   (date, codebase, lesson, section amended). If the kit had the lesson but it didn't
   fire, say why (friction? unclear? not wired to CI?).
5. **Commit the kit changes separately** from the port, each message explaining which
   failure it prevents next time.

Report: the top 3 kit improvements and the single failure the kit still would not have
prevented (the next port's target).

## Integrity
This skill and the rest of the suite are part of "all elements of the kit" — keep them
consistent with `PLAYBOOK.md`, the harnesses, and `LESSONS.md`. Run
`make -C porting-kit check-kit` (which includes the skills-integrity check) after edits.
