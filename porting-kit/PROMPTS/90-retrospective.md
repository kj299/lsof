# Prompt — end-of-port retrospective (patch the kit)

Paste this when a port (or a major phase) is done. This is what makes the kit
**compound**: every port leaves it sharper than it found it.

---

The `[PROJECT]` port (or phase `[PHASE]`) is complete. Run the closing
retrospective and **patch the Porting Kit** with what you learned.

0. **Run every harness against the real target and record what each finds.** This
   is not optional and not last: the kit's three post-ship dry-runs (LESSONS
   #2–#4) each found a defect *in a harness* — a scanner too noisy to trust, a
   gate delegated to an unwired lint, a differential that judged less than it
   captured — and *none* surfaced from reading the playbook. A dry-run that
   doesn't execute the tools against the actual codebase is theater. Run
   `scan_c_flaws.py`, `audit_unsafe.py`, the differential, etc. against this
   project and eyeball the signal-to-noise before trusting any of it.

1. **Reconstruct the experience from artifacts**, the way
   `RETROSPECTIVE-lsof.md` was built — lean on git history, especially:
   - commit *sequences* where a message says "the real fix" / "actually" (these
     mark where the first approach failed — highest signal, more than reverts),
   - churn per file/module (proxy for time sinks),
   - the `progress.json` final state and the `DIVERGENCES.md` entries.

2. **Diff lived experience against `PLAYBOOK.md`.** For each phase ask:
   - Did the entry/exit criteria match reality? Was a gate missing that would
     have caught a bug earlier?
   - Did any harness misfire, over-report, or miss its target? Did any produce
     enough friction that it got skipped (a skipped control is a broken control)?
   - Did a failure occur that the playbook, as written, would NOT have prevented?
     That is the most important finding.

3. **Patch the kit** — make the concrete edits, don't just describe them:
   - amend `PLAYBOOK.md` phases/criteria,
   - fix/extend a harness (add the normalization rule, the flaw pattern, the
     gate) and re-run `make -C porting-kit check-kit`,
   - update `ARCHITECTURE-TEMPLATE.md` / prompts if the shape or loop changed.

4. **Append to `LESSONS.md`** — one entry per lesson, in the required format
   (date, codebase, lesson, playbook section amended). If the kit already had
   the lesson but it didn't fire, say why (friction? unclear? not wired to CI?).

5. **Commit the kit changes separately** from the port, with a message explaining
   which failure each edit prevents next time.

Report: the top 3 kit improvements you made and the single failure that, in
hindsight, the kit still would not have prevented (the next port's target).
