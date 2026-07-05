# Prompt — port one module (the Phase 4 loop)

Paste this once per module, after Phase 0/1 are agreed. Replace `[MODULE]`.

---

Port the C module **`[MODULE]`** to Rust following `porting-kit/PLAYBOOK.md`
Phase 4. Re-read PLAYBOOK Phase 4 and `RETROSPECTIVE-lsof.md` §6 first.

**If this module was flagged hazardous (blocking syscall, exotic ioctl, unions,
threads), SPIKE FIRST:** a timeboxed experiment on the one scary operation —
does it block? need privilege? vary by platform/version? — and record the result
*before* committing to a design. This single habit is the highest-ROI lesson in
the retrospective.

Then run every gate; each is a hard requirement before merge:

1. **Port** into `core` (pure logic) or a safe wrapper in `sys` (if it touches
   FFI). Translate idioms safely: call-twice-for-size → growing `Vec` + length
   checks; pointer/struct math → slices + `repr(C)` with bounds; unions/flexible
   arrays → audited casts each with a `// SAFETY:`; integer math → checked/
   saturating. No `unwrap`/`expect`/unchecked indexing on untrusted input.
2. **Differential-test** vs the oracle:
   `python3 porting-kit/harnesses/differential/diff_run.py --oracle <c> --rust
   <rust> --matrix <m> --ledger DIVERGENCES.md`. A divergence is a TRIAGE: fix the
   Rust, OR — if the C was wrong — record the intentional fix in `DIVERGENCES.md`
   (`- [x] <case>: <why + CWE>`). Never silently match a C bug.
3. **Fuzz** the input surface:
   `bash porting-kit/harnesses/fuzz/gen_fuzz_target.sh [MODULE] --crate <crate>`,
   then `cargo fuzz run [MODULE] -- -max_total_time=60`. Any panic/crash blocks.
4. **Sanitize:** `bash porting-kit/harnesses/sanitizers/run_sanitizers.sh miri .`
   (and `asan`/`tsan` for the `sys` layer / threaded code).
5. **Unsafe-audit:** `python3 porting-kit/harnesses/unsafe-audit/audit_unsafe.py
   crates/` — must report **0 undocumented**. Add a `// SAFETY:` to any block it
   flags.
6. **Pin the oracle case + merge.** If a bug slipped through, add the golden/
   matrix case that would have caught it *in the same change* (the retrospective's
   "fix-forward, then immediately pin" rule — winlsof often shipped the fix first
   and the test late).

Advance the tracker as gates clear:
`python3 porting-kit/harnesses/progress/progress.py set [MODULE] <gate>`.

Report the module's final gate row and any new `DIVERGENCES.md` entries.
