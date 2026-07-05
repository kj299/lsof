---
name: porting-kit-module
description: Port one C module to Rust through the six safety gates. Use when translating/porting a specific module, function, or subsystem from C to Rust as part of a Porting-Kit port. Runs the per-module loop — spike-if-hazardous, port, differential-test, fuzz, sanitize, unsafe-audit, pin+merge — with each gate a hard requirement.
---

# Porting Kit — port one module (the Phase 4 loop)

Wraps `porting-kit/PROMPTS/10-module-port.md` and PLAYBOOK Phase 4. Re-read those first.

## Spike first if the module is hazardous
If flagged in Phase 1 (blocking syscall, exotic ioctl, unions, threads), run a
timeboxed spike on the one scary operation — does it block? need privilege? vary by
version? — and record the result *before* committing to a design. This is the
highest-ROI habit in the retrospective (the winlsof `NtQueryObject` hang cost 7
commits reactively vs ~1 day up front). For a capability that might be *impossible*
(not just hard), use the research spike-and-gate ritual: rate effort/confidence,
write the decision gate before coding, and do a pivot check before declaring it dead.

## The six gates (each a hard requirement before merge)
1. **Port** into `core` (pure logic) or a safe wrapper in `sys` (if it touches FFI).
   Idiom map: call-twice-for-size → growing `Vec` + length checks; pointer/struct math
   → slices + `repr(C)` with bounds; unions/flexible-arrays → audited casts each with
   `// SAFETY:`; integer math → `checked_*`/`saturating_*` (guard signedness/width,
   overflow, shift/rotation exactly). No `unwrap`/`expect`/unchecked index on input.
2. **Differential-test** vs the oracle:
   `python3 porting-kit/harnesses/differential/diff_run.py --oracle <c> --rust <rust> --matrix <m> --ledger DIVERGENCES.md`
   A divergence is a *triage*: fix the Rust, OR record an intentional fix-of-C-defect
   in `DIVERGENCES.md`. Verdict = stdout AND exit code; a timeout = a design smell
   (design the blocking call out, don't wrap it).
3. **Fuzz** the input surface:
   `bash porting-kit/harnesses/fuzz/gen_fuzz_target.sh <module> --crate <crate>`
   then `cargo fuzz run <module> -- -max_total_time=60`. Any panic/crash blocks.
4. **Sanitize:** `bash porting-kit/harnesses/sanitizers/run_sanitizers.sh miri .`
   (plus `asan`/`tsan` for the `sys` layer / threaded code).
5. **Unsafe-audit** (must report 0 undocumented):
   `python3 porting-kit/harnesses/unsafe-audit/audit_unsafe.py crates/`
   Clippy's `missing_safety_doc` + `undocumented_unsafe_blocks` (wired via
   `[workspace.lints]` and CI) cover `unsafe fn` docs.
6. **Pin the regression + merge.** If a bug slipped through, add the golden/matrix case
   that would have caught it *in the same change* (fix-forward, then immediately pin).

Advance the tracker as gates clear:
`python3 porting-kit/harnesses/progress/progress.py set <module> <gate>`
(gates: ported → differential → fuzzed → sanitized → unsafe_audited).

For the hardest modules, consider **two candidate translations by different methods**
and let the vector suite pick the winner (diversity beats any single method).

## Integrity
Commands/paths/gate-names must match the kit and PLAYBOOK Phase 4. Fix the reference on
drift; re-run `make -C porting-kit check-kit`.
